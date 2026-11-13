"""临时文件占用扫描（只读）。

范围：``%TEMP%`` / ``%TMP%`` / ``%SystemRoot%\\Temp`` / ``%LOCALAPPDATA%\\Temp``
以及一组已知缓存目录（浏览器/INetCache/pip/D3D/NVIDIA 等，可扩展）。

安全与限制：
* 只读：不修改、不删除任何文件；
* 不跟随符号链接/junction（``GetFileAttributesW`` 检查重解析点）；
* 有文件数/时间预算，超限时标记"结果可能不完整"，绝不无限扫描；
* "可能被占用"来自 ``CreateFileW(share=0)`` 只读探测，杀软干扰可能误判，
  且只探测 ≥1MB 的最大若干个文件；**未探测 ≠ 未占用**；
* 目录大小 = 文件逻辑大小之和（与资源管理器"占用空间"口径可能不同）。
"""

from __future__ import annotations

import heapq
import logging
import os
import time
from collections.abc import Callable, Sequence

from ..core.cancel import CancelToken
from ..core.fmt import human_bytes
from ..core.models import (
    Completeness,
    Occupancy,
    ScanWarning,
    TempEntry,
    TempRoot,
    TempScanResult,
)
from ..core.whitelist import normalize_path
from ..core.winapi import is_reparse_point, probe_file_occupancy

logger = logging.getLogger(__name__)

PROBE_MIN_BYTES = 1024 * 1024
MAX_DIRECTORY_DEPTH = 64

# (相对 %LOCALAPPDATA% 的子目录, 类型)
_DEFAULT_CACHE_SUBDIRS: tuple[tuple[str, str], ...] = (
    (r"Microsoft\Windows\INetCache", "cache"),
    (r"Microsoft\Edge\User Data\Default\Cache", "cache"),
    (r"Google\Chrome\User Data\Default\Cache", "cache"),
    (r"pip\Cache", "cache"),
    (r"NVIDIA\DXCache", "cache"),
    (r"D3DSCache", "cache"),
    (r"CrashDumps", "cache"),
    (r"Temp", "temp"),
)

ProgressCallback = Callable[[int, str], None]
"""``progress(percent_hint, text)``；percent_hint 是 0-100 的扫描进度估计。"""

_OCCUPANCY_RANK: dict[Occupancy, int] = {
    Occupancy.NOT_PROBED: 0,
    Occupancy.FREE: 1,
    Occupancy.NO_ACCESS: 2,
    Occupancy.LOCKED: 3,
}


def default_temp_roots() -> list[TempRoot]:
    """构造默认扫描根（去重后返回）。"""

    roots: list[TempRoot] = []
    seen: set[str] = set()

    def add(path: str | None, kind: str) -> None:
        if not path:
            return
        normalized = normalize_path(path)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        try:
            exists = os.path.isdir(path)
        except OSError:
            exists = False
        roots.append(TempRoot(path=path, kind=kind, exists=exists))

    for env_name in ("TEMP", "TMP"):
        add(os.environ.get(env_name), "temp")
    system_root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    add(os.path.join(system_root, "Temp"), "temp")

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        for relative, kind in _DEFAULT_CACHE_SUBDIRS:
            add(os.path.join(local_app_data, relative), kind)
    return roots


class _TempScanner:
    """单次临时文件扫描的状态机（非线程安全，仅在一个扫描任务内使用）。"""

    def __init__(
        self,
        *,
        token: CancelToken,
        max_files: int,
        budget_s: float,
        probe_max_files: int,
        probe_budget_s: float,
        progress: ProgressCallback | None,
    ) -> None:
        self.token = token
        self.max_files = max_files
        self.budget_s = budget_s
        self.probe_max_files = max(0, probe_max_files)
        self.probe_budget_s = probe_budget_s
        self.progress = progress

        self.entries: list[TempEntry] = []
        self.total_size = 0
        self.total_files = 0
        self.skipped_reparse = 0
        self.unreadable = 0
        self.warnings: list[ScanWarning] = []
        self._started_at = time.monotonic()
        self._scanned_files = 0
        self._stop_flag = False
        self._budget_hit = False
        # 小顶堆：只保留最大的 probe_max_files 个候选（元素：size, path, entry_index）
        self._candidates: list[tuple[int, str, int]] = []
        self._probe_stats: dict[int, dict[str, int]] = {}

    # ------------------------------------------------------------- 工具
    def _expired(self) -> bool:
        return (time.monotonic() - self._started_at) > self.budget_s

    def _stop(self) -> bool:
        return self._stop_flag or self.token.is_cancelled

    def _tick(self, current_path: str) -> None:
        """每 200 个文件检查取消/预算，并尝试上报进度。"""

        self._scanned_files += 1
        if self._scanned_files % 200 == 0:
            self.token.raise_if_cancelled("扫描临时目录")
            if self._expired():
                self._budget_hit = True
                self._stop_flag = True
                return
            if self.progress is not None:
                self.progress(self._progress_hint(), f"扫描临时目录：{current_path}")
        if self._scanned_files > self.max_files:
            self._budget_hit = True
            self._stop_flag = True

    def _progress_hint(self) -> int:
        if self.budget_s <= 0:
            return 50
        ratio = (time.monotonic() - self._started_at) / self.budget_s
        return max(0, min(99, int(ratio * 100)))

    def _add_candidate(self, size: int, path: str, entry_index: int) -> None:
        if size < PROBE_MIN_BYTES or self.probe_max_files <= 0:
            return
        heapq.heappush(self._candidates, (size, path, entry_index))
        if len(self._candidates) > self.probe_max_files:
            heapq.heappop(self._candidates)

    # ------------------------------------------------------------- 扫描
    def scan(self, roots: Sequence[TempRoot]) -> TempScanResult:
        scanned_roots: list[TempRoot] = []
        for root in roots:
            self.token.raise_if_cancelled("扫描临时目录")
            try:
                exists = os.path.isdir(root.path)
            except OSError:
                exists = False
            scanned_roots.append(TempRoot(path=root.path, kind=root.kind, exists=exists))
            if not exists:
                continue
            self._scan_root(root)

        if self._budget_hit:
            self.warnings.append(
                ScanWarning(
                    "temp_budget",
                    f"临时文件扫描达到预算上限（{self.max_files} 个文件 / {self.budget_s:.0f}s），结果可能不完整",
                    phase="temp",
                )
            )
        if self.unreadable:
            self.warnings.append(
                ScanWarning(
                    "temp_unreadable",
                    f"{self.unreadable} 个目录/文件无法读取（权限不足），已跳过",
                    phase="temp",
                )
            )
        if self.skipped_reparse:
            self.warnings.append(
                ScanWarning(
                    "temp_reparse_skipped",
                    f"已跳过 {self.skipped_reparse} 个符号链接/junction（不跟随）",
                    phase="temp",
                )
            )

        probed, candidates_total = self._probe_candidates()
        final_entries = self._finalize_entries()
        final_entries.sort(key=lambda item: item.size, reverse=True)

        if not any(root.exists for root in scanned_roots):
            completeness = Completeness.DEGRADED
            self.warnings.append(
                ScanWarning("temp_no_root", "默认临时目录均不存在或不可访问", phase="temp")
            )
        elif self._budget_hit or self.unreadable or (candidates_total and probed < candidates_total):
            completeness = Completeness.PARTIAL
        else:
            completeness = Completeness.FULL

        probe_note = (
            f"占用探测：{probed}/{candidates_total} 个 ≥{human_bytes(PROBE_MIN_BYTES)} 文件"
            f"（时间预算 {self.probe_budget_s:.0f}s）；未探测 ≠ 未占用"
        ) if candidates_total else (
            f"没有 ≥{human_bytes(PROBE_MIN_BYTES)} 的候选项，未做占用探测（未探测 ≠ 未占用）"
        )

        elapsed_ms = int((time.monotonic() - self._started_at) * 1000)
        logger.info(
            "临时目录扫描完成：根 %d，条目 %d，%s / %d 个文件，探测 %d/%d，完整度=%s",
            len(scanned_roots),
            len(final_entries),
            human_bytes(self.total_size),
            self.total_files,
            probed,
            candidates_total,
            completeness.value,
        )
        return TempScanResult(
            roots=scanned_roots,
            entries=final_entries,
            total_size=self.total_size,
            total_files=self.total_files,
            probed_files=probed,
            probe_candidates=candidates_total,
            skipped_reparse=self.skipped_reparse,
            unreadable=self.unreadable,
            elapsed_ms=elapsed_ms,
            completeness=completeness,
            probe_note=probe_note,
            warnings=self.warnings,
        )

    def _scan_root(self, root: TempRoot) -> None:
        try:
            with os.scandir(root.path) as iterator:
                first_level = list(iterator)
        except OSError as exc:
            self.unreadable += 1
            self.warnings.append(
                ScanWarning("temp_root_denied", f"无法读取临时目录：{root.path}（{exc}）", path=root.path, phase="temp")
            )
            return

        for entry in first_level:
            if self._stop():
                return
            self.token.raise_if_cancelled("扫描临时目录")
            self._tick(entry.path)
            if self._stop():
                return
            path = entry.path
            entry_index = len(self.entries)
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                self.unreadable += 1
                continue
            reparse = is_reparse_point(path)
            if reparse is True:
                self.skipped_reparse += 1
                continue
            if is_dir:
                size, count, mtime = self._summarize_directory(path, entry_index)
            else:
                try:
                    stat_result = entry.stat(follow_symlinks=False)
                    size = int(stat_result.st_size)
                    mtime = float(stat_result.st_mtime)
                except OSError:
                    self.unreadable += 1
                    continue
                count = 1
                self.total_files += 1
                self.total_size += size
                self._add_candidate(size, path, entry_index)
            self.entries.append(
                TempEntry(
                    root=root.path,
                    path=path,
                    is_dir=is_dir,
                    size=size,
                    file_count=count,
                    mtime=mtime,
                    occupancy=Occupancy.NOT_PROBED,
                )
            )
            if self.progress is not None:
                self.progress(self._progress_hint(), f"扫描临时目录：{path}")

    def _summarize_directory(self, path: str, entry_index: int) -> tuple[int, int, float]:
        """递归聚合目录：返回 (总大小, 文件数, 最新修改时间)。"""

        total_size = 0
        file_count = 0
        latest_mtime = 0.0
        stack: list[tuple[str, int]] = [(path, 0)]
        while stack and not self._stop():
            current_path, depth = stack.pop()
            try:
                with os.scandir(current_path) as iterator:
                    entries = list(iterator)
            except OSError:
                self.unreadable += 1
                continue
            for entry in entries:
                self._tick(current_path)
                if self._stop():
                    break
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if is_reparse_point(entry.path) is True:
                            self.skipped_reparse += 1
                            continue
                        if depth + 1 > MAX_DIRECTORY_DEPTH:
                            self.unreadable += 1
                            continue
                        stack.append((entry.path, depth + 1))
                    else:
                        stat_result = entry.stat(follow_symlinks=False)
                        size = int(stat_result.st_size)
                        total_size += size
                        file_count += 1
                        latest_mtime = max(latest_mtime, float(stat_result.st_mtime))
                        self._add_candidate(size, entry.path, entry_index)
                except OSError:
                    self.unreadable += 1
        self.total_size += total_size
        self.total_files += file_count
        return total_size, file_count, latest_mtime

    # ------------------------------------------------------------- 探测
    def _probe_candidates(self) -> tuple[int, int]:
        """返回 (已探测数, 候选总数)。"""

        candidates = sorted(self._candidates, key=lambda item: (-item[0], item[1]))
        total = len(candidates)
        if not candidates:
            return 0, 0
        probe_started = time.monotonic()
        probed = 0
        for _size, file_path, entry_index in candidates:
            self.token.raise_if_cancelled("占用探测")
            if (time.monotonic() - probe_started) > self.probe_budget_s:
                break
            occupancy, _error_code = probe_file_occupancy(file_path)
            probed += 1
            stats = self._probe_stats.setdefault(entry_index, {"probed": 0, "locked": 0, "no_access": 0})
            stats["probed"] += 1
            if occupancy is Occupancy.LOCKED:
                stats["locked"] += 1
            elif occupancy is Occupancy.NO_ACCESS:
                stats["no_access"] += 1
        return probed, total

    def _finalize_entries(self) -> list[TempEntry]:
        finalized: list[TempEntry] = []
        for index, entry in enumerate(self.entries):
            stats = self._probe_stats.get(index)
            if not stats or stats["probed"] == 0:
                finalized.append(entry)
                continue
            if stats["locked"] > 0:
                occupancy = Occupancy.LOCKED
                detail = f"探测 {stats['probed']} 个文件中 {stats['locked']} 个被占用"
            elif stats["no_access"] > 0:
                occupancy = Occupancy.NO_ACCESS
                detail = f"探测 {stats['probed']} 个文件中 {stats['no_access']} 个无访问权限"
            else:
                occupancy = Occupancy.FREE
                detail = f"探测 {stats['probed']} 个文件，均未被占用"
            finalized.append(
                TempEntry(
                    root=entry.root,
                    path=entry.path,
                    is_dir=entry.is_dir,
                    size=entry.size,
                    file_count=entry.file_count,
                    mtime=entry.mtime,
                    occupancy=occupancy,
                    occupancy_detail=detail,
                )
            )
        return finalized


def scan_temp(
    token: CancelToken,
    *,
    roots: Sequence[TempRoot] | None = None,
    max_files: int = 200_000,
    budget_s: float = 8.0,
    probe_max_files: int = 300,
    probe_budget_s: float = 2.0,
    progress: ProgressCallback | None = None,
) -> TempScanResult:
    """扫描临时文件占用（默认根见 :func:`default_temp_roots`）。"""

    scanner = _TempScanner(
        token=token,
        max_files=max_files,
        budget_s=budget_s,
        probe_max_files=probe_max_files,
        probe_budget_s=probe_budget_s,
        progress=progress,
    )
    return scanner.scan(roots if roots is not None else default_temp_roots())
