"""模块 C 只读扫描器（空间盘点 + 垃圾规则 + 大文件排行）。

安全与限制（与模块 B 的 ``module_b/walker.py`` 同口径）：
* 不跟随符号链接 / junction（``st_file_attributes`` 的 REPARSE_POINT 位）；
* 跳过 ``$Recycle.Bin`` / ``System Volume Information``；
* 跳过云占位文件（读取会触发下载）；
* 目录深度上限 64；支持取消令牌与时间预算（超限标记 ``truncated``，不谎报完整）；
* 单遍全盘概览：一次遍历同时得到「顶层子项占用」与「最大文件排行」，避免重复 I/O。
"""

from __future__ import annotations

import heapq
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core.cancel import CancelToken
from ..core.models import ScanWarning
from .models import LargeFileHit, OverviewEntry
from .safety import is_cloud_placeholder, is_drive_root, normalize_path

SKIP_DIRECTORY_NAMES: frozenset[str] = frozenset({"$recycle.bin", "system volume information"})
MAX_DIRECTORY_DEPTH = 64

FILE_ATTRIBUTE_REPARSE_POINT = 0x0400

ProgressCallback = Callable[[int, str], None]
"""``progress(已扫描文件数, 当前路径)``。"""


def _attributes(stat_result: os.stat_result) -> int:
    return int(getattr(stat_result, "st_file_attributes", 0) or 0)


@dataclass(slots=True)
class WalkStats:
    """一次递归统计的结果。"""

    total_bytes: int = 0
    files: int = 0
    dirs: int = 0
    skipped_reparse: int = 0
    skipped_unreadable: int = 0
    skipped_cloud: int = 0
    truncated: bool = False
    elapsed_ms: int = 0

    @property
    def is_incomplete(self) -> bool:
        return self.truncated or self.skipped_unreadable > 0


@dataclass(frozen=True, slots=True)
class ChildEntry:
    """目录下的直接子项（目录已递归汇总）。"""

    path: str
    name: str
    is_dir: bool
    size: int
    file_count: int
    mtime: float
    is_reparse: bool = False


@dataclass(slots=True)
class OverviewScanResult:
    """单遍全盘概览结果。"""

    entries: list[OverviewEntry] = field(default_factory=list)
    top_files: list[LargeFileHit] = field(default_factory=list)
    stats: WalkStats = field(default_factory=WalkStats)
    warnings: list[ScanWarning] = field(default_factory=list)


def _check_token(token: CancelToken | None) -> None:
    if token is not None:
        token.raise_if_cancelled("磁盘空间扫描")


def walk_size(
    root: str,
    *,
    token: CancelToken | None = None,
    progress: ProgressCallback | None = None,
    budget_s: float = 0.0,
    max_entries: int | None = None,
) -> WalkStats:
    """递归统计目录大小（文件逻辑字节数之和）。"""

    started = time.monotonic()
    stats = WalkStats()
    try:
        if not os.path.isdir(root):
            return stats
    except OSError:
        return stats

    stack: list[tuple[str, int]] = [(root, 0)]
    processed = 0
    while stack:
        _check_token(token)
        current, depth = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError:
            stats.skipped_unreadable += 1
            continue
        stats.dirs += 1
        for entry in entries:
            processed += 1
            if max_entries is not None and processed > max_entries:
                stats.truncated = True
                stack.clear()
                break
            try:
                stat_result = entry.stat(follow_symlinks=False)
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError:
                stats.skipped_unreadable += 1
                continue
            if _attributes(stat_result) & FILE_ATTRIBUTE_REPARSE_POINT:
                stats.skipped_reparse += 1
                continue
            if is_directory:
                if entry.name.casefold() in SKIP_DIRECTORY_NAMES:
                    continue
                if depth + 1 > MAX_DIRECTORY_DEPTH:
                    stats.skipped_unreadable += 1
                    continue
                stack.append((entry.path, depth + 1))
                continue
            if is_cloud_placeholder(entry.path):
                stats.skipped_cloud += 1
                continue
            stats.total_bytes += int(stat_result.st_size)
            stats.files += 1
        if progress is not None and stats.files % 2000 < len(entries):
            progress(stats.files, current)
        if budget_s > 0 and (time.monotonic() - started) > budget_s:
            stats.truncated = True
            break

    stats.elapsed_ms = int((time.monotonic() - started) * 1000)
    return stats


def list_children(
    root: str,
    *,
    token: CancelToken | None = None,
    progress: ProgressCallback | None = None,
    budget_s: float = 0.0,
) -> list[ChildEntry]:
    """列出目录的直接子项并计算大小（不跟随重解析点）。"""

    result: list[ChildEntry] = []
    try:
        with os.scandir(root) as iterator:
            entries = list(iterator)
    except OSError:
        return result

    for entry in entries:
        _check_token(token)
        try:
            stat_result = entry.stat(follow_symlinks=False)
            is_directory = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue
        name = entry.name
        if name.casefold() in SKIP_DIRECTORY_NAMES:
            continue
        reparse = bool(_attributes(stat_result) & FILE_ATTRIBUTE_REPARSE_POINT)
        if reparse:
            result.append(
                ChildEntry(
                    path=entry.path,
                    name=name,
                    is_dir=is_directory,
                    size=0,
                    file_count=0,
                    mtime=float(stat_result.st_mtime),
                    is_reparse=True,
                )
            )
            continue
        if is_directory:
            stats = walk_size(entry.path, token=token, progress=progress, budget_s=budget_s)
            result.append(
                ChildEntry(
                    path=entry.path,
                    name=name,
                    is_dir=True,
                    size=stats.total_bytes,
                    file_count=stats.files,
                    mtime=float(stat_result.st_mtime),
                )
            )
        else:
            result.append(
                ChildEntry(
                    path=entry.path,
                    name=name,
                    is_dir=False,
                    size=int(stat_result.st_size),
                    file_count=1,
                    mtime=float(stat_result.st_mtime),
                )
            )
    result.sort(key=lambda item: item.size, reverse=True)
    return result


def largest_files(
    root: str,
    *,
    token: CancelToken | None = None,
    top: int = 30,
    min_size: int = 0,
    budget_s: float = 0.0,
    progress: ProgressCallback | None = None,
) -> tuple[list[LargeFileHit], WalkStats]:
    """遍历目录，返回最大的 ``top`` 个文件（只读）。"""

    started = time.monotonic()
    stats = WalkStats()
    heap: list[tuple[int, str, float]] = []
    top = max(1, top)
    stack: list[tuple[str, int]] = [(os.path.abspath(root), 0)]

    while stack:
        _check_token(token)
        current, depth = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError:
            stats.skipped_unreadable += 1
            continue
        stats.dirs += 1
        for entry in entries:
            try:
                stat_result = entry.stat(follow_symlinks=False)
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError:
                stats.skipped_unreadable += 1
                continue
            if _attributes(stat_result) & FILE_ATTRIBUTE_REPARSE_POINT:
                stats.skipped_reparse += 1
                continue
            if is_directory:
                if entry.name.casefold() in SKIP_DIRECTORY_NAMES:
                    continue
                if depth + 1 > MAX_DIRECTORY_DEPTH:
                    stats.skipped_unreadable += 1
                    continue
                stack.append((entry.path, depth + 1))
                continue
            if is_cloud_placeholder(entry.path):
                stats.skipped_cloud += 1
                continue
            size = int(stat_result.st_size)
            stats.total_bytes += size
            stats.files += 1
            if size >= min_size:
                heapq.heappush(heap, (size, entry.path, float(stat_result.st_mtime)))
                if len(heap) > top:
                    heapq.heappop(heap)
        if progress is not None and stats.files % 2000 < len(entries):
            progress(stats.files, current)
        if budget_s > 0 and (time.monotonic() - started) > budget_s:
            stats.truncated = True
            break

    stats.elapsed_ms = int((time.monotonic() - started) * 1000)
    hits = [
        LargeFileHit(path=path, size=size, mtime=mtime)
        for size, path, mtime in sorted(heap, key=lambda item: item[0], reverse=True)
    ]
    return hits, stats


def overview_scan(
    root: str,
    *,
    token: CancelToken | None = None,
    top_files: int = 10,
    min_file_size: int = 0,
    progress: ProgressCallback | None = None,
    budget_s: float = 0.0,
) -> OverviewScanResult:
    """只遍历一次，同时得到「顶层子项占用聚合」与「最大文件排行」。"""

    root_abs = os.path.abspath(root)
    prefix_len = len(root_abs) + (0 if root_abs.endswith(os.sep) else 1)
    result = OverviewScanResult()
    aggregate: dict[str, dict[str, object]] = {}
    heap: list[tuple[int, str, float]] = []
    top_files = max(1, top_files)
    started = time.monotonic()
    stack: list[tuple[str, int]] = [(root_abs, 0)]

    while stack:
        _check_token(token)
        current, depth = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError:
            result.stats.skipped_unreadable += 1
            continue
        result.stats.dirs += 1
        for entry in entries:
            try:
                stat_result = entry.stat(follow_symlinks=False)
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError:
                result.stats.skipped_unreadable += 1
                continue
            if _attributes(stat_result) & FILE_ATTRIBUTE_REPARSE_POINT:
                result.stats.skipped_reparse += 1
                continue
            if is_directory:
                if entry.name.casefold() in SKIP_DIRECTORY_NAMES:
                    continue
                if depth + 1 > MAX_DIRECTORY_DEPTH:
                    result.stats.skipped_unreadable += 1
                    continue
                stack.append((entry.path, depth + 1))
                continue
            if is_cloud_placeholder(entry.path):
                result.stats.skipped_cloud += 1
                continue
            size = int(stat_result.st_size)
            mtime = float(stat_result.st_mtime)
            result.stats.total_bytes += size
            result.stats.files += 1

            try:
                relative = entry.path[prefix_len:]
            except (IndexError, ValueError):  # pragma: no cover - 防御性
                relative = entry.name
            parts = relative.split(os.sep)
            key = parts[0] if parts else entry.name
            bucket = aggregate.get(key)
            if bucket is None:
                bucket = {"size": 0, "files": 0, "mtime": 0.0, "root_file": len(parts) == 1}
                aggregate[key] = bucket
            bucket["size"] = int(bucket["size"]) + size
            bucket["files"] = int(bucket["files"]) + 1
            bucket["mtime"] = max(float(bucket["mtime"]), mtime)

            if size >= min_file_size:
                heapq.heappush(heap, (size, entry.path, mtime))
                if len(heap) > top_files:
                    heapq.heappop(heap)

        if progress is not None and result.stats.files % 2000 < len(entries):
            progress(result.stats.files, current)
        if budget_s > 0 and (time.monotonic() - started) > budget_s:
            result.stats.truncated = True
            break

    entries_out = [
        OverviewEntry(
            name=name,
            path=os.path.join(root_abs, name),
            is_dir=not bool(bucket.get("root_file")),
            size=int(bucket.get("size", 0)),
            file_count=int(bucket.get("files", 0)),
            mtime=float(bucket.get("mtime", 0.0) or 0.0),
        )
        for name, bucket in aggregate.items()
    ]
    entries_out.sort(key=lambda item: item.size, reverse=True)
    result.entries = entries_out
    result.top_files = [
        LargeFileHit(path=path, size=size, mtime=mtime)
        for size, path, mtime in sorted(heap, key=lambda item: item[0], reverse=True)
    ]
    result.stats.elapsed_ms = int((time.monotonic() - started) * 1000)
    if result.stats.truncated:
        result.warnings.append(
            ScanWarning(
                "overview_budget",
                f"空间盘点达到时间预算（{budget_s:.0f}s），结果可能不完整",
                phase="overview",
            )
        )
    if result.stats.skipped_unreadable:
        result.warnings.append(
            ScanWarning(
                "overview_unreadable",
                f"{result.stats.skipped_unreadable} 个目录/文件无法读取（权限不足或已被占用），已跳过",
                phase="overview",
            )
        )
    return result


# --------------------------------------------------------------------------- 分区
@dataclass(frozen=True, slots=True)
class DriveInfo:
    letter: str
    root: str
    drive_type: int
    total_bytes: int
    free_bytes: int

    @property
    def used_bytes(self) -> int:
        return max(0, self.total_bytes - self.free_bytes)

    @property
    def type_label(self) -> str:
        return {2: "可移动", 3: "本地磁盘", 4: "网络", 5: "光驱", 6: "内存盘"}.get(
            self.drive_type, "其他"
        )


def drive_type_of(root: str) -> int:
    if os.name != "nt":
        return 3
    try:
        import ctypes  # noqa: PLC0415 - 延迟导入

        return int(ctypes.windll.kernel32.GetDriveTypeW(root))  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - 无法判断按未知处理
        return 0


def list_drives(*, fixed_only: bool = True) -> list[DriveInfo]:
    """枚举卷（默认只返回本地固定磁盘）。"""

    drives: list[DriveInfo] = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if not os.path.exists(root):
            continue
        drive_type = drive_type_of(root)
        if fixed_only and drive_type != 3:
            continue
        total, free = drive_usage(root)
        if total <= 0:
            continue
        drives.append(
            DriveInfo(
                letter=f"{letter}:",
                root=root,
                drive_type=drive_type,
                total_bytes=total,
                free_bytes=free,
            )
        )
    return drives


def system_drive() -> str:
    """系统盘根目录（如 ``C:\\``）。"""

    drive = os.environ.get("SystemDrive") or "C:"
    return drive.rstrip("\\") + "\\"


def resolve_drive_root(text: str | None) -> str | None:
    """把 ``C`` / ``C:`` / ``C:\\`` / 任意路径 统一成卷根；无法识别返回 ``None``。"""

    if not text:
        return None
    candidate = str(text).strip().strip('"').strip("'")
    if not candidate:
        return None
    if len(candidate) == 1 and candidate.isalpha():
        root = candidate.upper() + ":\\"
        return root if os.path.exists(root) else None
    try:
        drive, _rest = os.path.splitdrive(os.path.abspath(candidate))
    except (OSError, ValueError):
        return None
    if not drive:
        return None
    root = drive.rstrip("\\") + "\\"
    return root if os.path.exists(root) else None


def drive_usage(root: str) -> tuple[int, int]:
    """返回 ``(总量, 可用)`` 字节；失败返回 ``(0, 0)``。"""

    try:
        import shutil  # noqa: PLC0415 - 延迟导入

        usage = shutil.disk_usage(root)
    except OSError:
        return 0, 0
    return int(usage.total), int(usage.free)


def format_skips(stats: WalkStats) -> list[str]:
    """把跳过/截断计数转成可展示的提示行。"""

    notes: list[str] = []
    if stats.skipped_reparse:
        notes.append(f"跳过 {stats.skipped_reparse} 个符号链接/junction")
    if stats.skipped_unreadable:
        notes.append(f"{stats.skipped_unreadable} 个目录/文件无法读取（权限或占用）")
    if stats.skipped_cloud:
        notes.append(f"跳过 {stats.skipped_cloud} 个云占位文件")
    if stats.truncated:
        notes.append("达到扫描预算，结果可能不完整")
    return notes


def normalize_key(path: str) -> str:
    """便于测试的路径键。"""

    return normalize_path(path)


def is_root_path(path: str) -> bool:
    return is_drive_root(path)


__all__ = [
    "ChildEntry",
    "DriveInfo",
    "OverviewScanResult",
    "WalkStats",
    "drive_type_of",
    "drive_usage",
    "format_skips",
    "is_root_path",
    "largest_files",
    "list_children",
    "list_drives",
    "normalize_key",
    "overview_scan",
    "resolve_drive_root",
    "system_drive",
    "walk_size",
]
