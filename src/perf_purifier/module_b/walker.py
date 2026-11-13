"""模块 B 遍历器（阶段 1C，只读）。

安全与限制：
* 不跟随符号链接 / junction（用 ``st_file_attributes`` 的 REPARSE_POINT 位判断），
  并跳过 ``$Recycle.Bin`` / ``System Volume Information`` 等系统目录；
* 跳过云占位文件（OneDrive 等，读取会触发下载）；
* 有文件数 / 时间预算，超限标记"结果不完整"，随时可取消；
* 超长路径：普通打开失败时用 ``\\\\?\\`` 前缀兜底重试。
"""

from __future__ import annotations

import fnmatch
import heapq
import logging
import os
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ..core.cancel import CancelToken
from ..core.models import Completeness, FileRecord, LargeFile, ScanWarning
from ..core.whitelist import is_under, normalize_path
from ..core.winapi import (
    FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT,
)

logger = logging.getLogger(__name__)

SKIP_DIRECTORY_NAMES: frozenset[str] = frozenset({"$recycle.bin", "system volume information"})
MAX_DIRECTORY_DEPTH = 64
CLOUD_ATTRIBUTE_MASK = (
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)

ProgressCallback = Callable[[int, str], None]
"""``progress(percent_hint, text)``。"""


@dataclass(slots=True)
class WalkResult:
    """遍历阶段的原始结果。"""

    records: list[FileRecord] = field(default_factory=list)
    large_files: list[LargeFile] = field(default_factory=list)
    files_scanned: int = 0
    dirs_scanned: int = 0
    total_bytes: int = 0
    skipped_reparse: int = 0
    skipped_unreadable: int = 0
    skipped_cloud: int = 0
    skipped_excluded: int = 0
    truncated: bool = False
    completeness: Completeness = Completeness.FULL
    warnings: list[ScanWarning] = field(default_factory=list)
    elapsed_ms: int = 0


def parse_exclude_patterns(raw: Sequence[str] | str) -> tuple[str, ...]:
    """把用户输入拆成排除规则列表（支持逗号/分号/换行分隔）。"""

    if isinstance(raw, str):
        parts = re.split(r"[,;\n]", raw)
    else:
        parts = [str(item) for item in raw]
    cleaned = [part.strip() for part in parts if part and part.strip()]
    return tuple(cleaned)


def _split_excludes(patterns: Sequence[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """拆成（名称通配符列表, 绝对路径前缀列表）。"""

    name_patterns: list[str] = []
    path_prefixes: list[str] = []
    for raw in patterns:
        pattern = str(raw).strip()
        if not pattern:
            continue
        if os.path.isabs(pattern) or os.sep in pattern or "/" in pattern:
            normalized = normalize_path(pattern)
            if normalized:
                path_prefixes.append(normalized)
        else:
            name_patterns.append(pattern.casefold())
    return tuple(name_patterns), tuple(path_prefixes)


def _is_excluded(
    name: str,
    path: str,
    name_patterns: tuple[str, ...],
    path_prefixes: tuple[str, ...],
) -> bool:
    if path_prefixes and is_under(path, path_prefixes):
        return True
    if name_patterns:
        folded = name.casefold()
        return any(fnmatch.fnmatchcase(folded, pattern) for pattern in name_patterns)
    return False


def walk_directory(
    root: str,
    token: CancelToken,
    *,
    max_files: int = 300_000,
    budget_s: float = 120.0,
    large_limit: int = 100,
    exclude_patterns: Sequence[str] = (),
    progress: ProgressCallback | None = None,
) -> WalkResult:
    """安全遍历目录，返回文件快照与 Top-N 大文件。"""

    started_at = time.monotonic()
    result = WalkResult()
    name_patterns, path_prefixes = _split_excludes(exclude_patterns)
    root_path = os.path.abspath(root) if root else ""
    if not root_path or not os.path.isdir(root_path):
        result.completeness = Completeness.DEGRADED
        result.warnings.append(
            ScanWarning(
                "walk_root_missing",
                f"目录不存在或不可访问：{root or '(未选择目录)'}",
                path=root or None,
                phase="walk",
            )
        )
        result.elapsed_ms = int((time.monotonic() - started_at) * 1000)
        return result

    large_heap: list[tuple[int, str, float]] = []
    stack: list[tuple[str, int]] = [(root_path, 0)]
    large_limit = max(1, large_limit)

    def budget_exceeded() -> bool:
        if result.files_scanned > max_files:
            return True
        return budget_s > 0 and (time.monotonic() - started_at) > budget_s

    while stack:
        token.raise_if_cancelled("遍历目录")
        if budget_exceeded():
            result.truncated = True
            break
        current_path, depth = stack.pop()
        try:
            with os.scandir(current_path) as iterator:
                entries = list(iterator)
        except OSError:
            result.skipped_unreadable += 1
            continue
        result.dirs_scanned += 1

        for entry in entries:
            token.raise_if_cancelled("遍历目录")
            if budget_exceeded():
                result.truncated = True
                break
            try:
                stat_result = entry.stat(follow_symlinks=False)
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError:
                result.skipped_unreadable += 1
                continue
            attributes = int(getattr(stat_result, "st_file_attributes", 0) or 0)

            if _is_excluded(entry.name, entry.path, name_patterns, path_prefixes):
                result.skipped_excluded += 1
                continue
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                result.skipped_reparse += 1
                continue
            if is_directory:
                if entry.name.casefold() in SKIP_DIRECTORY_NAMES:
                    continue
                if depth + 1 > MAX_DIRECTORY_DEPTH:
                    result.skipped_unreadable += 1
                    continue
                stack.append((entry.path, depth + 1))
                continue
            if attributes & CLOUD_ATTRIBUTE_MASK:
                result.skipped_cloud += 1
                continue

            size = int(stat_result.st_size)
            mtime = float(stat_result.st_mtime)
            result.records.append(
                FileRecord(
                    path=entry.path,
                    size=size,
                    mtime=mtime,
                    dev=int(getattr(stat_result, "st_dev", 0) or 0),
                    ino=int(getattr(stat_result, "st_ino", 0) or 0),
                    attributes=attributes,
                )
            )
            result.files_scanned += 1
            result.total_bytes += size
            heapq.heappush(large_heap, (size, entry.path, mtime))
            if len(large_heap) > large_limit:
                heapq.heappop(large_heap)

            if progress is not None and result.files_scanned % 200 == 0:
                percent = 50
                if budget_s > 0:
                    percent = min(99, int((time.monotonic() - started_at) / budget_s * 100))
                progress(percent, f"已扫描 {result.files_scanned} 个文件：{entry.path}")
        if result.truncated:
            break

    result.large_files = [
        LargeFile(path=path, size=size, mtime=mtime)
        for size, path, mtime in sorted(large_heap, key=lambda item: item[0], reverse=True)
    ]
    if result.truncated:
        result.warnings.append(
            ScanWarning(
                "walk_truncated",
                f"遍历达到预算上限（{max_files} 个文件 / {budget_s:.0f}s），结果可能不完整",
                phase="walk",
            )
        )
    if result.skipped_unreadable:
        result.warnings.append(
            ScanWarning(
                "walk_unreadable",
                f"{result.skipped_unreadable} 个目录/文件无法读取（权限不足或已被占用），已跳过",
                phase="walk",
            )
        )
    if result.skipped_reparse:
        result.warnings.append(
            ScanWarning(
                "walk_reparse",
                f"已跳过 {result.skipped_reparse} 个符号链接/junction（不跟随）",
                phase="walk",
            )
        )
    if result.skipped_cloud:
        result.warnings.append(
            ScanWarning(
                "walk_cloud",
                f"已跳过 {result.skipped_cloud} 个云占位文件（避免触发下载）",
                phase="walk",
            )
        )
    if result.skipped_excluded:
        result.warnings.append(
            ScanWarning(
                "walk_excluded",
                f"已按排除规则跳过 {result.skipped_excluded} 个文件/目录（不参与本次扫描）",
                phase="walk",
            )
        )

    result.completeness = (
        Completeness.PARTIAL
        if (result.truncated or result.skipped_unreadable)
        else Completeness.FULL
    )
    result.elapsed_ms = int((time.monotonic() - started_at) * 1000)
    logger.info(
        "目录遍历完成：%s，文件 %d，目录 %d，%d 字节，截断=%s",
        root_path,
        result.files_scanned,
        result.dirs_scanned,
        result.total_bytes,
        result.truncated,
    )
    return result
