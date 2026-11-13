"""重复文件检测流水线（阶段 1C，纯逻辑，可单测）。

流程：过滤（最小大小/扩展名/修改时间）→ 大小分桶 → 4KB 快速指纹 → SHA-256 全量
→ 分组 → 硬链接识别 → 建议保留。

1C 增强：
* 支持排除后的类型/时间过滤；
* 快速指纹与全量哈希支持多线程（HDD 自动串行，见 ``hasher.choose_hash_workers``）；
* 可选 SQLite 哈希缓存（大小+mtime 未变化时跳过全文件读取）；
* 每个重复组给出"建议保留"文件（路径层级最浅 → 修改时间更早 → 路径字典序），
  并在 files 顺序中把建议保留项放在第一位（仅建议，不执行任何删除）。
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace

from ..core.cancel import CancelToken, ScanCancelled
from ..core.models import DuplicateGroup, FileRecord, ScanWarning
from .hasher import digest_full, digest_partial

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int, int], None]
_CHUNK_SIZE = 512


@dataclass(slots=True)
class DedupeOutcome:
    groups: list[DuplicateGroup] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)
    partial_hashed: int = 0
    full_hashed: int = 0
    cache_hits: int = 0
    hash_bytes: int = 0
    failed_reads: int = 0
    unstable_files: int = 0
    workers: int = 1


def normalize_extensions(values: Sequence[str]) -> tuple[str, ...]:
    """把扩展名规范化为小写、带点前缀的元组（空序列表示不限制）。"""

    cleaned: list[str] = []
    for item in values:
        text = str(item).strip().casefold()
        if not text:
            continue
        if not text.startswith("."):
            text = "." + text
        if text not in cleaned:
            cleaned.append(text)
    return tuple(cleaned)


def _eligible(
    record: FileRecord,
    min_size: int,
    extensions: tuple[str, ...],
    modified_after: float,
) -> bool:
    if record.size < min_size:
        return False
    if extensions and record.suffix not in extensions:
        return False
    if modified_after > 0 and record.mtime < modified_after:
        return False
    return True


def _unchanged(record: FileRecord) -> bool:
    """确认文件在记录之后未被修改/替换。"""

    try:
        stat_result = os.stat(record.path, follow_symlinks=False)
    except OSError:
        return False
    return int(stat_result.st_size) == record.size and int(stat_result.st_mtime) == int(record.mtime)


def _resolve_identity(record: FileRecord) -> FileRecord:
    """补齐文件唯一标识（设备号, inode）。

    Windows 上 ``DirEntry.stat()`` 的 ``st_dev/st_ino`` 恒为 0（只有 ``os.stat()``
    会返回真实卷序列号与文件索引），因此这里只对进入重复候选的文件补一次 ``os.stat``。
    """

    if record.ino and record.dev:
        return record
    try:
        stat_result = os.stat(record.path, follow_symlinks=False)
    except OSError:
        return record
    dev = int(getattr(stat_result, "st_dev", 0) or 0)
    ino = int(getattr(stat_result, "st_ino", 0) or 0)
    if not dev and not ino:
        return record
    return replace(record, dev=dev, ino=ino)


def _choose_keep(files: Sequence[FileRecord]) -> FileRecord:
    """选择"建议保留"的文件。

    启发式：路径层级最浅（更可能是原始位置）→ 修改时间更早 → 路径字典序。
    内容完全相同，保留建议只影响元数据与后续操作便利性，不构成安全结论。
    """

    return min(files, key=lambda record: (record.path_depth, record.mtime, record.path.casefold()))


def _partial_task(record: FileRecord) -> tuple[FileRecord, str | None]:
    try:
        return record, digest_partial(record.path)
    except OSError:
        return record, None


def _full_task(record: FileRecord, token: CancelToken) -> tuple[FileRecord, str | None, int, str]:
    """返回 (record, digest, 读取字节数, 状态)；状态 ∈ ok/unstable/failed。"""

    if not _unchanged(record):
        return record, None, 0, "unstable"
    try:
        digest, read_bytes = digest_full(record.path, token)
    except ScanCancelled:
        raise
    except OSError:
        return record, None, 0, "failed"
    except Exception:  # noqa: BLE001 - 读取中途异常按失败处理，不中断整体扫描
        logger.debug("读取文件失败：%s", record.path, exc_info=True)
        return record, None, 0, "failed"
    if not _unchanged(record):
        return record, None, read_bytes, "unstable"
    return record, digest, read_bytes, "ok"


def _parallel_partial(
    records: Sequence[FileRecord],
    workers: int,
    token: CancelToken,
) -> list[tuple[FileRecord, str | None]]:
    if workers <= 1 or len(records) <= 1:
        results: list[tuple[FileRecord, str | None]] = []
        for record in records:
            token.raise_if_cancelled("快速指纹")
            results.append(_partial_task(record))
        return results

    results = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pp-partial") as executor:
        for start in range(0, len(records), _CHUNK_SIZE):
            token.raise_if_cancelled("快速指纹")
            chunk = records[start : start + _CHUNK_SIZE]
            futures = [executor.submit(_partial_task, record) for record in chunk]
            for future in futures:
                results.append(future.result())
    return results


def find_duplicates(
    records: Sequence[FileRecord],
    token: CancelToken,
    *,
    min_size: int = 1024,
    extensions: Sequence[str] = (),
    modified_after: float = 0.0,
    workers: int = 1,
    cache: object | None = None,
    progress_partial: ProgressCallback | None = None,
    progress_full: ProgressCallback | None = None,
) -> DedupeOutcome:
    """返回重复分组与统计。

    ``cache`` 需提供 ``lookup(record) -> str | None`` 与 ``store(record, digest)``
    （通常为 :class:`module_b.cache.HashCache`），可为 None。
    取消时抛 ``ScanCancelled``。
    """

    outcome = DedupeOutcome(workers=max(1, workers))
    normalized_extensions = normalize_extensions(extensions)
    workers = max(1, workers)

    # ---- 1. 过滤 + 大小分桶：大小不同必然不重复 ----
    buckets: dict[int, list[FileRecord]] = defaultdict(list)
    for record in records:
        if not _eligible(record, min_size, normalized_extensions, modified_after):
            continue
        buckets[record.size].append(record)
    size_groups = [files for files in buckets.values() if len(files) >= 2]
    candidates = [record for files in size_groups for record in files]
    total_candidates = len(candidates)

    # ---- 2. 4KB 快速指纹（可并发）----
    partial_map: dict[tuple[int, str], list[FileRecord]] = defaultdict(list)
    for index, (record, digest) in enumerate(_parallel_partial(candidates, workers, token), start=1):
        if digest is None:
            outcome.failed_reads += 1
        else:
            outcome.partial_hashed += 1
            partial_map[(record.size, digest)].append(record)
        if progress_partial is not None and index % 50 == 0:
            progress_partial(index, total_candidates)
    if progress_partial is not None:
        progress_partial(total_candidates, total_candidates)

    fingerprint_groups = [files for files in partial_map.values() if len(files) >= 2]
    to_hash: list[FileRecord] = [record for files in fingerprint_groups for record in files]
    total_bytes = sum(record.size for record in to_hash)
    digest_by_path: dict[str, str] = {}

    # ---- 3a. 优先使用 SQLite 哈希缓存 ----
    pending_hash: list[FileRecord] = []
    for record in to_hash:
        token.raise_if_cancelled("SHA256 全量哈希")
        if not _unchanged(record):
            outcome.unstable_files += 1
            continue
        cached: str | None = None
        if cache is not None:
            try:
                cached = cache.lookup(record)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001 - 缓存异常降级为无缓存
                logger.warning("哈希缓存查询失败，本次忽略缓存", exc_info=True)
                cache = None
        if cached:
            digest_by_path[record.path] = cached
            outcome.cache_hits += 1
            outcome.full_hashed += 1
        else:
            pending_hash.append(record)

    # ---- 3b. 其余文件并行/串行做全量 SHA-256 ----
    bytes_done = [0]

    def apply_result(record: FileRecord, digest: str | None, read_bytes: int, status: str) -> None:
        bytes_done[0] += read_bytes
        outcome.hash_bytes += read_bytes
        if status == "ok" and digest:
            outcome.full_hashed += 1
            digest_by_path[record.path] = digest
        elif status == "unstable":
            outcome.unstable_files += 1
        else:
            outcome.failed_reads += 1
        if progress_full is not None:
            progress_full(min(bytes_done[0], total_bytes), total_bytes)

    if workers <= 1 or len(pending_hash) <= 1:
        for record in pending_hash:
            token.raise_if_cancelled("SHA256 全量哈希")
            apply_result(*_full_task(record, token))
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pp-fullhash") as executor:
            for start in range(0, len(pending_hash), _CHUNK_SIZE):
                token.raise_if_cancelled("SHA256 全量哈希")
                chunk = pending_hash[start : start + _CHUNK_SIZE]
                futures = [executor.submit(_full_task, record, token) for record in chunk]
                for future in futures:
                    apply_result(*future.result())
    if progress_full is not None:
        progress_full(min(bytes_done[0], total_bytes), total_bytes)

    # ---- 4. 全量哈希分组 ----
    full_map: dict[tuple[int, str], list[FileRecord]] = defaultdict(list)
    for record in to_hash:
        digest = digest_by_path.get(record.path)
        if digest is None:
            continue
        full_map[(record.size, digest)].append(record)
        if cache is not None:
            try:
                cache.store(record, digest)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                logger.warning("哈希缓存写入失败，本次忽略缓存", exc_info=True)
                cache = None

    # ---- 5. 分组 + 硬链接识别 + 建议保留 ----
    raw_groups: list[DuplicateGroup] = []
    identity_unknown = False
    for (size, digest), files in full_map.items():
        if len(files) < 2:
            continue
        resolved = tuple(
            sorted((_resolve_identity(record) for record in files), key=lambda item: item.path.casefold())
        )
        if any(record.ino == 0 for record in resolved):
            identity_unknown = True
            distinct_inodes = len(resolved)
        else:
            distinct_inodes = len({record.identity for record in resolved})
        suggested = _choose_keep(resolved)
        ordered = (suggested,) + tuple(record for record in resolved if record.path != suggested.path)
        raw_groups.append(
            DuplicateGroup(
                group_id=0,
                size=size,
                full_sha256=digest,
                files=ordered,
                distinct_inodes=distinct_inodes,
                has_hardlinks=distinct_inodes < len(ordered),
                already_hardlinked=distinct_inodes == 1 and not identity_unknown,
                suggested_keep_path=suggested.path,
            )
        )
    raw_groups.sort(key=lambda group: (group.reclaimable_bytes, group.size), reverse=True)
    outcome.groups = [
        DuplicateGroup(
            group_id=index,
            size=group.size,
            full_sha256=group.full_sha256,
            files=group.files,
            distinct_inodes=group.distinct_inodes,
            has_hardlinks=group.has_hardlinks,
            already_hardlinked=group.already_hardlinked,
            suggested_keep_path=group.suggested_keep_path,
        )
        for index, group in enumerate(raw_groups, start=1)
    ]

    if outcome.failed_reads:
        outcome.warnings.append(
            ScanWarning(
                "hash_read_failed",
                f"{outcome.failed_reads} 个文件读取失败（权限/占用/已删除），已从结果中排除",
                phase="hash",
            )
        )
    if outcome.unstable_files:
        outcome.warnings.append(
            ScanWarning(
                "hash_unstable",
                f"{outcome.unstable_files} 个文件在扫描期间发生变化，已从结果中排除",
                phase="hash",
            )
        )
    if identity_unknown:
        outcome.warnings.append(
            ScanWarning(
                "hardlink_unknown",
                "部分文件无法读取唯一标识（inode），硬链接识别可能不准确，可回收空间按最坏情况估算",
                phase="hash",
            )
        )
    logger.info(
        "重复检测完成：候选 %d，4KB 指纹 %d，全量哈希 %d（缓存命中 %d），重复组 %d，可回收 %d 字节，并发 %d",
        total_candidates,
        outcome.partial_hashed,
        outcome.full_hashed,
        outcome.cache_hits,
        len(outcome.groups),
        sum(group.reclaimable_bytes for group in outcome.groups),
        workers,
    )
    return outcome
