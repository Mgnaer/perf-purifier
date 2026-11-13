"""模块 B 扫描任务：遍历 → 过滤/分桶/4KB 指纹 → SHA-256 → 分组。

1C 增强：排除规则、类型/时间过滤、并行哈希（HDD 自适应）、SQLite 哈希缓存、
建议保留。全部只读；单文件失败只跳过，可随时取消。
"""

from __future__ import annotations

import logging
import time

from PySide6.QtCore import QObject

from ..core.cancel import CancelToken
from ..core.fmt import human_bytes
from ..core.models import Completeness, FileScanOptions, FileScanResult, ScanWarning
from ..core.winapi import detect_storage_media
from ..module_b.cache import HashCache
from ..module_b.dedupe import find_duplicates
from ..module_b.hasher import choose_hash_workers
from ..module_b.walker import walk_directory
from .base_job import ScanJob

logger = logging.getLogger(__name__)


class FileScanJob(ScanJob):
    """阶段 1C：重复文件/大文件只读扫描（含过滤、并发哈希与哈希缓存）。"""

    def __init__(
        self,
        options: FileScanOptions,
        *,
        token: CancelToken | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(token, parent)
        self._options = options

    def _run(self) -> None:
        started_at = time.time()
        options = self._options
        warnings: list[ScanWarning] = []

        def record(warning: ScanWarning) -> None:
            warnings.append(warning)
            self._warn(warning)

        # ---- 介质探测与并发策略（HDD 串行，SSD 最多 4 并发）----
        media_type = detect_storage_media(options.root)
        workers = choose_hash_workers(media_type, options.hash_workers)
        self._stage(f"正在遍历目录…（哈希并发 {workers}，介质：{media_type}）")

        # ---- 1. 遍历目录（0-30%）----
        def on_walk_progress(percent: int, text: str) -> None:
            self._progress(percent * 0.30, text)

        walk = walk_directory(
            options.root,
            self.token,
            max_files=options.max_files,
            budget_s=options.walk_budget_s,
            large_limit=options.large_limit,
            exclude_patterns=options.exclude_patterns,
            progress=on_walk_progress,
        )
        for warning in walk.warnings:
            record(warning)

        # ---- 2. 哈希缓存（可选；失败自动降级）----
        cache: HashCache | None = None
        if options.use_cache:
            try:
                cache = HashCache(HashCache.default_path(), ttl_days=options.cache_ttl_days)
            except Exception as exc:  # noqa: BLE001 - 缓存不可用不应影响扫描
                record(
                    ScanWarning(
                        "cache_unavailable",
                        f"哈希缓存不可用（{type(exc).__name__}: {exc}），本次不使用缓存",
                        phase="cache",
                    )
                )

        # ---- 3. 快速指纹 + SHA-256 全量（30-97%）----
        self._progress(30, "正在按大小分桶并计算 4KB 快速指纹…", force=True)

        def on_partial_progress(done: int, total: int) -> None:
            percent = 30.0 + (done / total * 25.0 if total else 25.0)
            self._progress(percent, f"快速指纹 {done}/{total} 个候选文件（并发 {workers}）")

        def on_full_progress(done: int, total: int) -> None:
            percent = 55.0 + (done / total * 42.0 if total else 42.0)
            self._progress(percent, f"SHA256 校验 {human_bytes(done)} / {human_bytes(total)}")

        try:
            outcome = find_duplicates(
                walk.records,
                self.token,
                min_size=options.min_size,
                extensions=options.extensions,
                modified_after=options.modified_after,
                workers=workers,
                cache=cache,
                progress_partial=on_partial_progress,
                progress_full=on_full_progress,
            )
        finally:
            if cache is not None:
                cache.close()
        for warning in outcome.warnings:
            record(warning)

        completeness = walk.completeness
        if outcome.failed_reads or outcome.unstable_files:
            completeness = Completeness.PARTIAL

        finished_at = time.time()
        result = FileScanResult(
            root=options.root,
            options=options,
            started_at=started_at,
            finished_at=finished_at,
            duplicate_groups=outcome.groups,
            large_files=walk.large_files,
            files_scanned=walk.files_scanned,
            dirs_scanned=walk.dirs_scanned,
            total_bytes=walk.total_bytes,
            skipped_reparse=walk.skipped_reparse,
            skipped_unreadable=walk.skipped_unreadable,
            skipped_cloud=walk.skipped_cloud,
            skipped_excluded=walk.skipped_excluded,
            failed_reads=outcome.failed_reads,
            unstable_files=outcome.unstable_files,
            partial_hashed=outcome.partial_hashed,
            full_hashed=outcome.full_hashed,
            cache_hits=outcome.cache_hits,
            hash_bytes=outcome.hash_bytes,
            hash_workers=workers,
            media_type=media_type,
            warnings=warnings,
            completeness=completeness,
            elapsed_ms=int((finished_at - started_at) * 1000),
            truncated=walk.truncated,
        )
        self._progress(100, "扫描完成", force=True)
        self.finished.emit(result)
