"""模块 C 磁盘空间扫描任务（后台线程执行，可取消）。

复用模块 A/B 的 ``ScanJob`` 契约：``finished(object)`` 返回
:class:`~perf_purifier.module_c.models.SpaceScanResult`，取消走 ``CancelToken``。
"""

from __future__ import annotations

from PySide6.QtCore import QObject

from ..core.cancel import CancelToken
from ..module_c import scan as scan_module
from ..module_c.models import SpaceScanResult
from .base_job import ScanJob


class SpaceScanJob(ScanJob):
    """一次「磁盘空间」扫描（概览 + 垃圾规则，只读）。"""

    def __init__(
        self,
        *,
        config: object,
        is_admin: bool,
        drive: str | None = None,
        include_caution: bool = False,
        include_system: bool = False,
        top_files: int = 10,
        min_file_size: int = 0,
        parent: QObject | None = None,
        token: CancelToken | None = None,
    ) -> None:
        super().__init__(token, parent)
        self._config = config
        self._is_admin = is_admin
        self._drive = drive
        self._include_caution = include_caution
        self._include_system = include_system
        self._top_files = top_files
        self._min_file_size = min_file_size

    def _run(self) -> None:
        self._stage("读取磁盘信息…")

        def progress(percent: int, text: str) -> None:
            self._progress(percent, text)

        result: SpaceScanResult = scan_module.scan_space(
            drive=self._drive,
            token=self.token,
            config=self._config,
            is_admin=self._is_admin,
            include_caution=self._include_caution,
            include_system=self._include_system,
            top_files=self._top_files,
            min_file_size=self._min_file_size,
            progress=progress,
        )
        self._progress(100, "扫描完成", force=True)
        self.finished.emit(result)


__all__ = ["SpaceScanJob"]
