"""后台扫描任务基类与线程生命周期管理。

线程模型：
* ``ScanJob`` 是 ``QObject``，由 ``JobRunner`` 移动到独立 ``QThread`` 执行；
* 所有信号在主线程接收，UI 只允许在信号回调里更新控件；
* 取消通过共享 ``CancelToken`` 协作完成，禁止 ``QThread.terminate()``。
"""

from __future__ import annotations

import logging
import time

from PySide6.QtCore import QObject, QThread, Signal, Slot

from ..core.cancel import CancelToken, ScanCancelled
from ..core.models import ScanWarning

logger = logging.getLogger(__name__)


class ScanJob(QObject):
    """一次扫描任务。子类实现 ``_run()``，通过基类信号与 UI 通信。"""

    stage_changed = Signal(str)
    progress = Signal(int, str)  # 0-100, 文案
    warning = Signal(object)  # ScanWarning
    finished = Signal(object)  # 结果对象
    failed = Signal(str)
    cancelled = Signal()

    PROGRESS_INTERVAL_S = 0.1

    def __init__(self, token: CancelToken | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.token = token or CancelToken()
        self._last_progress_emit = 0.0

    @Slot()
    def run(self) -> None:
        """线程入口：统一异常/取消边界。"""

        try:
            self._run()
        except ScanCancelled as exc:
            logger.info("扫描被取消：%s", exc)
            self.cancelled.emit()
        except Exception as exc:  # noqa: BLE001 - 会话级失败必须上报给 UI
            logger.exception("扫描失败")
            self.failed.emit(f"{type(exc).__name__}: {exc}")

    def _run(self) -> None:  # pragma: no cover - 子类实现
        raise NotImplementedError

    def _stage(self, text: str) -> None:
        self.stage_changed.emit(text)

    def _progress(self, percent: float, text: str = "", *, force: bool = False) -> None:
        now = time.monotonic()
        clamped = max(0, min(100, int(percent)))
        if not force and clamped < 100 and (now - self._last_progress_emit) < self.PROGRESS_INTERVAL_S:
            return
        self._last_progress_emit = now
        self.progress.emit(clamped, text)

    def _warn(self, warning: ScanWarning) -> None:
        logger.warning("[%s] %s %s", warning.code, warning.message, warning.path or "")
        self.warning.emit(warning)


class JobRunner(QObject):
    """管理单个 ScanJob + 其 QThread 的生命周期（同一时间只允许一个任务）。"""

    started = Signal()
    finished = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._job: ScanJob | None = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def start(self, job: ScanJob) -> bool:
        """启动任务；已有任务运行时返回 ``False``。"""

        if self.is_running():
            return False
        thread = QThread()
        job.moveToThread(thread)
        thread.started.connect(job.run)
        job.finished.connect(thread.quit)
        job.failed.connect(thread.quit)
        job.cancelled.connect(thread.quit)
        thread.finished.connect(self._on_thread_finished)
        self._thread = thread
        self._job = job
        thread.start()
        self.started.emit()
        return True

    def cancel(self) -> None:
        if self._job is not None:
            self._job.token.cancel()

    def wait(self, msecs: int = 3000) -> bool:
        """等待线程结束（仅用于退出程序时调用）。返回是否已结束。"""

        thread = self._thread
        if thread is None:
            return True
        return thread.wait(msecs)

    @Slot()
    def _on_thread_finished(self) -> None:
        thread = self._thread
        job = self._job
        self._thread = None
        self._job = None
        if job is not None:
            job.deleteLater()
        if thread is not None:
            thread.deleteLater()
        self.finished.emit()
