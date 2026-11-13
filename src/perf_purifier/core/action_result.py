"""动作执行结果的通用数据类（**不依赖 Qt**）。

从 ``jobs/action_job.py`` 下沉而来：模块 C（磁盘清理）的 CLI 需要执行器的返回类型，
但命令行入口不应被迫依赖 PySide6。``jobs.action_job`` 继续 re-export 同名符号，
保持既有导入路径兼容。
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ActionExecutionResult"]


@dataclass(frozen=True, slots=True)
class ActionExecutionResult:
    """单个目标的执行结果（由 executor 返回）。

    ``result`` ∈ ``success`` / ``failed`` / ``skipped`` / ``refused`` / ``dry_run``。
    """

    result: str
    error_code: str = ""
    detail: str = ""
