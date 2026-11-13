"""模块 C 清理执行器（实现 ``jobs.action_job`` 的 executor 协议）。

安全契约（与模块 A 的 ``DeleteTempExecutor`` 一致）：
* 只调用注入的回收站后端（``send2trash``），失败仅报告，**绝不**回退永久删除；
* 每项执行前重新调用 :func:`module_c.safety.check_deletable` 做身份重验；
* 系统级规则需要管理员权限，非管理员一律 ``refused``；
* 专用通道（回收站清空 / Defender 旧平台）走各自专用逻辑，不做通用路径删除。
"""

from __future__ import annotations

import os

from ..core.action_result import ActionExecutionResult
from ..core.trash import TrashBackend
from . import safety
from .models import JunkItem


def _outcome_code(code: str, detail: str) -> ActionExecutionResult:
    return ActionExecutionResult("refused", code, detail)


class SlimDeleteExecutor:
    """把 :class:`~perf_purifier.module_c.models.JunkItem` 移到回收站。"""

    def __init__(
        self,
        backend: TrashBackend,
        *,
        is_admin: bool = False,
        drive: str | None = None,
    ) -> None:
        self._backend = backend
        self._is_admin = is_admin
        self._drive = drive or os.environ.get("SystemDrive", "C:") + "\\"

    def __call__(self, target: object) -> ActionExecutionResult:
        if not isinstance(target, JunkItem):
            return _outcome_code("invalid_target", "目标类型不是 JunkItem")
        if target.is_special:
            return self._execute_special(target)

        if target.requires_admin and not self._is_admin:
            return _outcome_code("admin_required", "该规则需要管理员权限，当前为普通用户")
        if not target.path:
            return _outcome_code("invalid_path", "路径为空")

        check = safety.check_deletable(
            target.path,
            target.allowed_root,
            expected_size=target.size if target.kind == "file" else None,
            expected_mtime=target.mtime if target.kind == "file" else None,
        )
        if not check.ok:
            return _outcome_code(check.code, check.detail)

        try:
            outcome = self._backend.send(target.path)
        except Exception as exc:  # noqa: BLE001 - 回收站异常统一降级为失败
            return ActionExecutionResult("failed", "trash_exception", f"{type(exc).__name__}: {exc}")
        if outcome.result == "success":
            return ActionExecutionResult("success", detail=outcome.detail or "已移动到回收站")
        return ActionExecutionResult(
            "failed", outcome.error_code or "trash_failed", outcome.detail or "回收站操作失败"
        )

    # ------------------------------------------------------------------ 专用通道
    def _execute_special(self, target: JunkItem) -> ActionExecutionResult:
        if target.special == "recycle_bin":
            ok, message = safety.empty_recycle_bin(self._drive)
            if ok:
                return ActionExecutionResult("success", detail=message)
            return ActionExecutionResult("failed", "empty_trash_failed", message)
        if target.special == "defender_platforms":
            if not self._is_admin:
                return _outcome_code("admin_required", "Defender 旧平台清理需要管理员权限")
            if not safety.is_defender_platform_old_version(target.path):
                return _outcome_code("identity_changed", "已不是可清理的 Defender 旧平台版本")
            try:
                outcome = self._backend.send(target.path)
            except Exception as exc:  # noqa: BLE001
                return ActionExecutionResult(
                    "failed", "trash_exception", f"{type(exc).__name__}: {exc}"
                )
            if outcome.result == "success":
                return ActionExecutionResult("success", detail=outcome.detail or "已移动到回收站")
            return ActionExecutionResult(
                "failed", outcome.error_code or "trash_failed", outcome.detail or "回收站操作失败"
            )
        return _outcome_code("unknown_special", "未知的专用通道类型")


__all__ = ["SlimDeleteExecutor"]
