"""回收站删除后端（阶段 2C）。

设计（S4/S8）：
* 通过 :class:`TrashBackend` 协议注入，单测可用记录型 fake，**不污染真实回收站**；
* 真实实现只调用 ``send2trash``，失败仅报告，**绝不回退为永久删除**；
* 不依赖管理员权限；权限不足/回收站不可用都会以稳定错误码返回。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

try:  # 依赖缺失时降级为"后端不可用"，不阻断程序启动
    from send2trash import send2trash as _send2trash
except Exception:  # pragma: no cover - 依赖缺失分支
    _send2trash = None


@dataclass(frozen=True, slots=True)
class TrashOutcome:
    """回收站操作结果：``result`` ∈ success/failed。"""

    result: str
    error_code: str = ""
    detail: str = ""


class TrashBackend(Protocol):
    def send(self, path: str) -> TrashOutcome:
        """把单个文件移动到回收站（不得实现为永久删除）。"""
        ...


class Send2TrashBackend:
    """真实回收站后端：失败不重试、不回退 ``os.remove``。"""

    def send(self, path: str) -> TrashOutcome:
        if _send2trash is None:
            return TrashOutcome("failed", "backend_unavailable", "send2trash 未安装或不可用")
        try:
            _send2trash(path)
        except Exception as exc:  # noqa: BLE001 - 回收站异常统一降级为失败
            name = type(exc).__name__
            code = "trash_permission_denied" if "TrashPermission" in name else "trash_failed"
            return TrashOutcome("failed", code, f"{name}: {exc}")
        return TrashOutcome("success", detail="已移动到回收站")


@dataclass
class RecordingTrashBackend:
    """测试用记录后端：不产生副作用，可注入失败（不得用于真实执行）。"""

    fail_paths: frozenset[str] = frozenset()
    error_code: str = "trash_failed"
    sent: list[str] = field(default_factory=list)

    def send(self, path: str) -> TrashOutcome:
        self.sent.append(path)
        if path in self.fail_paths:
            return TrashOutcome("failed", self.error_code, "注入的失败")
        return TrashOutcome("success")
