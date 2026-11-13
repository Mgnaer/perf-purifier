"""阶段 2 动作执行任务（2A 框架）。

职责（对应 docs/04）：
1. 执行前校验预览 token（动作一致/策略版本/未过期/非空）；
2. **先写审计 header，再执行**；审计写失败立即中止（不允许静默执行）；
3. 逐项调用注入的 executor（2A 只提供 :class:`DryRunExecutor`，无任何副作用）；
4. 逐项写审计 item；失败不中断其它项；进度/取消走 ScanJob 契约。

真实动作（回收站删除/硬链接/结束进程）在后续里程碑以 executor 形式接入，
本框架不直接调用 send2trash / os.link / psutil.terminate。
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from PySide6.QtCore import QObject

from ..core.action_policy import (
    POLICY_VERSION,
    ActionKind,
    PreviewToken,
    action_label,
    validate_preview_token,
)
from ..core.action_result import ActionExecutionResult
from ..core.audit import (
    ActionAuditWriter,
    AuditEnd,
    AuditHeader,
    AuditItem,
    format_audit_timestamp,
)
from ..core.cancel import CancelToken
from ..core.judgements import CompletenessVerdict
from .base_job import ScanJob


class DryRunExecutor:
    """2A 占位执行器：只记录、不做任何真实动作。"""

    def __call__(self, target: object) -> ActionExecutionResult:
        return ActionExecutionResult("dry_run", detail="2A 框架：未执行任何真实动作")


@dataclass(frozen=True, slots=True)
class ActionItemResult:
    index: int
    target: str
    identity: str
    result: str
    error_code: str = ""
    detail: str = ""
    duration_ms: int = 0


@dataclass(slots=True)
class ActionSessionResult:
    action: ActionKind
    session_id: str
    dry_run: bool
    results: list[ActionItemResult] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def duration_ms(self) -> int:
        return max(0, int((self.finished_at - self.started_at) * 1000))

    @property
    def success_count(self) -> int:
        return sum(1 for item in self.results if item.result in ("success", "dry_run"))

    @property
    def failed_count(self) -> int:
        return sum(1 for item in self.results if item.result == "failed")


def new_session_id() -> str:
    return uuid.uuid4().hex


def target_label(target: object) -> str:
    path = getattr(target, "path", None)
    if isinstance(path, str) and path:
        return path
    pid = getattr(target, "pid", None)
    if pid is not None:
        return f"PID {pid}"
    canonical = getattr(target, "canonical", None)
    redundant = getattr(target, "redundant", None)
    if canonical is not None and redundant is not None:
        return f"{getattr(redundant, 'path', '?')} ← {getattr(canonical, 'path', '?')}"
    return repr(target)


def target_identity(target: object) -> str:
    """把目标身份快照压成审计可读字符串（执行前重验的依据）。"""

    path = getattr(target, "path", None)
    if isinstance(path, str) and path:
        parts = [f"path={path}"]
        for name in ("size", "dev", "ino", "mtime", "occupancy", "is_reparse"):
            value = getattr(target, name, None)
            if value is not None:
                parts.append(f"{name}={value}")
        return ";".join(parts)
    pid = getattr(target, "pid", None)
    if pid is not None:
        return (
            f"pid={pid};create_time={getattr(target, 'create_time', 0)};"
            f"exe={getattr(target, 'exe', None)}"
        )
    canonical = getattr(target, "canonical", None)
    redundant = getattr(target, "redundant", None)
    if canonical is not None and redundant is not None:
        return (
            f"canonical={getattr(canonical, 'path', '?')}({getattr(canonical, 'st_dev', '?')},"
            f"{getattr(canonical, 'st_ino', '?')});"
            f"redundant={getattr(redundant, 'path', '?')}({getattr(redundant, 'st_dev', '?')},"
            f"{getattr(redundant, 'st_ino', '?')})"
        )
    return "unknown"


def target_total_bytes(target: object) -> int:
    for name in ("size", "total_bytes"):
        value = getattr(target, name, None)
        if isinstance(value, int) and value > 0:
            return value
    redundant = getattr(target, "redundant", None)
    size = getattr(redundant, "size", None)
    if isinstance(size, int) and size > 0:
        return size
    return 0


class ActionJob(ScanJob):
    """一次性动作执行任务（2A 只跑 DryRun；真实 executor 由后续里程碑注入）。"""

    def __init__(
        self,
        *,
        action: ActionKind,
        token: PreviewToken,
        targets: Sequence[object],
        allowed_indices: Sequence[int],
        executor: Callable[[object], ActionExecutionResult],
        audit: ActionAuditWriter | None,
        verdict: CompletenessVerdict | None,
        is_admin: bool,
        app_version: str,
        session_id: str | None = None,
        dry_run: bool = True,
        clock: Callable[[], float] = time.time,
        parent: QObject | None = None,
        cancel_token: CancelToken | None = None,
    ) -> None:
        super().__init__(cancel_token, parent)
        self._action = action
        self._token = token
        self._targets = list(targets)
        self._allowed_indices = list(allowed_indices)
        self._executor = executor
        self._audit = audit
        self._verdict = verdict
        self._is_admin = is_admin
        self._app_version = app_version
        self._session_id = session_id or new_session_id()
        self._dry_run = dry_run
        self._clock = clock

    @property
    def session_id(self) -> str:
        return self._session_id

    def _run(self) -> None:
        started_at = self._clock()
        valid, reason = validate_preview_token(
            self._token, action=self._action, now=started_at, policy_version=POLICY_VERSION
        )
        if not valid:
            raise RuntimeError(f"预览校验失败：{reason}")

        targets = [
            self._targets[index]
            for index in self._allowed_indices
            if 0 <= index < len(self._targets)
        ]
        if not targets:
            raise RuntimeError("没有可执行的目标")

        if self._audit is not None:
            header = AuditHeader(
                ts=format_audit_timestamp(started_at),
                session_id=self._session_id,
                token_id=self._token.token_id,
                action=self._action.value,
                policy_version=POLICY_VERSION,
                verdict_level=self._verdict.level if self._verdict else "unknown",
                verdict_codes=tuple(r.code for r in self._verdict.reasons) if self._verdict else (),
                is_admin=self._is_admin,
                item_count=len(targets),
                total_bytes=sum(target_total_bytes(target) for target in targets),
                app_version=self._app_version,
                dry_run=self._dry_run,
            )
            try:
                self._audit.write_header(header)
            except Exception as exc:  # noqa: BLE001 - 审计失败必须中止
                raise RuntimeError(f"审计日志写入失败，已中止执行：{exc}") from exc

        results: list[ActionItemResult] = []
        total = len(targets)
        for position, target in enumerate(targets):
            self.token.raise_if_cancelled("动作执行")
            label = target_label(target)
            identity = target_identity(target)
            item_started = self._clock()
            try:
                outcome = self._executor(target)
            except Exception as exc:  # noqa: BLE001 - 单项异常不中断整体
                outcome = ActionExecutionResult(
                    "failed", "executor_exception", f"{type(exc).__name__}: {exc}"
                )
            duration_ms = max(0, int((self._clock() - item_started) * 1000))
            item = ActionItemResult(
                index=self._allowed_indices[position],
                target=label,
                identity=identity,
                result=outcome.result,
                error_code=outcome.error_code,
                detail=outcome.detail,
                duration_ms=duration_ms,
            )
            results.append(item)
            if self._audit is not None:
                try:
                    self._audit.write_item(
                        AuditItem(
                            ts=format_audit_timestamp(self._clock()),
                            session_id=self._session_id,
                            action=self._action.value,
                            target=label,
                            identity=identity,
                            result=outcome.result,
                            error_code=outcome.error_code,
                            detail=outcome.detail,
                            duration_ms=duration_ms,
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - 审计失败中止后续
                    raise RuntimeError(f"审计日志写入失败，已中止剩余动作：{exc}") from exc
            self._progress(
                (position + 1) / total * 100,
                f"{action_label(self._action)} {position + 1}/{total}：{outcome.result}",
            )

        finished_at = self._clock()
        if self._audit is not None:
            success = sum(1 for item in results if item.result == "success")
            failed = sum(1 for item in results if item.result == "failed")
            try:
                self._audit.write_end(
                    AuditEnd(
                        ts=format_audit_timestamp(finished_at),
                        session_id=self._session_id,
                        action=self._action.value,
                        status="completed",
                        success=success,
                        failed=failed,
                        total=len(results),
                    )
                )
            except Exception as exc:  # noqa: BLE001 - 审计失败中止上报
                raise RuntimeError(f"审计日志写入失败（结束记录）：{exc}") from exc
        self._progress(100, "完成", force=True)
        self.finished.emit(
            ActionSessionResult(
                action=self._action,
                session_id=self._session_id,
                dry_run=self._dry_run,
                results=results,
                started_at=started_at,
                finished_at=finished_at,
            )
        )


def run_dry_action(
    *,
    action: ActionKind,
    token: PreviewToken,
    targets: Sequence[object],
    allowed_indices: Sequence[int],
    audit: ActionAuditWriter | None,
    verdict: CompletenessVerdict | None,
    is_admin: bool,
    app_version: str,
) -> ActionJob:
    """构造一个只做 dry-run 的 ActionJob（2A 阶段唯一入口，无副作用）。"""

    return ActionJob(
        action=action,
        token=token,
        targets=targets,
        allowed_indices=allowed_indices,
        executor=DryRunExecutor(),
        audit=audit,
        verdict=verdict,
        is_admin=is_admin,
        app_version=app_version,
        dry_run=True,
    )
