"""阶段 3A：动作预演（dry-run）通用逻辑。

设计（docs/05 S3-4/S3-5）：
* 预演只注入 :class:`DryRunExecutor`，**不接触回收站/文件/进程**；
* 审计正常写入，但 header 中 ``dry_run=true``；
* 首次预演完成后写入 config 标记并持久化（``config_path`` 为 None 时用默认配置路径）；
* 预演为同步执行（每个目标只有内存操作，无磁盘/进程 I/O，不会卡住 UI）。
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path

from PySide6.QtWidgets import QMessageBox, QWidget

from ..core.action_policy import ActionKind, PreviewToken, action_label
from ..core.audit import ActionAuditWriter, rotate_audit_log
from ..core.config import AppConfig
from ..core.first_run import is_preview_required, mark_preview_done
from ..core.judgements import CompletenessVerdict
from ..jobs.action_job import ActionJob, ActionSessionResult, DryRunExecutor

logger = logging.getLogger(__name__)


def ensure_first_preview(parent: QWidget, kind: ActionKind, config: AppConfig) -> bool:
    """真实执行前的首次预演闸门；返回 False 表示应中止真实执行。"""

    if not is_preview_required(kind, config):
        return True
    QMessageBox.information(
        parent,
        "首次使用请先预演",
        f"这是首次使用「{action_label(kind)}」。\n\n"
        "请先点击「预演选中项（不执行）」完成一次预演：预演只做策略校验并列出"
        "将会处理的目标，**不会修改任何文件、也不会结束任何进程**。\n\n"
        "预演完成后即可再次点击执行（真实执行仍需二次确认）。",
    )
    return False


def run_preview_job(
    *,
    kind: ActionKind,
    token: PreviewToken,
    targets: Sequence[object],
    allowed_indices: Sequence[int],
    verdict: CompletenessVerdict | None,
    is_admin: bool,
    app_version: str,
    audit_directory: Path,
    config: AppConfig | None = None,
    config_path: Path | None = None,
) -> tuple[ActionSessionResult | None, str]:
    """同步执行一次 dry-run；返回 (会话结果, 错误消息)。"""

    job = ActionJob(
        action=kind,
        token=token,
        targets=targets,
        allowed_indices=allowed_indices,
        executor=DryRunExecutor(),
        audit=ActionAuditWriter(audit_directory),
        verdict=verdict,
        is_admin=is_admin,
        app_version=app_version,
        dry_run=True,
    )
    finished: list[ActionSessionResult] = []
    failures: list[str] = []
    job.finished.connect(finished.append)
    job.failed.connect(failures.append)
    job.run()
    rotate_audit_log(audit_directory)

    if failures:
        return None, failures[0]
    if not finished:
        return None, "预演未产生结果"
    session = finished[0]
    if config is not None and mark_preview_done(config, kind):
        saved, message = config.save(config_path)
        if not saved:
            logger.warning("预演标记保存失败：%s", message)
    return session, ""


def preview_result_text(session: ActionSessionResult, kind: ActionKind) -> str:
    """预演结果摘要（供 QMessageBox 使用）。"""

    lines = [
        f"预演结果：动作「{action_label(kind)}」，共 {len(session.results)} 项。",
        "本次预演未执行任何真实动作（文件/进程/回收站均未改变）。",
        "",
    ]
    for item in session.results[:50]:
        detail = f"（{item.error_code}）" if item.error_code else ""
        lines.append(f"{item.result}: {item.target}{detail}")
    if len(session.results) > 50:
        lines.append(f"... 其余 {len(session.results) - 50} 项略")
    lines.append("")
    lines.append("如需真实执行：开启对应动作开关后再次点击执行按钮（需二次确认）。")
    return "\n".join(lines)
