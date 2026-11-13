"""阶段 2C：删除 Temp 文件到回收站（目标构建 / 完整度适配 / 执行器）。

只读扫描 → 用户勾选 → 策略判定（``core.action_policy``）→ 二次确认 → ``ActionJob``
→ :class:`DeleteTempExecutor` 逐项执行（执行前重验路径身份）→ 审计日志。
安全边界：只调用注入的回收站后端；失败仅报告，绝不永久删除。
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from ..core.action_policy import (
    ActionKind,
    ActionPolicy,
    DeleteTarget,
    PolicyDecision,
    PreviewToken,
    build_preview_token,
    evaluate_delete_targets,
    target_signature,
)
from ..core.judgements import CompletenessVerdict, ScanStats, compute_completeness
from ..core.models import Completeness, TempEntry, TempRoot, TempScanResult
from ..core.trash import TrashBackend
from ..core.whitelist import PROTECTED_PATH_MARKERS, is_under, normalize_path
from ..core.winapi import is_reparse_point
from ..jobs.action_job import ActionExecutionResult

SELECTABLE_OCCUPANCY = frozenset({"free", "not_probed"})
"""UI 允许勾选的占用状态；locked/no_access 不可选，未探测可选但确认框会提示。"""

CACHE_ONLY_OCCUPANCY_NOTE = "未探测≠未占用：选中未探测文件时请确认其可删除"


def temp_scan_verdict(result: TempScanResult, *, is_admin: bool) -> CompletenessVerdict:
    """把 Temp 扫描结果适配为完整度判定（limited 将禁止删除，S3）。"""

    budget_truncated = any(warning.code == "temp_budget" for warning in result.warnings)
    stats = ScanStats(
        total_items=result.total_files,
        unreadable_items=result.unreadable,
        permission_limited=(not is_admin and result.completeness is not Completeness.FULL),
        budget_truncated=budget_truncated,
    )
    return compute_completeness(stats)


def entry_selectable(entry: TempEntry) -> bool:
    """UI 默认是否允许勾选该条目（目录/被占用/无权限不可选）。"""

    return (not entry.is_dir) and entry.occupancy.value in SELECTABLE_OCCUPANCY


def delete_targets_from_entries(
    entries: Sequence[TempEntry],
    roots: Sequence[TempRoot],
) -> list[DeleteTarget]:
    """把 UI 勾选的 TempEntry 转成策略层目标快照（不改文件系统）。"""

    allowed_roots = {
        os.path.normcase(os.path.normpath(root.path)) for root in roots if root.exists
    }
    targets: list[DeleteTarget] = []
    for entry in entries:
        root_key = os.path.normcase(os.path.normpath(entry.root))
        targets.append(
            DeleteTarget(
                path=entry.path,
                root=entry.root,
                size=max(0, int(entry.size)),
                is_dir=entry.is_dir,
                occupancy=entry.occupancy.value,
                exists=True,
                inside_declared_root=True,
                root_allowed=root_key in allowed_roots,
                mtime=float(entry.mtime),
            )
        )
    return targets


def build_delete_preview(
    entries: Sequence[TempEntry],
    roots: Sequence[TempRoot],
    *,
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
    now: float,
    token_id: str,
) -> tuple[list[DeleteTarget], PolicyDecision, PreviewToken | None]:
    """构建目标 + 策略判定 + 预览 token（不允许时返回 ``None`` token）。"""

    targets = delete_targets_from_entries(entries, roots)
    decision = evaluate_delete_targets(targets, policy, verdict)
    if not decision.allowed:
        return targets, decision, None
    allowed_targets = [targets[index] for index in decision.allowed_indices]
    signature = target_signature(
        [f"{target.path}|{target.size}|{int(target.mtime)}" for target in allowed_targets]
    )
    token = build_preview_token(
        action=ActionKind.DELETE_TEMP,
        target_signature_value=signature,
        item_count=len(allowed_targets),
        total_bytes=sum(target.size for target in allowed_targets),
        token_id=token_id,
        now=now,
        ttl_s=policy.preview_ttl_s,
    )
    return targets, decision, token


def preview_refusal_text(decision: PolicyDecision) -> str:
    """把策略拒绝列表转成可展示的多行文本。"""

    lines = [f"[{refusal.code}] {refusal.text}" for refusal in decision.refusals]
    if decision.warnings:
        lines.extend(f"提示：{warning}" for warning in decision.warnings)
    return "\n".join(lines) or "策略拒绝执行"


class DeleteTempExecutor:
    """逐项执行：重验路径身份 → 调用回收站后端 → 返回稳定结果码。"""

    def __init__(self, backend: TrashBackend) -> None:
        self._backend = backend

    def __call__(self, target: object) -> ActionExecutionResult:
        if not isinstance(target, DeleteTarget):
            return ActionExecutionResult("failed", "invalid_target", "目标类型不是 DeleteTarget")
        path = target.path
        if not path:
            return ActionExecutionResult("refused", "invalid_path", "路径为空")

        normalized = normalize_path(path)
        root = normalize_path(target.root)
        if not root or not is_under(path, (root,)):
            return ActionExecutionResult("refused", "outside_root", "路径不在声明的扫描根内")
        folded = normalized.casefold()
        if any(marker in folded for marker in PROTECTED_PATH_MARKERS):
            return ActionExecutionResult("refused", "protected_path", "路径命中受保护路径标记")

        try:
            stat_result = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            return ActionExecutionResult("refused", "stale", "文件已不存在（扫描后发生变化）")
        except OSError as exc:
            return ActionExecutionResult("failed", "stat_failed", f"{type(exc).__name__}: {exc}")

        if os.path.isdir(path):
            return ActionExecutionResult("refused", "dir_not_supported", "当前阶段仅支持删除文件")
        reparse = is_reparse_point(path)
        if reparse is True:
            return ActionExecutionResult("refused", "reparse_point", "符号链接/junction 不允许删除")
        if reparse is None:
            return ActionExecutionResult("refused", "unreadable", "无法确认文件属性（权限不足）")
        if int(stat_result.st_size) != target.size:
            return ActionExecutionResult(
                "refused",
                "identity_changed",
                f"文件大小已变化（预览 {target.size}，当前 {stat_result.st_size}），请重新扫描",
            )
        if target.mtime > 0 and int(stat_result.st_mtime) != int(target.mtime):
            return ActionExecutionResult(
                "refused",
                "identity_changed",
                "文件修改时间已变化（扫描后发生变化），请重新扫描",
            )

        outcome = self._backend.send(path)
        if outcome.result == "success":
            return ActionExecutionResult("success", detail=outcome.detail or "已移动到回收站")
        return ActionExecutionResult(
            "failed", outcome.error_code or "trash_failed", outcome.detail or "回收站操作失败"
        )


def summarize_decision(decision: PolicyDecision) -> str:
    """UI 摘要：允许/拒绝数量（供确认框与状态栏使用）。"""

    allowed = len(decision.allowed_indices)
    refused = len(decision.refusals)
    if not decision.allowed:
        return f"拒绝执行：{preview_refusal_text(decision)}"
    return f"可执行 {allowed} 项，拒绝 {refused} 项"
