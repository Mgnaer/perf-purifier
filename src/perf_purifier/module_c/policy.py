"""模块 C 动作策略：清理目标的批量闸门与逐项判定。

与 ``core.action_policy`` 的分工：
* ``core.action_policy`` 提供 :class:`ActionKind` / :class:`ActionPolicy` / 批量闸门等通用原语；
* 本模块定义磁盘清理专用的目标快照 :class:`SlimTarget` 与
  :func:`evaluate_slim_targets`（允许删除目录、需要管理员、专用通道白名单）。

安全不变量：
* 没有扫描结果（``verdict`` 为 ``None``）不允许动作；
* ``limited`` 完整度禁止一切批量动作；
* 执行层总开关 / 分动作开关默认关闭；
* 单次批量上限（默认 500 项 / 10 GiB）；
* 越界 / 受保护 / 用户数据 / 重解析点一律拒绝（逐项，不静默跳过）。
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from ..core.action_policy import (
    ActionKind,
    ActionPolicy,
    ActionRefusal,
    PolicyDecision,
    PreviewToken,
    build_preview_token,
    evaluate_batch_gate,
    target_signature,
)
from ..core.judgements import CompletenessVerdict
from .models import JunkItem
from .safety import find_forbidden, is_drive_root, is_under, known_user_data_roots

ALLOWED_SPECIAL_KINDS: frozenset[str] = frozenset({"recycle_bin", "defender_platforms"})
"""允许出现在批量清理中的专用通道（其余一律拒绝）。"""


@dataclass(frozen=True, slots=True)
class SlimTarget:
    """清理目标快照（来自扫描结果，执行前需重验身份）。"""

    path: str
    rule_id: str
    size: int
    kind: str
    allowed_root: str
    exists: bool = True
    inside_declared_root: bool = True
    root_allowed: bool = True
    is_reparse: bool = False
    special: str = ""
    requires_admin: bool = False


def _root_allowed(root: str, *, special: str) -> bool:
    """规则根是否可信：专用通道先放行，其余非卷根/非用户数据/非受保护序列。"""

    if not root:
        return False
    if special in ALLOWED_SPECIAL_KINDS:
        return True
    if is_drive_root(root):
        return False
    if is_under(root, known_user_data_roots()):
        return False
    return find_forbidden(root) is None


def slim_targets_from_items(items: Sequence[JunkItem]) -> list[SlimTarget]:
    """把扫描结果转成策略层目标快照（不做任何 I/O）。"""

    targets: list[SlimTarget] = []
    for item in items:
        targets.append(
            SlimTarget(
                path=item.path,
                rule_id=item.rule_id,
                size=item.size_bytes,
                kind=item.kind,
                allowed_root=item.allowed_root,
                exists=True,
                inside_declared_root=bool(item.allowed_root),
                root_allowed=_root_allowed(item.allowed_root, special=item.special),
                is_reparse=False,
                special=item.special,
                requires_admin=item.requires_admin,
            )
        )
    return targets


def evaluate_slim_targets(
    targets: Sequence[SlimTarget],
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
    *,
    is_admin: bool = False,
) -> PolicyDecision:
    """磁盘清理的逐项判定（目录可删、系统级需管理员、专用通道白名单）。"""

    total_bytes = sum(max(0, target.size) for target in targets)
    batch = evaluate_batch_gate(
        ActionKind.CLEAN_SPACE, policy, verdict, len(targets), total_bytes
    )
    if not batch.allowed:
        return batch

    allowed: list[int] = []
    refusals: list[ActionRefusal] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for index, target in enumerate(targets):
        key = target.path.casefold() if target.path else ""
        reason: ActionRefusal | None = None
        if not target.path or not key:
            reason = ActionRefusal("invalid_path", "路径为空", index)
        elif key in seen:
            reason = ActionRefusal("duplicate_target", "同一路径重复出现", index)
        elif not target.exists:
            reason = ActionRefusal("stale", "目标已不存在（扫描后发生变化）", index)
        elif not target.root_allowed:
            reason = ActionRefusal("root_not_allowed", "扫描根不在允许的目录列表中", index)
        elif not target.inside_declared_root:
            reason = ActionRefusal("outside_root", "路径不在声明的扫描根内（疑似越界）", index)
        elif not target.allowed_root or not is_under(target.path, (target.allowed_root,)):
            reason = ActionRefusal("outside_root", "路径不在规则声明的根目录内", index)
        elif target.is_reparse:
            reason = ActionRefusal("reparse_point", "符号链接/junction 不允许删除", index)
        elif target.special and target.special not in ALLOWED_SPECIAL_KINDS:
            reason = ActionRefusal("unknown_special", f"未知的专用通道：{target.special}", index)
        elif target.requires_admin and not is_admin:
            reason = ActionRefusal("admin_required", "该规则需要管理员权限", index)
        elif find_forbidden(target.path) is not None and not target.special:
            reason = ActionRefusal("protected_path", "目标命中受保护路径", index)
        elif not target.special and is_under(target.path, known_user_data_roots()):
            reason = ActionRefusal("user_data", "目标位于用户数据目录，永不删除", index)
        if reason is not None:
            refusals.append(reason)
            continue
        seen.add(key)
        allowed.append(index)
        if target.special == "recycle_bin":
            warnings.append("将清空整个回收站（含此前删除的其他文件）")
        if target.kind == "dir":
            warnings.append(f"目录将连同内容一起删除：{target.path}")
    return PolicyDecision(bool(allowed), tuple(allowed), tuple(refusals), tuple(warnings))


def build_slim_preview(
    items: Sequence[JunkItem],
    *,
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
    is_admin: bool,
    now: float,
    token_id: str | None = None,
) -> tuple[list[SlimTarget], PolicyDecision, PreviewToken | None]:
    """构建目标 + 策略判定 + 预览 token（不允许时返回 ``None``）。"""

    targets = slim_targets_from_items(items)
    decision = evaluate_slim_targets(targets, policy, verdict, is_admin=is_admin)
    if not decision.allowed:
        return targets, decision, None
    allowed_targets = [targets[index] for index in decision.allowed_indices]
    signature = target_signature(
        [f"{target.path}|{target.size}|{target.rule_id}" for target in allowed_targets]
    )
    token = build_preview_token(
        action=ActionKind.CLEAN_SPACE,
        target_signature_value=signature,
        item_count=len(allowed_targets),
        total_bytes=sum(target.size for target in allowed_targets),
        token_id=token_id or uuid.uuid4().hex,
        now=now,
        ttl_s=policy.preview_ttl_s,
    )
    return targets, decision, token


def refusal_text(decision: PolicyDecision) -> str:
    """把策略拒绝/警告转成可展示的多行文本。"""

    lines = [f"[{refusal.code}] {refusal.text}" for refusal in decision.refusals]
    if decision.warnings:
        lines.extend(f"提示：{warning}" for warning in decision.warnings)
    return "\n".join(lines) or "策略拒绝执行"


__all__ = [
    "ALLOWED_SPECIAL_KINDS",
    "SlimTarget",
    "build_slim_preview",
    "evaluate_slim_targets",
    "refusal_text",
    "slim_targets_from_items",
]
