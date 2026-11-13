"""阶段 2 动作安全策略（纯函数层：无 I/O、无时间依赖，时间/ID 由调用方注入）。

设计依据：docs/04-阶段2动作安全设计.md。
本模块只回答"该动作/该目标是否允许"，不执行任何动作；真实执行在 ``jobs/action_job.py``。

安全不变量：
* 没有扫描结果（CompletenessVerdict）不允许动作；
* ``limited`` 完整度禁止一切动作（S3）；
* 主开关/分动作开关默认关闭，必须显式开启（S2）；
* 批量上限（2C 200 项/5GB、2D 100、2B 20，S6）；
* 系统关键进程、自身/祖先、已变化身份一律拒绝（逐项，不静默跳过）。
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .judgements import (
    CompletenessVerdict,
    FileMeta,
    is_fully_hardlinked,
    is_mutual_hardlink,
)

POLICY_VERSION = "2a.1"
""""策略版本：预览 token 绑定该版本，策略变更后旧 token 自动失效。"""

DEFAULT_PREVIEW_TTL_S = 120.0

DELETABLE_OCCUPANCY_ALLOWED = frozenset({"free"})
"""允许删除的占用状态；locked/no_access 默认拒绝，not_probed 给警告但不阻断。"""


class ActionKind(str, Enum):
    DELETE_TEMP = "delete_temp"
    HARDLINK_DEDUPE = "hardlink_dedupe"
    KILL_PROCESS = "kill_process"
    HARDLINK_DETACH = "hardlink_detach"
    CLEAN_SPACE = "clean_space"


_ACTION_LABELS: dict[ActionKind, str] = {
    ActionKind.DELETE_TEMP: "删除到回收站（Temp 文件）",
    ActionKind.HARDLINK_DEDUPE: "硬链接去重",
    ActionKind.KILL_PROCESS: "结束进程",
    ActionKind.HARDLINK_DETACH: "硬链接独立化",
    ActionKind.CLEAN_SPACE: "清理磁盘垃圾（移到回收站）",
}


def action_label(kind: ActionKind) -> str:
    return _ACTION_LABELS.get(kind, kind.value)


@dataclass(frozen=True, slots=True)
class ActionPolicy:
    """阶段 2 开关与批量上限（由 AppConfig 构造，测试可直接构造）。"""

    stage2_enabled: bool = False
    allow_delete_temp: bool = False
    allow_hardlink_dedupe: bool = False
    allow_kill_process: bool = False
    allow_hardlink_detach: bool = False
    allow_hardlink_detach: bool = False
    allow_clean_space: bool = False
    preview_ttl_s: float = DEFAULT_PREVIEW_TTL_S
    max_delete_items: int = 200
    max_delete_bytes: int = 5 * 1024**3
    max_hardlink_items: int = 100
    max_kill_items: int = 20
    max_detach_items: int = 20
    max_detach_items: int = 20
    max_clean_items: int = 500
    max_clean_bytes: int = 10 * 1024**3

    @classmethod
    def from_config(cls, config: object) -> ActionPolicy:
        """从 AppConfig（duck typing）构造，避免纯函数层依赖配置模块。"""

        def value(name: str, default: Any) -> Any:
            return getattr(config, name, default)

        return cls(
            stage2_enabled=bool(value("stage2_enabled", False)),
            allow_delete_temp=bool(value("allow_delete_temp", False)),
            allow_hardlink_dedupe=bool(value("allow_hardlink_dedupe", False)),
            allow_kill_process=bool(value("allow_kill_process", False)),
            allow_hardlink_detach=bool(value("allow_hardlink_detach", False)),
            allow_clean_space=bool(value("allow_clean_space", False)),
            preview_ttl_s=float(value("action_preview_ttl_s", DEFAULT_PREVIEW_TTL_S)),
            max_delete_items=max(0, int(value("action_max_delete_items", 200))),
            max_delete_bytes=max(0, int(value("action_max_delete_bytes", 5 * 1024**3))),
            max_hardlink_items=max(0, int(value("action_max_hardlink_items", 100))),
            max_kill_items=max(0, int(value("action_max_kill_items", 20))),
            max_detach_items=max(0, int(value("action_max_detach_items", 20))),
            max_clean_items=max(0, int(value("action_max_clean_items", 500))),
            max_clean_bytes=max(0, int(value("action_max_clean_bytes", 10 * 1024**3))),
        )

    def action_enabled(self, kind: ActionKind) -> bool:
        if not self.stage2_enabled:
            return False
        return {
            ActionKind.DELETE_TEMP: self.allow_delete_temp,
            ActionKind.HARDLINK_DEDUPE: self.allow_hardlink_dedupe,
            ActionKind.KILL_PROCESS: self.allow_kill_process,
            ActionKind.HARDLINK_DETACH: self.allow_hardlink_detach,
            ActionKind.HARDLINK_DETACH: self.allow_hardlink_detach,
            ActionKind.CLEAN_SPACE: self.allow_clean_space,
        }.get(kind, False)

    def max_items(self, kind: ActionKind) -> int:
        return {
            ActionKind.DELETE_TEMP: self.max_delete_items,
            ActionKind.HARDLINK_DEDUPE: self.max_hardlink_items,
            ActionKind.KILL_PROCESS: self.max_kill_items,
            ActionKind.HARDLINK_DETACH: self.max_detach_items,
            ActionKind.HARDLINK_DETACH: self.max_detach_items,
            ActionKind.CLEAN_SPACE: self.max_clean_items,
        }.get(kind, 0)


@dataclass(frozen=True, slots=True)
class ActionRefusal:
    """一条拒绝原因；``target_index`` 为 None 表示整批级拒绝。"""

    code: str
    text: str
    target_index: int | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """动作策略判定结果：允许部分仅含 ``allowed_indices`` 指向的目标。"""

    allowed: bool
    allowed_indices: tuple[int, ...] = ()
    refusals: tuple[ActionRefusal, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PreviewToken:
    """预览凭证（只在内存中，一次性使用；不落盘防篡改）。"""

    token_id: str
    action: ActionKind
    created_at: float
    expires_at: float
    policy_version: str
    item_count: int
    total_bytes: int
    target_signature: str


def target_signature(parts: Sequence[str]) -> str:
    """把目标身份快照压成稳定摘要（用于预览 token 绑定与一致性校验）。"""

    joined = "\n".join(sorted(str(part) for part in parts))
    return hashlib.sha256(joined.encode("utf-8", errors="surrogatepass")).hexdigest()[:32]


def build_preview_token(
    *,
    action: ActionKind,
    target_signature_value: str,
    item_count: int,
    total_bytes: int,
    token_id: str,
    now: float,
    ttl_s: float = DEFAULT_PREVIEW_TTL_S,
    policy_version: str = POLICY_VERSION,
) -> PreviewToken:
    """构造预览 token（``token_id``/``now`` 由调用方注入，保证可测试）。"""

    ttl = ttl_s if ttl_s > 0 else DEFAULT_PREVIEW_TTL_S
    return PreviewToken(
        token_id=token_id,
        action=action,
        created_at=now,
        expires_at=now + ttl,
        policy_version=policy_version,
        item_count=max(0, int(item_count)),
        total_bytes=max(0, int(total_bytes)),
        target_signature=target_signature_value,
    )


def validate_preview_token(
    token: PreviewToken,
    *,
    action: ActionKind,
    now: float,
    policy_version: str = POLICY_VERSION,
) -> tuple[bool, str]:
    """校验 token 是否可用于执行：动作一致、策略版本一致、未过期、目标非空。"""

    if token.action is not action:
        return False, "预览凭证的动作类型与当前动作不一致"
    if token.policy_version != policy_version:
        return False, "策略版本已变化，请重新预览"
    if now > token.expires_at:
        return False, "预览已过期，请重新预览"
    if token.item_count <= 0:
        return False, "预览目标为空"
    if token.total_bytes < 0:
        return False, "预览数据异常"
    return True, ""


# ---------------------------------------------------------------------------
# 目标快照
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DeleteTarget:
    """2C 删除目标快照（来自 TempScanResult，执行前需重验身份）。"""

    path: str
    root: str
    size: int
    is_dir: bool = False
    occupancy: str = "not_probed"
    is_reparse: bool = False
    exists: bool = True
    inside_declared_root: bool = True
    root_allowed: bool = True
    mtime: float = 0.0


@dataclass(frozen=True, slots=True)
class KillTarget:
    """2B 结束进程目标快照（来自进程快照，执行前需重验 pid+create_time+exe）。"""

    pid: int
    name: str
    create_time: float
    exe: str | None = None
    is_protected_pid: bool = False
    never_terminate: bool = False
    is_self_or_ancestor: bool = False
    identity_matches_snapshot: bool = True
    needs_review_network: bool = False
    needs_review_reason: str = ""


@dataclass(frozen=True, slots=True)
class HardlinkTarget:
    """2D 硬链接去重目标：把 ``redundant`` 替换为指向 ``canonical`` 的硬链接。"""

    canonical: FileMeta
    redundant: FileMeta
    group: tuple[FileMeta, ...]
    content_sha256: str
    same_volume: bool = True
    ntfs: bool = True
    rehash_matches: bool = True
    paths_exist: bool = True


# ---------------------------------------------------------------------------
# 批量闸门
# ---------------------------------------------------------------------------
def _batch_gate(
    kind: ActionKind,
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
    item_count: int,
    total_bytes: int,
) -> tuple[bool, list[ActionRefusal]]:
    refusals: list[ActionRefusal] = []
    if verdict is None:
        refusals.append(ActionRefusal("no_scan_result", "没有可用的扫描结果，请先完成扫描"))
        return False, refusals
    if verdict.level == "limited":
        codes = ",".join(reason.code for reason in verdict.reasons) or "unknown"
        refusals.append(
            ActionRefusal(
                "completeness_limited",
                f"扫描数据完整度为 limited（{codes}），已禁止批量动作；请重新扫描后再试",
            )
        )
        return False, refusals
    if not policy.stage2_enabled:
        refusals.append(ActionRefusal("stage2_disabled", "执行层总开关未开启"))
    if not policy.action_enabled(kind):
        refusals.append(ActionRefusal("action_disabled", f"动作「{action_label(kind)}」未开启"))
    if item_count <= 0:
        refusals.append(ActionRefusal("empty_selection", "未选择任何目标"))
    max_items = policy.max_items(kind)
    if max_items > 0 and item_count > max_items:
        refusals.append(
            ActionRefusal("batch_too_large", f"单次最多 {max_items} 项（当前 {item_count} 项）")
        )
    if kind is ActionKind.DELETE_TEMP and policy.max_delete_bytes > 0 and total_bytes > policy.max_delete_bytes:
        refusals.append(
            ActionRefusal(
                "batch_bytes_too_large",
                f"单次删除上限 {policy.max_delete_bytes} 字节（当前 {total_bytes} 字节）",
            )
        )
    if kind is ActionKind.CLEAN_SPACE and policy.max_clean_bytes > 0 and total_bytes > policy.max_clean_bytes:
        refusals.append(
            ActionRefusal(
                "batch_bytes_too_large",
                f"单次清理上限 {policy.max_clean_bytes} 字节（当前 {total_bytes} 字节）",
            )
        )
    return not refusals, refusals


def evaluate_batch_gate(
    kind: ActionKind,
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
    item_count: int,
    total_bytes: int = 0,
) -> PolicyDecision:
    """批次级闸门（对外公开版本，供模块 C 的专用判定复用）。

    返回 ``allowed=True`` 表示批次通过，逐项目标判定由调用方继续执行。
    """

    ok, refusals = _batch_gate(kind, policy, verdict, item_count, total_bytes)
    return PolicyDecision(ok, () if not ok else tuple(range(max(0, item_count))), tuple(refusals))


def _dedupe_key(path: str) -> str:
    return os.path.normcase(os.path.normpath(path)) if path else ""


# ---------------------------------------------------------------------------
# 各动作的逐项判定
# ---------------------------------------------------------------------------
def evaluate_delete_targets(
    targets: Sequence[DeleteTarget],
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
) -> PolicyDecision:
    """2C：删除到回收站的逐项判定（目录、越界、reparse、被占用默认拒绝）。"""

    total_bytes = sum(max(0, target.size) for target in targets)
    batch_ok, batch_refusals = _batch_gate(
        ActionKind.DELETE_TEMP, policy, verdict, len(targets), total_bytes
    )
    if not batch_ok:
        return PolicyDecision(False, refusals=tuple(batch_refusals))

    allowed: list[int] = []
    refusals: list[ActionRefusal] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for index, target in enumerate(targets):
        reason: ActionRefusal | None = None
        key = _dedupe_key(target.path)
        if not target.path or not key:
            reason = ActionRefusal("invalid_path", "路径为空", index)
        elif key in seen:
            reason = ActionRefusal("duplicate_target", "同一路径重复出现", index)
        elif not target.exists:
            reason = ActionRefusal("stale", "文件已不存在（扫描后发生变化）", index)
        elif target.is_dir:
            reason = ActionRefusal("dir_not_supported", "当前阶段仅支持删除文件，不支持目录", index)
        elif not target.root_allowed:
            reason = ActionRefusal("root_not_allowed", "扫描根不在允许的临时目录列表中", index)
        elif not target.inside_declared_root:
            reason = ActionRefusal("outside_root", "路径不在声明的扫描根内（疑似越界）", index)
        elif target.is_reparse:
            reason = ActionRefusal("reparse_point", "符号链接/junction 不允许删除", index)
        elif target.occupancy == "locked":
            reason = ActionRefusal("in_use", "文件可能被占用，默认不允许删除", index)
        elif target.occupancy == "no_access":
            reason = ActionRefusal("no_access", "无访问权限，默认不允许删除", index)
        elif target.occupancy not in DELETABLE_OCCUPANCY_ALLOWED:
            warnings.append(f"第 {index + 1} 项未被占用探测覆盖（未探测≠未占用）")
        if reason is not None:
            refusals.append(reason)
            continue
        seen.add(key)
        allowed.append(index)
    return PolicyDecision(bool(allowed), tuple(allowed), tuple(refusals), tuple(warnings))


def evaluate_kill_targets(
    targets: Sequence[KillTarget],
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
) -> PolicyDecision:
    """2B：结束进程的逐项判定（系统关键/自身祖先/身份变化默认拒绝）。"""

    batch_ok, batch_refusals = _batch_gate(
        ActionKind.KILL_PROCESS, policy, verdict, len(targets), 0
    )
    if not batch_ok:
        return PolicyDecision(False, refusals=tuple(batch_refusals))

    allowed: list[int] = []
    refusals: list[ActionRefusal] = []
    warnings: list[str] = []
    seen: set[int] = set()
    for index, target in enumerate(targets):
        reason: ActionRefusal | None = None
        if target.pid <= 0 or target.is_protected_pid:
            reason = ActionRefusal("protected_pid", "PID 0/4 等系统进程禁止结束", index)
        elif target.pid in seen:
            reason = ActionRefusal("duplicate_target", "同一 PID 重复出现", index)
        elif target.never_terminate:
            reason = ActionRefusal(
                "protected_process", f"「{target.name}」在动作黑名单中，禁止结束", index
            )
        elif target.is_self_or_ancestor:
            reason = ActionRefusal("self_protected", "本程序自身或其祖先进程禁止结束", index)
        elif not target.identity_matches_snapshot:
            reason = ActionRefusal(
                "identity_changed", "进程身份与扫描快照不一致（可能已退出或 PID 被复用）", index
            )
        elif target.create_time <= 0 or not target.name:
            reason = ActionRefusal("invalid_identity", "进程身份信息不完整，拒绝执行", index)
        if target.needs_review_network:
            warnings.append(
                f"「{target.name}」(PID {target.pid}) 存在需人工核实的公网连接："
                f"{target.needs_review_reason or '请先核实'}"
            )
        if reason is not None:
            refusals.append(reason)
            continue
        seen.add(target.pid)
        allowed.append(index)
    return PolicyDecision(bool(allowed), tuple(allowed), tuple(refusals), tuple(warnings))


def evaluate_hardlink_targets(
    targets: Sequence[HardlinkTarget],
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
) -> PolicyDecision:
    """2D：硬链接去重的逐项判定（同卷 NTFS、哈希复验、已有硬链接默认拒绝）。"""

    total_bytes = sum(max(0, target.redundant.size or 0) for target in targets)
    batch_ok, batch_refusals = _batch_gate(
        ActionKind.HARDLINK_DEDUPE, policy, verdict, len(targets), total_bytes
    )
    if not batch_ok:
        return PolicyDecision(False, refusals=tuple(batch_refusals))

    allowed: list[int] = []
    refusals: list[ActionRefusal] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for index, target in enumerate(targets):
        canonical = target.canonical
        redundant = target.redundant
        key = _dedupe_key(redundant.path)
        reason: ActionRefusal | None = None
        if not canonical.path or not redundant.path or key == "":
            reason = ActionRefusal("invalid_path", "路径为空", index)
        elif _dedupe_key(canonical.path) == key:
            reason = ActionRefusal("same_path", "保留文件与冗余文件是同一路径", index)
        elif key in seen:
            reason = ActionRefusal("duplicate_target", "同一冗余路径重复出现", index)
        elif not target.paths_exist:
            reason = ActionRefusal("stale", "文件已不存在（扫描后发生变化）", index)
        elif not target.content_sha256:
            reason = ActionRefusal("missing_hash", "缺少内容哈希，无法安全去重", index)
        elif not canonical.identity_known or not redundant.identity_known:
            reason = ActionRefusal("unknown_identity", "文件身份未知（inode 不可用）", index)
        elif canonical.identity == redundant.identity:
            reason = ActionRefusal("already_hardlinked", "两个路径已指向同一份数据", index)
        elif is_fully_hardlinked(target.group) or is_mutual_hardlink(target.group):
            reason = ActionRefusal(
                "group_has_hardlinks", "该重复组内已存在硬链接，不再自动建链接", index
            )
        elif not target.same_volume:
            reason = ActionRefusal("cross_volume", "不同卷之间不能建立硬链接", index)
        elif not target.ntfs:
            reason = ActionRefusal("non_ntfs", "目标卷不是 NTFS，不支持硬链接", index)
        elif not target.rehash_matches:
            reason = ActionRefusal("content_changed", "执行前内容哈希复验不一致，拒绝去重", index)
        elif canonical.size is not None and redundant.size is not None and canonical.size != redundant.size:
            reason = ActionRefusal("size_mismatch", "两个文件大小不一致", index)
        if reason is not None:
            refusals.append(reason)
            continue
        seen.add(key)
        allowed.append(index)
        warnings.append(
            f"第 {index + 1} 项替换后，「{redundant.path}」的修改时间/ACL 将变为保留文件的"
        )
    return PolicyDecision(bool(allowed), tuple(allowed), tuple(refusals), tuple(warnings))


@dataclass(frozen=True, slots=True)
class HardlinkDetachTarget:
    path: str
    size: int
    mtime: float
    nlink: int
    dev: int = 0
    ino: int = 0
    exists: bool = True
    is_dir: bool = False
    is_reparse: bool = False


def evaluate_detach_targets(
    targets: Sequence[HardlinkDetachTarget],
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
) -> PolicyDecision:
    """4B：硬链接独立化的逐项判定（仅 nlink>1 的普通文件）。"""

    total_bytes = sum(max(0, target.size) for target in targets)
    batch_ok, batch_refusals = _batch_gate(
        ActionKind.HARDLINK_DETACH, policy, verdict, len(targets), total_bytes
    )
    if not batch_ok:
        return PolicyDecision(False, refusals=tuple(batch_refusals))
    allowed: list[int] = []
    refusals: list[ActionRefusal] = []
    seen: set[str] = set()
    for index, target in enumerate(targets):
        key = _dedupe_key(target.path)
        reason: ActionRefusal | None = None
        if not target.path or not key:
            reason = ActionRefusal("invalid_path", "路径为空", index)
        elif key in seen:
            reason = ActionRefusal("duplicate_target", "同一路径重复出现", index)
        elif not target.exists:
            reason = ActionRefusal("stale", "文件已不存在（扫描后发生变化）", index)
        elif target.is_dir:
            reason = ActionRefusal("dir_not_supported", "当前阶段仅支持普通文件", index)
        elif target.is_reparse:
            reason = ActionRefusal("reparse_point", "符号链接/junction 不支持", index)
        elif target.nlink <= 1:
            reason = ActionRefusal("not_hardlinked", "该文件不是硬链接（nlink<=1）", index)
        if reason is not None:
            refusals.append(reason)
            continue
        seen.add(key)
        allowed.append(index)
    return PolicyDecision(bool(allowed), tuple(allowed), tuple(refusals), ())


def is_action_permitted(
    kind: ActionKind,
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
) -> PolicyDecision:
    """只做批次级闸门（UI 入口预检；逐项目标判定用对应的 evaluate_*）。"""

    ok, refusals = _batch_gate(kind, policy, verdict, 1, 0)
    return PolicyDecision(ok, () if not ok else (0,), tuple(refusals))


def policy_refusal_text(decision: PolicyDecision) -> str:
    """把策略拒绝/警告转成可展示的多行文本（各动作页面共用）。"""

    lines = [f"[{refusal.code}] {refusal.text}" for refusal in decision.refusals]
    if decision.warnings:
        lines.extend(f"提示：{warning}" for warning in decision.warnings)
    return "\n".join(lines) or "策略拒绝执行"
