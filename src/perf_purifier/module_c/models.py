"""模块 C 数据结构（只读扫描结果 / 垃圾规则 / 清理目标）。

设计约定：
* 所有 dataclass 都不持有文件句柄或 UI 对象，可安全跨线程传递；
* 清理目标 :class:`JunkItem` 同时作为 ``core.action_policy.SlimTarget`` 的构造输入，
  以及 ``jobs.action_job.ActionJob`` 的执行目标（其 duck-typing 只需 ``path/size``）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.judgements import CompletenessVerdict
from ..core.models import Completeness, ScanWarning

RISK_SAFE = "safe"
RISK_CAUTION = "caution"
RISK_SYSTEM = "system"

RISK_LABELS: dict[str, str] = {
    RISK_SAFE: "安全",
    RISK_CAUTION: "谨慎",
    RISK_SYSTEM: "系统",
}
RISK_ORDER: dict[str, int] = {RISK_SAFE: 0, RISK_CAUTION: 1, RISK_SYSTEM: 2}

MODE_CHILDREN = "children"
MODE_TREE = "tree"
MODE_FILES = "files"
MODE_SPECIAL = "special"

MODE_LABELS: dict[str, str] = {
    MODE_CHILDREN: "清空目录内容",
    MODE_TREE: "删除整个目录",
    MODE_FILES: "删除匹配文件",
    MODE_SPECIAL: "专用通道",
}


@dataclass(frozen=True, slots=True)
class JunkRule:
    """一条可清理规则（声明式：只描述"能删什么"，不执行任何动作）。"""

    id: str
    name: str
    category: str
    risk: str
    mode: str
    roots: tuple[str, ...]
    file_globs: tuple[str, ...] = ()
    requires_admin: bool = False
    note: str = ""
    special: str = ""

    @property
    def risk_label(self) -> str:
        return RISK_LABELS.get(self.risk, self.risk)

    @property
    def mode_label(self) -> str:
        return MODE_LABELS.get(self.mode, self.mode)


@dataclass(slots=True)
class JunkItem:
    """一个可删除单元（文件 / 目录 / 专用动作）。"""

    rule_id: str
    rule_name: str
    category: str
    risk: str
    path: str
    size: int
    file_count: int
    mtime: float
    kind: str  # dir / file / special
    allowed_root: str
    requires_admin: bool = False
    note: str = ""
    special: str = ""

    @property
    def is_special(self) -> bool:
        return bool(self.special)

    @property
    def size_bytes(self) -> int:
        return max(0, int(self.size))


@dataclass(slots=True)
class JunkRuleResult:
    """单条规则的扫描结果。"""

    rule: JunkRule
    items: list[JunkItem] = field(default_factory=list)
    error: str = ""

    @property
    def total_size(self) -> int:
        return sum(item.size_bytes for item in self.items)

    @property
    def file_count(self) -> int:
        return sum(item.file_count for item in self.items)


@dataclass(frozen=True, slots=True)
class OverviewEntry:
    """卷根顶层子项（目录已递归汇总）。"""

    name: str
    path: str
    is_dir: bool
    size: int
    file_count: int
    mtime: float


@dataclass(frozen=True, slots=True)
class LargeFileHit:
    """大文件排行条目。"""

    path: str
    size: int
    mtime: float


@dataclass(slots=True)
class SpaceScanResult:
    """一次「磁盘空间」扫描的完整结果（概览 + 垃圾规则 + 大文件）。"""

    drive: str = ""
    total_bytes: int = 0
    free_bytes: int = 0
    overview_entries: list[OverviewEntry] = field(default_factory=list)
    top_files: list[LargeFileHit] = field(default_factory=list)
    junk_results: list[JunkRuleResult] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)
    completeness: Completeness = Completeness.FULL
    verdict: CompletenessVerdict | None = None
    elapsed_ms: int = 0
    include_caution: bool = False
    include_system: bool = False
    overview_truncated: bool = False
    files_scanned: int = 0

    # ------------------------------------------------------------------ 派生
    @property
    def used_bytes(self) -> int:
        return max(0, self.total_bytes - self.free_bytes)

    @property
    def junk_items(self) -> list[JunkItem]:
        items: list[JunkItem] = []
        for result in self.junk_results:
            items.extend(result.items)
        return items

    @property
    def junk_total_size(self) -> int:
        return sum(result.total_size for result in self.junk_results)

    def sizes_by_risk(self) -> dict[str, int]:
        sizes = {RISK_SAFE: 0, RISK_CAUTION: 0, RISK_SYSTEM: 0}
        for result in self.junk_results:
            sizes[result.rule.risk] = sizes.get(result.rule.risk, 0) + result.total_size
        return sizes

    def items_for_rule(self, rule_id: str) -> list[JunkItem]:
        for result in self.junk_results:
            if result.rule.id == rule_id:
                return list(result.items)
        return []


__all__ = [
    "MODE_CHILDREN",
    "MODE_FILES",
    "MODE_LABELS",
    "MODE_SPECIAL",
    "MODE_TREE",
    "RISK_CAUTION",
    "RISK_LABELS",
    "RISK_ORDER",
    "RISK_SAFE",
    "RISK_SYSTEM",
    "JunkItem",
    "JunkRule",
    "JunkRuleResult",
    "LargeFileHit",
    "OverviewEntry",
    "SpaceScanResult",
]
