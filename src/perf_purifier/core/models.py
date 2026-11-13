"""跨模块共享的数据结构。

设计约定：
* ``ProcessInfo`` 是采集层的不可变快照，树/评分/导出只读它，不回写。
* 风险等级只用于排序与筛选，**不是安全结论**，也不是"病毒判定"。
* 路径在展示时保持原始字符串；比较一律走 ``core.whitelist.normalize_path``。
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum, IntEnum

SCHEMA_VERSION = "1.1"
FILE_SCAN_SCHEMA_VERSION = "1.0"


class Severity(IntEnum):
    """风险等级。"""

    INFO = 0
    NOTICE = 1
    SUSPICIOUS = 2
    HIGH = 3


class Completeness(str, Enum):
    """数据完整度。"""

    FULL = "full"
    PARTIAL = "partial"
    DEGRADED = "degraded"


class SigStatus(str, Enum):
    """数字签名状态。"""

    NOT_CHECKED = "not_checked"
    VALID = "valid"
    SIGNED_UNTRUSTED = "signed_untrusted"
    INVALID = "invalid"
    UNSIGNED = "unsigned"
    CATALOG_OR_UNKNOWN = "catalog_or_unknown"
    UNREADABLE = "unreadable"


class Occupancy(str, Enum):
    """文件/目录占用状态（只读探测）。"""

    FREE = "free"
    LOCKED = "locked"
    NO_ACCESS = "no_access"
    NOT_PROBED = "not_probed"


class RemoteClass(str, Enum):
    """远端地址分类。"""

    LOOPBACK = "loopback"
    PRIVATE = "private"
    CGNAT = "cgnat"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    PUBLIC = "public"
    UNKNOWN = "unknown"


_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.INFO: "信息",
    Severity.NOTICE: "关注",
    Severity.SUSPICIOUS: "可疑",
    Severity.HIGH: "高风险",
}

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.INFO: "#6b7280",
    Severity.NOTICE: "#b45309",
    Severity.SUSPICIOUS: "#c2410c",
    Severity.HIGH: "#b91c1c",
}

_COMPLETENESS_LABELS: dict[Completeness, str] = {
    Completeness.FULL: "完整",
    Completeness.PARTIAL: "部分（权限不足）",
    Completeness.DEGRADED: "降级（数据可能缺失）",
}

_SIG_LABELS: dict[SigStatus, str] = {
    SigStatus.NOT_CHECKED: "未检查",
    SigStatus.VALID: "有效",
    SigStatus.SIGNED_UNTRUSTED: "已签名但不受信任/已过期",
    SigStatus.INVALID: "无效/可能被篡改",
    SigStatus.UNSIGNED: "无签名",
    SigStatus.CATALOG_OR_UNKNOWN: "目录签名或未知",
    SigStatus.UNREADABLE: "无法读取",
}

_OCCUPANCY_LABELS: dict[Occupancy, str] = {
    Occupancy.FREE: "空闲",
    Occupancy.LOCKED: "可能被占用",
    Occupancy.NO_ACCESS: "无访问权限",
    Occupancy.NOT_PROBED: "未探测",
}

_OCCUPANCY_COLORS: dict[Occupancy, str] = {
    Occupancy.FREE: "#15803d",
    Occupancy.LOCKED: "#b91c1c",
    Occupancy.NO_ACCESS: "#b45309",
    Occupancy.NOT_PROBED: "#6b7280",
}

_REMOTE_CLASS_LABELS: dict[RemoteClass, str] = {
    RemoteClass.LOOPBACK: "回环",
    RemoteClass.PRIVATE: "内网",
    RemoteClass.CGNAT: "运营商 NAT",
    RemoteClass.LINK_LOCAL: "链路本地",
    RemoteClass.MULTICAST: "组播",
    RemoteClass.RESERVED: "保留地址",
    RemoteClass.PUBLIC: "公网",
    RemoteClass.UNKNOWN: "未知",
}


def severity_label(severity: Severity) -> str:
    return _SEVERITY_LABELS.get(severity, str(severity))


def severity_color(severity: Severity) -> str:
    return _SEVERITY_COLORS.get(severity, "#6b7280")


def completeness_label(value: Completeness) -> str:
    return _COMPLETENESS_LABELS.get(value, str(value))


def signature_label(value: SigStatus) -> str:
    return _SIG_LABELS.get(value, str(value))


def occupancy_label(value: Occupancy) -> str:
    return _OCCUPANCY_LABELS.get(value, str(value))


def occupancy_color(value: Occupancy) -> str:
    return _OCCUPANCY_COLORS.get(value, "#6b7280")


def remote_class_label(value: RemoteClass) -> str:
    return _REMOTE_CLASS_LABELS.get(value, str(value))


def risk_of_score(score: int) -> Severity:
    """按加权总分映射等级：0-9 信息 / 10-24 关注 / 25-49 可疑 / >=50 高风险。"""

    if score >= 50:
        return Severity.HIGH
    if score >= 25:
        return Severity.SUSPICIOUS
    if score >= 10:
        return Severity.NOTICE
    return Severity.INFO


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """单个进程的只读快照（采集层产出）。"""

    pid: int
    ppid: int
    name: str = ""
    exe: str | None = None
    cmdline: tuple[str, ...] = ()
    username: str | None = None
    create_time: float = 0.0
    status: str = ""
    rss: int = 0
    vms: int = 0
    sig_status: SigStatus = SigStatus.NOT_CHECKED
    sig_publisher: str | None = None
    access_errors: tuple[str, ...] = ()

    @property
    def display_name(self) -> str:
        return self.name or f"<PID {self.pid}>"

    @property
    def cmdline_text(self) -> str:
        return " ".join(self.cmdline)

    @property
    def exe_basename(self) -> str:
        return os.path.basename(self.exe) if self.exe else ""


@dataclass(frozen=True, slots=True)
class RiskFlag:
    """一条命中的启发式规则。"""

    rule_id: str
    severity: Severity
    weight: int
    title: str
    evidence: str


@dataclass(slots=True)
class ProcessNode:
    """进程树节点：快照 + 派生信息（父子、深度、风险）。"""

    info: ProcessInfo
    parent_pid: int | None = None
    children: list[int] = field(default_factory=list)
    depth: int = 0
    flags: list[RiskFlag] = field(default_factory=list)
    score: int = 0
    risk: Severity = Severity.INFO
    orphaned: bool = False
    parent_pid_reused: bool = False

    @property
    def pid(self) -> int:
        return self.info.pid

    def flag_ids(self) -> list[str]:
        return [flag.rule_id for flag in self.flags]


@dataclass(frozen=True, slots=True)
class ScanWarning:
    """扫描过程中的非致命问题（权限、跳过、数据缺失等）。"""

    code: str
    message: str
    path: str | None = None
    phase: str = ""


@dataclass(frozen=True, slots=True)
class Endpoint:
    """一个网络端点（IP + 端口）。"""

    address: str
    port: int

    @property
    def text(self) -> str:
        if ":" in self.address:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"


@dataclass(frozen=True, slots=True)
class ConnectionInfo:
    """一条网络连接（已关联进程信息）。"""

    pid: int | None
    family: str
    protocol: str
    status: str
    laddr: Endpoint | None = None
    raddr: Endpoint | None = None
    remote_class: RemoteClass = RemoteClass.UNKNOWN
    is_listen: bool = False
    is_kernel: bool = False
    process_name: str | None = None
    process_exe: str | None = None
    process_trusted: bool = False
    process_sig: SigStatus = SigStatus.NOT_CHECKED
    needs_review: bool = False
    review_reason: str = ""
    note: str = ""

    @property
    def process_label(self) -> str:
        """表格/报告中展示的归属说明。"""

        if self.is_kernel:
            return "内核/系统连接（PID 0）"
        return self.process_name or "—"

    @property
    def explanation(self) -> str:
        """展示用说明：优先核实原因，其次普通备注。"""

        return self.review_reason or self.note


@dataclass(slots=True)
class NetworkScanResult:
    """一次网络连接采集的结果。"""

    connections: list[ConnectionInfo] = field(default_factory=list)
    completeness: Completeness = Completeness.FULL
    elapsed_ms: int = 0
    warnings: list[ScanWarning] = field(default_factory=list)

    @property
    def public_count(self) -> int:
        return sum(1 for item in self.connections if item.remote_class is RemoteClass.PUBLIC)

    @property
    def review_count(self) -> int:
        return sum(1 for item in self.connections if item.needs_review)

    @property
    def kernel_public_count(self) -> int:
        return sum(
            1 for item in self.connections if item.is_kernel and item.remote_class is RemoteClass.PUBLIC
        )

    @property
    def listen_count(self) -> int:
        return sum(1 for item in self.connections if item.is_listen)

    @property
    def established_count(self) -> int:
        return sum(1 for item in self.connections if item.status == "ESTABLISHED")

    def by_pid(self) -> dict[int, list[ConnectionInfo]]:
        grouped: dict[int, list[ConnectionInfo]] = {}
        for item in self.connections:
            if item.pid is None:
                continue
            grouped.setdefault(item.pid, []).append(item)
        return grouped


@dataclass(frozen=True, slots=True)
class TempRoot:
    """一个临时文件扫描根。"""

    path: str
    kind: str = "temp"
    exists: bool = True


@dataclass(frozen=True, slots=True)
class TempEntry:
    """临时目录/文件条目（根目录下一层，目录为递归聚合值）。"""

    root: str
    path: str
    is_dir: bool
    size: int
    file_count: int
    mtime: float
    occupancy: Occupancy = Occupancy.NOT_PROBED
    occupancy_detail: str = ""


@dataclass(slots=True)
class TempScanResult:
    """一次临时文件占用扫描的结果。"""

    roots: list[TempRoot] = field(default_factory=list)
    entries: list[TempEntry] = field(default_factory=list)
    total_size: int = 0
    total_files: int = 0
    probed_files: int = 0
    probe_candidates: int = 0
    skipped_reparse: int = 0
    unreadable: int = 0
    elapsed_ms: int = 0
    completeness: Completeness = Completeness.FULL
    probe_note: str = ""
    warnings: list[ScanWarning] = field(default_factory=list)

    def size_for_root(self, root_path: str) -> int:
        return sum(entry.size for entry in self.entries if entry.root == root_path)

    def files_for_root(self, root_path: str) -> int:
        return sum(entry.file_count for entry in self.entries if entry.root == root_path)


@dataclass(slots=True)
class ProcessTree:
    """进程树快照与派生结果。"""

    nodes: dict[int, ProcessNode] = field(default_factory=dict)
    roots: list[int] = field(default_factory=list)
    orphans: list[int] = field(default_factory=list)
    cycles: list[int] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)
    completeness: Completeness = Completeness.FULL
    total_processes: int = 0
    elapsed_ms: int = 0

    def iter_preorder(self) -> Iterator[ProcessNode]:
        """按树的先序产出节点（用于 CSV/HTML 导出的层级顺序）。"""

        stack: list[ProcessNode] = [
            self.nodes[pid] for pid in reversed(self.roots) if pid in self.nodes
        ]
        seen: set[int] = set()
        while stack:
            node = stack.pop()
            if node.pid in seen:
                continue
            seen.add(node.pid)
            yield node
            for child_pid in reversed(node.children):
                child = self.nodes.get(child_pid)
                if child is not None and child.pid not in seen:
                    stack.append(child)

    def flagged_nodes(self) -> list[ProcessNode]:
        return [node for node in self.nodes.values() if node.flags]

    def count_at_least(self, severity: Severity) -> int:
        return sum(1 for node in self.nodes.values() if node.flags and node.risk >= severity)

    def max_severity(self) -> Severity:
        if not self.nodes:
            return Severity.INFO
        return max(node.risk for node in self.nodes.values())


@dataclass(slots=True)
class ProcessScanResult:
    """模块 A 一次扫描的完整结果（进程 + 网络 + 临时占用）。"""

    tree: ProcessTree
    started_at: float
    finished_at: float
    is_admin: bool = False
    connections: NetworkScanResult | None = None
    temp: TempScanResult | None = None

    @property
    def duration_ms(self) -> int:
        return max(0, int((self.finished_at - self.started_at) * 1000))


# ---------------------------------------------------------------------------
# 模块 B：文件扫描（阶段 1C，只读）
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class FileRecord:
    """遍历阶段产出的文件快照。"""

    path: str
    size: int
    mtime: float
    dev: int = 0
    ino: int = 0
    attributes: int = 0

    @property
    def identity(self) -> tuple[int, int]:
        """(设备号, inode)；相同 identity 说明两个路径指向同一份数据（硬链接）。"""

        return (self.dev, self.ino)

    @property
    def suffix(self) -> str:
        return os.path.splitext(self.path)[1].casefold()

    @property
    def path_depth(self) -> int:
        return self.path.replace("/", os.sep).count(os.sep)


@dataclass(frozen=True, slots=True)
class LargeFile:
    path: str
    size: int
    mtime: float


@dataclass(frozen=True, slots=True)
class DuplicateGroup:
    """一组内容完全相同的文件。"""

    group_id: int
    size: int
    full_sha256: str
    files: tuple[FileRecord, ...]
    distinct_inodes: int = 0
    has_hardlinks: bool = False
    already_hardlinked: bool = False
    suggested_keep_path: str = ""

    @property
    def reclaimable_bytes(self) -> int:
        """删除冗余副本可释放的估算空间（硬链接副本不重复占用空间，不计入）。"""

        return self.size * (self.distinct_inodes - 1) if self.distinct_inodes > 1 else 0

    @property
    def suggested_keep(self) -> FileRecord | None:
        for record in self.files:
            if record.path == self.suggested_keep_path:
                return record
        return None


@dataclass(frozen=True, slots=True)
class FileScanOptions:
    """模块 B 扫描参数（全部可配置，有安全默认值）。"""

    root: str
    min_size: int = 1024
    max_files: int = 300_000
    walk_budget_s: float = 120.0
    large_limit: int = 100
    # 过滤/排除（阶段 1C 增强）
    exclude_patterns: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()
    modified_after: float = 0.0
    # 哈希并发（0=按介质自动）与 SQLite 哈希缓存
    hash_workers: int = 0
    use_cache: bool = True
    cache_ttl_days: int = 30


@dataclass(slots=True)
class FileScanResult:
    """模块 B 一次扫描的完整结果。"""

    root: str
    options: FileScanOptions
    started_at: float
    finished_at: float
    duplicate_groups: list[DuplicateGroup] = field(default_factory=list)
    large_files: list[LargeFile] = field(default_factory=list)
    files_scanned: int = 0
    dirs_scanned: int = 0
    total_bytes: int = 0
    skipped_reparse: int = 0
    skipped_unreadable: int = 0
    skipped_cloud: int = 0
    skipped_excluded: int = 0
    failed_reads: int = 0
    unstable_files: int = 0
    partial_hashed: int = 0
    full_hashed: int = 0
    cache_hits: int = 0
    hash_bytes: int = 0
    hash_workers: int = 1
    media_type: str = "unknown"
    warnings: list[ScanWarning] = field(default_factory=list)
    completeness: Completeness = Completeness.FULL
    elapsed_ms: int = 0
    truncated: bool = False

    @property
    def duration_ms(self) -> int:
        return max(0, int((self.finished_at - self.started_at) * 1000))

    @property
    def duplicate_file_count(self) -> int:
        return sum(len(group.files) for group in self.duplicate_groups)

    @property
    def reclaimable_bytes(self) -> int:
        return sum(group.reclaimable_bytes for group in self.duplicate_groups)
