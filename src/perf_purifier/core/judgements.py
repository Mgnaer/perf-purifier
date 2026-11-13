"""阶段 2 依赖的纯判定函数（P0 补测，逐函数交付）。

本模块只放"无副作用、输入即全部信息"的判定逻辑：不做 I/O、不读环境、不依赖
Windows 权限/网络。阶段 1 的扫描器暂不接线（见交付说明），阶段 2 前的接线会以
本模块为唯一真源，避免执行层与展示层各写一套判断。

当前已交付：
* 任务 1：网络"需人工核实"判定 —— :func:`is_needs_review`
* 任务 2：文件硬链接判定 —— :func:`is_mutual_hardlink` / :func:`is_fully_hardlinked`
* 任务 4：扫描数据完整度三档判定 —— :func:`compute_completeness`
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .models import Completeness, RemoteClass, SigStatus, signature_label

CompletenessLevel = Literal["full", "partial", "limited"]
"""三档完整度：``limited`` 表示"数据不可信，阶段 2 应禁止批量动作"。"""

DEFAULT_UNREADABLE_RATIO_THRESHOLD = 0.30
DEFAULT_UNREADABLE_MIN_ABSOLUTE = 5
"""默认阈值：不可读对象比例 > 30% 且绝对数 >= 5 才升级为 ``limited``（小样本豁免）。"""


@dataclass(frozen=True, slots=True)
class ConnectionMeta:
    """一条网络连接的判定输入（纯数据，不包含 psutil 对象）。

    调用方约定：
    * ``remote_class`` 由现有地址分类器（``classify_address``）计算后注入；
    * 监听连接没有 ``raddr``，通常为 ``remote_class=UNKNOWN`` + ``is_listen=True``；
    * ``is_listen`` 仅为防御字段：若与 ``remote_class`` 矛盾，本函数以"监听"为准。
    """

    pid: int | None
    remote_ip: str | None
    remote_class: RemoteClass
    protocol: str = "TCP"
    status: str = ""
    is_listen: bool = False
    family: str = "IPv4"


@dataclass(frozen=True, slots=True)
class ProcessMeta:
    """关联进程的判定输入（纯数据）。

    调用方约定：
    * ``trusted_path`` 由分析白名单（Whitelist）计算后注入，函数本身不做路径判断；
    * ``pid`` 为 ``None`` 表示进程元数据缺失（无法关联）；
    * ``sig_status`` 来自签名校验阶段，未校验时用 ``NOT_CHECKED``。
    """

    pid: int | None = None
    name: str | None = None
    exe: str | None = None
    sig_status: SigStatus = SigStatus.NOT_CHECKED
    trusted_path: bool = False


def is_needs_review(conn: ConnectionMeta, proc: ProcessMeta) -> tuple[bool, str]:
    """判断一条公网连接是否需要人工核实（阶段 2B 结束进程前的复核闸门/审计输入）。

    判定依据（三者同时满足才返回 True）：
    1. 远端为公网（``remote_class is RemoteClass.PUBLIC``）；
    2. 进程不在受信路径（``proc.trusted_path`` 为 False）；
    3. 签名不是有效签名（``proc.sig_status`` 不是 ``VALID``；未签名/无效/不受信任/
       未检查/目录签名未知都算"非有效"，理由里会给出具体状态）。

    求值顺序（短路，保证原因可解释）：
    1. 非公网远端（内网/回环/链路本地/保留/未知）→ ``(False, "")``；
    2. 监听连接或无远端地址（防御性输入）→ ``(False, "")``；
    3. PID 0 → ``(False, "")``：内核/系统连接，无用户进程可归因，不进入本判定；
    4. 连接 PID 缺失或与进程元数据不匹配 → ``(True, "无法关联进程")``；
    5. 受信路径 → ``(False, "")``；
    6. 有效签名 → ``(False, "")``；
    7. 其余 → ``(True, 原因)``。

    已知局限：
    * catalog 签名（``CATALOG_OR_UNKNOWN``）**不判**"无签名"：系统/Program Files 下
      大量文件是目录签名，因此受信路径会在第 5 步直接放过，不追求签名结论；
    * PID 0 不进入本函数（函数内仅做防御，调用方应先过滤并单独标注内核连接）；
    * 不解析域名/ASN/CDN，不判断连接方向语义（只透传 ``status``）；
    * 不做路径判断（``trusted_path`` 由调用方注入）；分析白名单（用户自定义进程名）
      的抑制逻辑放在适配器层，不在本函数内，避免纯函数持有配置；
    * 无 I/O、无时间依赖：同一输入永远得到同一输出，可直接用于审计日志复现。

    安全边界：返回 True 只代表"值得人工核实"，不是恶意判定，也不构成任何
    结束进程/删除动作的授权；阶段 2 仍需二次确认与动作黑名单。
    """

    # 1. 只有公网远端才纳入本判定
    if conn.remote_class is not RemoteClass.PUBLIC:
        return False, ""
    # 2. 监听连接/无远端地址（正常不会带 PUBLIC，防御异常输入）
    if conn.is_listen or not conn.remote_ip:
        return False, ""
    # 3. 内核/系统连接：PID 0 不代表用户进程（调用方应已单独标注）
    if conn.pid is not None and conn.pid <= 0:
        return False, ""
    # 4. 无法关联到用户进程
    if conn.pid is None:
        return True, "公网远端，但无法关联到进程（PID 缺失）"
    if proc.pid is None or proc.pid != conn.pid:
        return True, "公网远端，但无法关联到进程（进程元数据缺失或不匹配）"
    # 5. 受信路径（Windows/Program Files 等）不因签名结论被标记
    if proc.trusted_path:
        return False, ""
    # 6. 有效签名
    if proc.sig_status is SigStatus.VALID:
        return False, ""
    # 7. 其余：非受信路径 + 非有效签名
    sig_text = signature_label(proc.sig_status)
    if not proc.exe:
        return True, f"公网远端；进程可执行文件路径不可读（权限不足）；签名状态：{sig_text}"
    return True, f"公网远端；进程位于非受信路径（非 Windows / Program Files）；签名状态：{sig_text}"


@dataclass(frozen=True, slots=True)
class FileMeta:
    """文件身份元数据（阶段 2C/2D 判定的最小输入，纯数据）。

    数据来源约定：调用方需先用
    ``os.stat(path, follow_symlinks=False)`` 补全 ``st_dev/st_ino/st_nlink``
    （Windows 上 ``DirEntry.stat()`` 的 dev/ino 恒为 0），再构造本对象。
    """

    path: str
    st_dev: int
    st_ino: int
    st_nlink: int = 0
    size: int | None = None

    @property
    def identity(self) -> tuple[int, int]:
        """文件唯一身份：(卷序列号, 文件索引)。"""

        return (self.st_dev, self.st_ino)

    @property
    def identity_known(self) -> bool:
        """身份是否可信；``0`` 表示文件系统/API 未提供（未知，不能据此下结论）。"""

        return self.st_dev != 0 and self.st_ino != 0


def is_mutual_hardlink(group: Sequence[FileMeta]) -> bool:
    """判断组内是否存在"互为硬链接"的路径（阶段 2D 闸门 / 2C 可回收估算输入）。

    判定依据：
    * 组内存在 >= 2 条路径的 ``(st_dev, st_ino)`` 完全相同 → True；
    * 仅凭 ``st_nlink > 1`` 不足以判定：若组内只有 1 条路径持有该 inode，
      说明其它链接在组外，删除组内文件仍会释放空间 → False；
    * 身份未知（``st_dev == 0`` 或 ``st_ino == 0``）的条目不计入任何 inode 分组、
      不参与结论；若因此无法形成">=2 路径同 inode"的证据 → False（保守，不猜）；
    * 同 inode 但不同 ``st_dev`` 视为不同文件（跨卷不可能是同一条硬链接）。

    已知局限：
    * junction/符号链接已在扫描阶段跳过，本函数不做 reparse point 判断；
    * 不校验 ACL、大小写敏感性、文件系统类型；FAT32 等无可靠 inode 的卷结果为
      "身份未知"；
    * ``st_nlink`` 只作为诊断字段，不参与布尔判定（计数可能被外部工具重置）；
    * 无 I/O：不做路径存在性检查，也不补 ``os.stat``。

    安全边界：本函数只回答"是否互为硬链接"，不替代阶段 2D 的同卷 / NTFS /
    内容哈希校验；也不构成任何删除或建链接动作的授权。
    """

    known = [meta for meta in group if meta.identity_known]
    if len(known) < 2:
        return False
    counts: dict[tuple[int, int], int] = {}
    for meta in known:
        identity = meta.identity
        counts[identity] = counts.get(identity, 0) + 1
        if counts[identity] >= 2:
            return True
    return False


def is_fully_hardlinked(group: Sequence[FileMeta]) -> bool:
    """判断组内全部路径是否指向同一份数据（阶段 2D"硬链接无收益"判断）。

    判定依据：组内 >= 2 条路径、全部身份已知、且 ``(st_dev, st_ino)`` 完全一致
    → True。任一身份未知或存在不同 inode → False（保守，不把"疑似"当"确定"）。

    已知局限：同 :func:`is_mutual_hardlink`；另外不感知"未来新增/删除链接"导致的
    引用计数变化，判定仅代表本次快照。
    """

    if len(group) < 2:
        return False
    first_identity: tuple[int, int] | None = None
    for meta in group:
        if not meta.identity_known:
            return False
        identity = meta.identity
        if first_identity is None:
            first_identity = identity
        elif identity != first_identity:
            return False
    return True


# ---------------------------------------------------------------------------
# 任务 4：扫描数据完整度三档判定
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ScanStats:
    """一次扫描的完整度判定输入（纯数据，由各扫描器汇总后注入）。

    字段约定：
    * ``total_items``：本次扫描的对象数（进程数或文件数）；0 表示没有采集到数据；
    * ``unreadable_fields``：字段级不可读次数（如 username/cmdline 读取失败），
      只影响展示/证据完整性，**不**代表对象集合缺失；
    * ``unreadable_items``：对象级不可读数量（进程/文件整体读不到）；
    * ``permission_limited``：整体权限受限标记（如非管理员运行）；
    * ``budget_truncated``：任一阶段预算触顶（进程上限 / Temp 预算 / 遍历预算）；
    * ``excluded_items``：用户排除规则命中的数量（主动缩小范围，不降档）；
    * ``core_enumeration_failed``：核心枚举整体失败（进程/网络枚举失败）。
    """

    total_items: int = 0
    unreadable_fields: int = 0
    unreadable_items: int = 0
    permission_limited: bool = False
    budget_truncated: bool = False
    excluded_items: int = 0
    core_enumeration_failed: bool = False


@dataclass(frozen=True, slots=True)
class Reason:
    """稳定性原因：``code`` 供审计日志引用（不随文案变化），``text`` 供 UI 展示。"""

    code: str
    text: str


@dataclass(frozen=True, slots=True)
class CompletenessVerdict:
    """三档完整度判定结果；``reasons`` 中可能含不改变档位的提示（如 excluded_items）。"""

    level: CompletenessLevel
    reasons: tuple[Reason, ...] = ()

    @property
    def allows_batch_actions(self) -> bool:
        """阶段 2 建议口径：``limited`` 时禁止批量动作（仅允许单条 + 额外复核）。

        注意：这是**建议策略**，不构成任何动作授权；阶段 2 仍须二次确认与动作黑名单。
        """

        return self.level != "limited"


def to_completeness(verdict: CompletenessVerdict) -> Completeness:
    """适配阶段 1 现有枚举（``limited`` ↔ 现有 ``DEGRADED``），供接线阶段使用。"""

    return {
        "full": Completeness.FULL,
        "partial": Completeness.PARTIAL,
        "limited": Completeness.DEGRADED,
    }[verdict.level]


def compute_completeness(
    stats: ScanStats,
    *,
    ratio_threshold: float = DEFAULT_UNREADABLE_RATIO_THRESHOLD,
    min_absolute: int = DEFAULT_UNREADABLE_MIN_ABSOLUTE,
) -> CompletenessVerdict:
    """把扫描统计判定为 ``full`` / ``partial`` / ``limited`` 三档（阶段 2 动作闸门输入）。

    判定依据（优先级从高到低）：
    1. ``core_enumeration_failed`` → limited（核心枚举失败，数据不可信）；
    2. ``budget_truncated`` → limited（扫描未完成，结果不是全集）；
    3. ``total_items == 0`` → limited（没有数据，不能授权任何批量动作）；
    4. 不可读对象比例 **严格大于** ``ratio_threshold`` 且绝对数 ``>= min_absolute``
       → limited；
    5. 否则若 ``permission_limited`` / ``unreadable_fields > 0`` /
       ``unreadable_items > 0`` → partial；
    6. 其余 → full。

    阈值说明（默认 30% / 5 条，理由见设计说明）：
    * 用**对象级**不可读比例，不用字段级：非管理员下部分字段缺失是常态；
    * 严格大于（相等不触发），避免"恰好 30%"的边界抖动；
    * 绝对下限 ``min_absolute`` 给小样本豁免，避免"2 条里 1 条失败=50%"直接禁批量；
    * 比例超阈值但绝对数不足时仍降为 partial，并给出 ``small_sample_ratio`` 提示。

    已知局限：
    * 非管理员恒为 partial 是预期行为，不是异常；
    * 阈值与阶段 2 的 "limited 禁批量执行" 策略耦合，调整阈值需同步评审动作闸门；
    * 不评价数据新鲜度（缓存命中/上次扫描时间）与跨阶段合并（进程/网络/Temp 各自统计）；
    * ``excluded_items`` 是用户主动排除，只作为原因记录，**永不**因它降档；
    * 纯函数：输入即全部信息，不读权限/环境/文件系统。

    安全边界：本函数只输出判定与原因，不执行任何动作，也不构成动作授权。
    """

    total = max(0, int(stats.total_items))
    unreadable_items = max(0, int(stats.unreadable_items))
    unreadable_fields = max(0, int(stats.unreadable_fields))
    excluded_items = max(0, int(stats.excluded_items))
    threshold = (
        float(ratio_threshold)
        if 0.0 <= float(ratio_threshold) <= 1.0
        else DEFAULT_UNREADABLE_RATIO_THRESHOLD
    )
    absolute = max(0, int(min_absolute))
    ratio = (unreadable_items / total) if total > 0 else 0.0

    reasons: list[Reason] = []
    limited = False

    if stats.core_enumeration_failed:
        limited = True
        reasons.append(
            Reason("enumeration_failed", "核心枚举整体失败（进程/网络枚举失败），数据不可信")
        )
    if stats.budget_truncated:
        limited = True
        reasons.append(
            Reason("budget_truncated", "扫描达到预算上限（进程数/临时文件/遍历预算），结果不是全集")
        )
    if total == 0:
        limited = True
        reasons.append(Reason("no_data", "未采集到任何数据，不能据此执行批量操作"))

    if total > 0 and ratio > threshold and unreadable_items >= absolute:
        limited = True
        reasons.append(
            Reason(
                "unreadable_ratio",
                f"不可读对象比例 {ratio:.0%} 超过阈值 {threshold:.0%}"
                f"（{unreadable_items}/{total}）",
            )
        )

    degraded = False
    if not limited:
        if stats.permission_limited:
            degraded = True
            reasons.append(Reason("permission_limited", "当前权限受限（如非管理员），部分数据不可读"))
        if unreadable_fields > 0:
            degraded = True
            reasons.append(
                Reason("unreadable_fields", f"{unreadable_fields} 个字段不可读（不影响对象集合完整性）")
            )
        if unreadable_items > 0:
            degraded = True
            reasons.append(
                Reason("unreadable_items", f"{unreadable_items} 个对象不可读（共 {total} 个，占 {ratio:.0%}）")
            )
            if ratio > threshold and unreadable_items < absolute:
                reasons.append(
                    Reason(
                        "small_sample_ratio",
                        f"不可读比例偏高，但样本仅 {unreadable_items} 个"
                        f"（低于绝对阈值 {absolute}），保守降为部分",
                    )
                )

    if excluded_items > 0:
        reasons.append(
            Reason(
                "excluded_items",
                f"已按用户排除规则跳过 {excluded_items} 项，结果不代表全盘；"
                "阶段 2 应在日志中记录扫描范围",
            )
        )

    if limited:
        level: CompletenessLevel = "limited"
    elif degraded:
        level = "partial"
    else:
        level = "full"
    return CompletenessVerdict(level=level, reasons=tuple(reasons))
