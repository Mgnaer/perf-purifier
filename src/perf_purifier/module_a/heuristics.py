"""启发式规则引擎（纯函数，可脱离 GUI/psutil 单测）。

纪律：
* 只输出"规则命中 + 证据"，**不输出"病毒/恶意"结论**；
* 命中证据中的命令行使用脱敏文本，避免把密码/令牌写进 UI 与导出；
* 权重只用于排序/筛选，最终等级 = ``max(总分档位, 单条规则最高等级)``；
* 单条规则异常不影响其它规则（逐条 try/except）。
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass

from ..core.fmt import redact_cmdline
from ..core.models import (
    ProcessNode,
    ProcessTree,
    RiskFlag,
    Severity,
    SigStatus,
    risk_of_score,
)
from ..core.whitelist import (
    Whitelist,
    expected_paths_for,
    is_suspicious_location,
    normalize_path,
)

logger = logging.getLogger(__name__)

_MAX_EVIDENCE = 240


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    severity: Severity
    weight: int
    title: str
    description: str


RULES: dict[str, Rule] = {
    rule.rule_id: rule
    for rule in (
        Rule("R01", Severity.SUSPICIOUS, 12, "从用户临时/下载目录运行", "可执行文件位于 %TEMP% / Downloads 等用户可写目录"),
        Rule("R02", Severity.NOTICE, 4, "无数字签名", "签名状态为未签名；单条不足以定性，仅作加权"),
        Rule("R02B", Severity.SUSPICIOUS, 15, "数字签名无效", "签名校验失败，文件可能在签名后被修改"),
        Rule("R02C", Severity.NOTICE, 6, "签名不受信任或已过期", "存在签名，但证书链不受信任或已过期；需人工核实来源"),
        Rule("R03", Severity.NOTICE, 6, "父进程已退出或 PID 被复用", "父进程不在快照中，或父进程创建时间晚于子进程"),
        Rule("R04", Severity.HIGH, 30, "系统进程名来自非预期路径（疑似伪装）", "关键系统进程名未运行在 System32 等预期路径"),
        Rule("R05", Severity.HIGH, 25, "关键系统进程的父进程异常", "如 svchost.exe 的父进程不是 services.exe"),
        Rule("R06", Severity.HIGH, 25, "命令行包含可疑参数", "命中编码命令/隐藏窗口/下载执行等 LOLBin 特征"),
        Rule("R07", Severity.HIGH, 25, "文档/IM 进程派生了命令行类子进程", "常见钓鱼/宏病毒的链式行为特征"),
        Rule("R07B", Severity.NOTICE, 8, "浏览器派生了命令行类子进程", "可能是正常更新/扩展行为，也可能是漏洞利用，需人工核实"),
        Rule("R09", Severity.HIGH, 20, "从网络路径运行", "可执行文件位于 UNC 网络路径"),
        Rule("R10", Severity.NOTICE, 5, "进程名与可执行文件不一致", "name 与 exe 文件名不匹配"),
        Rule("R11", Severity.INFO, 2, "部分进程信息不可读（权限不足）", "需管理员权限才能读取完整进程信息"),
    )
}

# ---- 命令行特征 ----
_STRONG_CMDLINE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("编码命令", re.compile(r"(?i)\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}")),
    ("隐藏窗口", re.compile(r"(?i)\s-w(?:indowstyle)?\s+hidden")),
    ("下载/动态执行", re.compile(r"(?i)(?:invoke-webrequest|\biwr\b|downloadstring|downloadfile|invoke-expression|\biex\b)")),
    ("certutil 下载/解码", re.compile(r"(?i)certutil(?:\.exe)?\s+(?:-urlcache|-decode|-decodehex)")),
    ("bitsadmin 传输", re.compile(r"(?i)bitsadmin(?:\.exe)?\s+/transfer")),
    ("mshta 远程脚本", re.compile(r"(?i)mshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)")),
    ("rundll32 脚本", re.compile(r"(?i)rundll32(?:\.exe)?\s+\S*?(?:javascript:|vbscript:)")),
    ("regsvr32 远程注册", re.compile(r"(?i)regsvr32(?:\.exe)?\s+.*?/i:https?://")),
    ("wmic 创建进程", re.compile(r"(?i)wmic(?:\.exe)?\s+process\s+call\s+create")),
    ("base64 解码", re.compile(r"(?i)frombase64string")),
)
_WEAK_CMDLINE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("执行策略绕过", re.compile(r"(?i)-executionpolicy\s+bypass")),
    ("隐藏配置", re.compile(r"(?i)-(?:nop|noprofile)\b")),
    ("窗口最小化", re.compile(r"(?i)-windowstyle\s+minimized")),
)

# ---- 进程血缘特征 ----
_OFFICE_PDF_IM_PARENTS: frozenset[str] = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "onenote.exe",
        "mspub.exe",
        "visio.exe",
        "acrord32.exe",
        "acrobat.exe",
        "foxitreader.exe",
        "foxitpdfreader.exe",
        "sumatrapdf.exe",
        "wps.exe",
        "et.exe",
        "wpp.exe",
        "wpspdf.exe",
        "wechat.exe",
        "weixin.exe",
        "qq.exe",
        "tim.exe",
        "dingtalk.exe",
        "feishu.exe",
        "lark.exe",
        "telegram.exe",
        "discord.exe",
    }
)
_BROWSER_PARENTS: frozenset[str] = frozenset(
    {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"}
)
_SHELL_SPAWN_CHILD_NAMES: frozenset[str] = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe",
    }
)

# 关键系统进程 -> 预期父进程名
_EXPECTED_PARENT_NAMES: dict[str, frozenset[str]] = {
    "svchost.exe": frozenset({"services.exe"}),
    "lsass.exe": frozenset({"wininit.exe"}),
    "winlogon.exe": frozenset({"smss.exe"}),
    "csrss.exe": frozenset({"smss.exe"}),
    "services.exe": frozenset({"wininit.exe"}),
}

# 父进程退出后很常见的正常进程（避免"孤儿"规则误报）
_ORPHAN_PRONE_NAMES: frozenset[str] = frozenset(
    {
        "conhost.exe",
        "dllhost.exe",
        "runtimebroker.exe",
        "searchprotocolhost.exe",
        "searchfilterhost.exe",
        "wmiprvse.exe",
        "taskhostw.exe",
        "backgroundtaskhost.exe",
        "smartscreen.exe",
        "sihost.exe",
        "ctfmon.exe",
        "shellexperiencehost.exe",
    }
)


def _flag(
    rule_id: str,
    evidence: str,
    *,
    severity: Severity | None = None,
    weight: int | None = None,
    title: str | None = None,
) -> RiskFlag:
    rule = RULES[rule_id]
    return RiskFlag(
        rule_id=rule_id,
        severity=rule.severity if severity is None else severity,
        weight=rule.weight if weight is None else weight,
        title=rule.title if title is None else title,
        evidence=evidence[:_MAX_EVIDENCE],
    )


def _parent_node(node: ProcessNode, tree: ProcessTree) -> ProcessNode | None:
    if node.parent_pid is None:
        return None
    return tree.nodes.get(node.parent_pid)


def _check_r01_location(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    exe = node.info.exe
    if not exe or whitelist.is_trusted_path(exe):
        return None
    if is_suspicious_location(exe):
        return _flag("R01", f"可执行文件路径：{exe}")
    return None


def _check_r02_signature(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    info = node.info
    # 系统目录内大量文件使用 catalog 签名，阶段 1A 不对其下"无签名"结论
    if not info.exe or whitelist.is_trusted_path(info.exe):
        return None
    if info.sig_status is SigStatus.INVALID:
        return _flag("R02B", "签名校验失败")
    if info.sig_status is SigStatus.SIGNED_UNTRUSTED:
        return _flag("R02C", "签名状态：已签名但不受信任/已过期")
    if info.sig_status is SigStatus.UNSIGNED:
        return _flag("R02", "签名状态：未签名")
    return None


def _check_r03_orphan(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    if not node.orphaned:
        return None
    info = node.info
    if info.exe and whitelist.is_trusted_path(info.exe):
        return None
    if info.name.casefold() in _ORPHAN_PRONE_NAMES:
        return None
    if node.parent_pid_reused:
        return _flag("R03", f"ppid={info.ppid} 已被其它进程复用（父进程创建时间晚于本进程）")
    return _flag("R03", f"ppid={info.ppid} 不在当前进程快照中")


def _check_r04_masquerade(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    info = node.info
    expected = expected_paths_for(info.name)
    if not expected or not info.exe:
        return None
    if normalize_path(info.exe) in expected:
        return None
    return _flag("R04", f"进程名 {info.name} 的真实路径为 {info.exe}（预期 {expected[0]}）")


def _check_r05_parent(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    info = node.info
    expected_parents = _EXPECTED_PARENT_NAMES.get(info.name.casefold())
    if not expected_parents or not info.exe:
        return None
    if normalize_path(info.exe) not in expected_paths_for(info.name):
        return None  # 路径异常由 R04 处理，这里只判断真实系统二进制的父子关系
    parent = _parent_node(node, tree)
    if parent is None:
        return None  # 父进程不可见，无法下结论
    if parent.info.name.casefold() in expected_parents:
        return None
    expected_text = "/".join(sorted(expected_parents))
    return _flag(
        "R05",
        f"{info.name} 的父进程是 {parent.info.display_name}({parent.pid})，预期为 {expected_text}",
    )


def _check_r06_cmdline(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    info = node.info
    text = info.cmdline_text
    if not text:
        return None
    strong = [label for label, pattern in _STRONG_CMDLINE_PATTERNS if pattern.search(text)]
    weak = [label for label, pattern in _WEAK_CMDLINE_PATTERNS if pattern.search(text)]
    if not strong and len(weak) < 2:
        return None
    labels = "、".join(strong + weak[:2])
    evidence = f"命中：{labels}；命令行：{redact_cmdline(info.cmdline, enabled=True, max_chars=160)}"
    parent = _parent_node(node, tree)
    parent_trusted = bool(parent and parent.info.exe and whitelist.is_trusted_path(parent.info.exe))
    if whitelist.is_trusted_path(info.exe) and parent_trusted:
        # 系统二进制 + 受信父进程（常见于计划任务/系统脚本）→ 降级为"关注"
        return _flag(
            "R06",
            evidence,
            severity=Severity.NOTICE,
            weight=8,
            title="命令行包含可疑参数（系统路径，已降级为关注）",
        )
    return _flag("R06", evidence)


def _check_r07_lineage(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    parent = _parent_node(node, tree)
    if parent is None:
        return None
    child_name = node.info.name.casefold()
    if child_name not in _SHELL_SPAWN_CHILD_NAMES:
        return None
    parent_name = parent.info.name.casefold()
    if parent_name in _OFFICE_PDF_IM_PARENTS:
        return _flag(
            "R07",
            f"{parent.info.display_name}({parent.pid}) → {node.info.display_name}({node.pid})",
        )
    return None


def _check_r07b_browser_spawn(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    parent = _parent_node(node, tree)
    if parent is None:
        return None
    if node.info.name.casefold() not in _SHELL_SPAWN_CHILD_NAMES:
        return None
    if parent.info.name.casefold() in _BROWSER_PARENTS:
        return _flag(
            "R07B",
            f"{parent.info.display_name}({parent.pid}) → {node.info.display_name}({node.pid})（常见于更新/扩展，需人工核实）",
        )
    return None


def _check_r09_unc(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    exe = node.info.exe
    if not exe:
        return None
    if exe.startswith("\\\\") or exe.casefold().startswith("\\\\?\\unc\\"):
        return _flag("R09", f"可执行文件路径：{exe}")
    return None


def _check_r10_name_mismatch(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    info = node.info
    if not info.exe or not info.name:
        return None
    basename = os.path.basename(info.exe).casefold()
    # 部分 Windows API 会截断进程名为 15 字符，所以用 startswith 做宽容匹配
    if basename and not basename.startswith(info.name.casefold()):
        return _flag("R10", f"name={info.name}，但 exe={info.exe}")
    return None


def _check_r11_access(node: ProcessNode, tree: ProcessTree, whitelist: Whitelist) -> RiskFlag | None:
    errors = node.info.access_errors
    if not errors:
        return None
    return _flag("R11", "不可读字段：" + "、".join(errors[:4]))


Check = Callable[[ProcessNode, ProcessTree, Whitelist], RiskFlag | None]

_CHECKS: tuple[Check, ...] = (
    _check_r01_location,
    _check_r02_signature,
    _check_r03_orphan,
    _check_r04_masquerade,
    _check_r05_parent,
    _check_r06_cmdline,
    _check_r07_lineage,
    _check_r07b_browser_spawn,
    _check_r09_unc,
    _check_r10_name_mismatch,
    _check_r11_access,
)


def analyze_tree(tree: ProcessTree, whitelist: Whitelist) -> None:
    """对整棵树执行启发式评分（原地写入 ``node.flags/score/risk``）。"""

    for node in tree.nodes.values():
        flags: list[RiskFlag] = []
        for check in _CHECKS:
            try:
                flag = check(node, tree, whitelist)
            except Exception:  # noqa: BLE001 - 单条规则失败不阻断其它规则
                logger.exception("规则 %s 评估失败（pid=%s）", check.__name__, node.info.pid)
                continue
            if flag is not None:
                flags.append(flag)
        node.flags = flags
        node.score = sum(flag.weight for flag in flags)
        highest = max((flag.severity for flag in flags), default=Severity.INFO)
        node.risk = Severity(max(int(risk_of_score(node.score)), int(highest)))

    flagged = len(tree.flagged_nodes())
    suspicious = tree.count_at_least(Severity.SUSPICIOUS)
    logger.info("风险评分完成：命中 %d 个进程，其中可疑及以上 %d 个", flagged, suspicious)
