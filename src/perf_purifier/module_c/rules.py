"""模块 C 垃圾规则库。

设计原则（与模块 A/B 的「动作白名单」一致）：
* **规则是唯一删除来源**，不存在"用户输入任意路径就删"的入口；
* 每条规则显式声明 ``mode``（清空目录内容 / 删除整个目录 / 删除匹配文件 / 专用通道）
  与 ``risk``（safe / caution / system），GUI 默认只勾选 safe；
* 根目录支持 ``%ENV%`` 与末段 ``*`` 通配（用于 ``*-updater``、``User Data\\*\\Cache``）；
* 用户数据（文档/桌面/聊天记录/存档）不在任何规则范围内；
* :func:`validate_rules` 在测试中强制校验，防止后续手滑加入危险规则。
"""

from __future__ import annotations

import glob
import os

from .models import (
    MODE_CHILDREN,
    MODE_FILES,
    MODE_SPECIAL,
    MODE_TREE,
    RISK_CAUTION,
    RISK_ORDER,
    RISK_SAFE,
    RISK_SYSTEM,
    JunkRule,
)
from .safety import (
    canonical_key,
    defender_platform_dir,
    find_forbidden,
    is_drive_root,
    is_reparse_point,
    is_under,
    known_user_data_roots,
    to_long_path,
)

# 允许作为规则根的系统目录（除此之外，Windows 目录下一律不许碰）
SYSTEM_ROOT_ALLOWLIST: tuple[str, ...] = (
    r"%SystemRoot%\Temp",
    r"%SystemRoot%\SoftwareDistribution\Download",
    r"%SystemRoot%\servicing\LCU",
    r"%SystemRoot%\Panther",
    r"%SystemRoot%\Logs\CBS",
    r"%SystemRoot%\Minidump",
    r"%SystemRoot%\LiveKernelReports",
    r"%SystemRoot%\System32",
    r"%SystemRoot%\SysWOW64",
)

# 厂商/工具安装包残留目录（按需存在的固定位置）
VENDOR_ROOT_ALLOWLIST: tuple[str, ...] = (
    r"C:\DrvPath",
    r"C:\KDubaSoftDownloads",
)


# --------------------------------------------------------------------------- 规则表
RULES: tuple[JunkRule, ...] = (
    # ---------------------------------------------------------------- 临时文件
    JunkRule(
        id="temp_user",
        name="用户临时文件",
        category="临时文件",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%TEMP%", r"%TMP%", r"%LOCALAPPDATA%\Temp"),
        note="应用运行产生的临时文件；正在使用的文件会被占用而自动跳过",
    ),
    JunkRule(
        id="temp_shared",
        name="共享内存临时区",
        category="临时文件",
        risk=RISK_CAUTION,
        mode=MODE_CHILDREN,
        roots=(r"%ProgramData%\boost_interprocess",),
        note="跨进程共享内存文件，通常被运行中的程序锁定，能清掉的很少",
    ),
    JunkRule(
        id="inetcache",
        name="IE/系统网络缓存",
        category="临时文件",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%LOCALAPPDATA%\Microsoft\Windows\INetCache",),
    ),
    JunkRule(
        id="pip_cache",
        name="pip 下载缓存",
        category="临时文件",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%LOCALAPPDATA%\pip\Cache",),
        note="删除后不影响已安装的包，只影响重复安装时的下载速度",
    ),
    # ---------------------------------------------------------------- 更新与安装残留
    JunkRule(
        id="updater_caches",
        name="应用更新包缓存",
        category="更新与安装残留",
        risk=RISK_SAFE,
        mode=MODE_TREE,
        roots=(r"%LOCALAPPDATA%\*-updater",),
        note="各类客户端的自我更新下载包，删除后可重新下载",
    ),
    JunkRule(
        id="epic_update_cache",
        name="Epic 启动器更新缓存",
        category="更新与安装残留",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%ProgramData%\Epic\EpicGamesLauncher\Data\Update",),
    ),
    JunkRule(
        id="office_solution_packages",
        name="Office 解决方案包缓存",
        category="更新与安装残留",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%LOCALAPPDATA%\Microsoft\Office\SolutionPackages",),
        note="Office 加载项的离线包，按需会重新下载",
    ),
    JunkRule(
        id="vendor_driver_archives",
        name="厂商驱动/软件安装包",
        category="更新与安装残留",
        risk=RISK_CAUTION,
        mode=MODE_CHILDREN,
        roots=VENDOR_ROOT_ALLOWLIST,
        note="驱动与工具安装包的备份；删除后重装驱动需要重新下载",
    ),
    JunkRule(
        id="win_update_cache",
        name="Windows 更新下载缓存",
        category="更新与安装残留",
        risk=RISK_SYSTEM,
        mode=MODE_CHILDREN,
        roots=(r"%SystemRoot%\SoftwareDistribution\Download",),
        requires_admin=True,
    ),
    JunkRule(
        id="win_lcu_cache",
        name="Windows 更新包解压缓存",
        category="更新与安装残留",
        risk=RISK_SYSTEM,
        mode=MODE_TREE,
        roots=(r"%SystemRoot%\servicing\LCU",),
        requires_admin=True,
        note="最近的累积更新解压副本；删除后如再安装更新会重新解压",
    ),
    JunkRule(
        id="win_setup_temp",
        name="Windows 安装临时文件",
        category="更新与安装残留",
        risk=RISK_SYSTEM,
        mode=MODE_FILES,
        roots=(r"%SystemRoot%\System32", r"%SystemRoot%\SysWOW64"),
        file_globs=("SET*.tmp",),
        requires_admin=True,
        note="系统升级遗留的临时文件，通常锁定后只剩少部分可删",
    ),
    JunkRule(
        id="win_mrt",
        name="恶意软件删除工具旧文件",
        category="更新与安装残留",
        risk=RISK_SYSTEM,
        mode=MODE_FILES,
        roots=(r"%SystemRoot%\System32",),
        file_globs=("MRT.exe",),
        requires_admin=True,
        note="MRT 每月随更新重建；删除不影响 Windows Defender",
    ),
    # ---------------------------------------------------------------- 浏览器与客户端缓存
    JunkRule(
        id="edge_cache",
        name="Edge 浏览器缓存",
        category="浏览器缓存",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(
            r"%LOCALAPPDATA%\Microsoft\Edge\User Data\*\Cache",
            r"%LOCALAPPDATA%\Microsoft\Edge\User Data\*\Code Cache",
            r"%LOCALAPPDATA%\Microsoft\Edge\User Data\*\GPUCache",
            r"%LOCALAPPDATA%\Microsoft\Edge\User Data\*\Service Worker\CacheStorage",
        ),
        note="只清缓存，不动书签/密码/历史记录",
    ),
    JunkRule(
        id="chrome_cache",
        name="Chrome 浏览器缓存",
        category="浏览器缓存",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(
            r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache",
            r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Code Cache",
            r"%LOCALAPPDATA%\Google\Chrome\User Data\*\GPUCache",
        ),
        note="只清缓存，不动书签/密码/历史记录",
    ),
    JunkRule(
        id="firefox_cache",
        name="Firefox 浏览器缓存",
        category="浏览器缓存",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2",),
    ),
    JunkRule(
        id="b360_browser_cache",
        name="第三方浏览器缓存（360/QQ 等）",
        category="浏览器缓存",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(
            r"%LOCALAPPDATA%\360Chrome\Chrome\User Data\*\Cache",
            r"%LOCALAPPDATA%\Tencent\QQBrowser\User Data\*\Cache",
        ),
    ),
    JunkRule(
        id="electron_app_caches",
        name="桌面客户端缓存（B站/抖音/网易/加速器）",
        category="浏览器缓存",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(
            r"%APPDATA%\bilibili\Cache",
            r"%APPDATA%\bilibili\Code Cache",
            r"%APPDATA%\bilibili\GPUCache",
            r"%APPDATA%\douyin\Cache",
            r"%APPDATA%\douyin\Code Cache",
            r"%APPDATA%\douyin\GPUCache",
            r"%APPDATA%\Netease\Cache",
            r"%APPDATA%\leigod\Cache",
            r"%APPDATA%\leigod\Code Cache",
            r"%APPDATA%\QQ\Cache",
            r"%APPDATA%\QQ\GPUCache",
        ),
        note="Electron 类客户端的网页缓存；清空后不影响账号、聊天记录与收藏",
    ),
    # ---------------------------------------------------------------- 游戏缓存
    JunkRule(
        id="game_hogwarts_shaders",
        name="霍格沃茨之遗着色器缓存",
        category="游戏缓存",
        risk=RISK_CAUTION,
        mode=MODE_TREE,
        roots=(r"%ProgramData%\Hogwarts Legacy",),
        note="删除后首次进入游戏会重新编译着色器，略慢",
    ),
    JunkRule(
        id="game_forza_scratch",
        name="极限竞速地平线图形缓存",
        category="游戏缓存",
        risk=RISK_CAUTION,
        mode=MODE_TREE,
        roots=(r"%LOCALAPPDATA%\ForzaHorizon4\scratch", r"%LOCALAPPDATA%\ForzaHorizon5\scratch"),
        note="赛道/车辆图形缓存，重新载入时自动重建",
    ),
    JunkRule(
        id="game_bf5_shaders",
        name="战地5 着色器缓存",
        category="游戏缓存",
        risk=RISK_CAUTION,
        mode=MODE_CHILDREN,
        roots=(r"%LOCALAPPDATA%\Battlefield V\shaders",),
    ),
    JunkRule(
        id="gpu_shader_caches",
        name="显卡着色器缓存",
        category="游戏缓存",
        risk=RISK_CAUTION,
        mode=MODE_CHILDREN,
        roots=(
            r"%LOCALAPPDATA%\NVIDIA\DXCache",
            r"%LOCALAPPDATA%\NVIDIA\GLCache",
            r"%LOCALAPPDATA%\D3DSCache",
            r"%ProgramData%\AMD\DxCache",
            r"%ProgramData%\AMD\DxcCache",
        ),
        note="部分文件被显卡驱动锁定，清理时会被自动跳过",
    ),
    JunkRule(
        id="game_uagame_cdn",
        name="UAGame 下载缓存",
        category="游戏缓存",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%LOCALAPPDATA%\UAGame\Saved\CDNCached",),
    ),
    # ---------------------------------------------------------------- 启动器缓存
    JunkRule(
        id="steam_htmlcache",
        name="Steam 网页缓存",
        category="启动器缓存",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%LOCALAPPDATA%\Steam\htmlcache",),
        note="不影响游戏文件与账号",
    ),
    JunkRule(
        id="ea_ac_cache",
        name="EA 反作弊组件缓存",
        category="启动器缓存",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%APPDATA%\EA\AC\Cache",),
    ),
    # ---------------------------------------------------------------- 崩溃与日志
    JunkRule(
        id="user_crash_dumps",
        name="程序崩溃转储",
        category="崩溃与日志",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(r"%LOCALAPPDATA%\CrashDumps",),
        note="崩溃分析文件，普通用户无需保留",
    ),
    JunkRule(
        id="user_wer_reports",
        name="用户错误报告",
        category="崩溃与日志",
        risk=RISK_SAFE,
        mode=MODE_CHILDREN,
        roots=(
            r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive",
            r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue",
        ),
    ),
    JunkRule(
        id="machine_wer_reports",
        name="系统错误报告",
        category="崩溃与日志",
        risk=RISK_SYSTEM,
        mode=MODE_CHILDREN,
        roots=(r"%ProgramData%\Microsoft\Windows\WER",),
        requires_admin=True,
    ),
    JunkRule(
        id="win_minidump",
        name="系统小内存转储",
        category="崩溃与日志",
        risk=RISK_SYSTEM,
        mode=MODE_CHILDREN,
        roots=(r"%SystemRoot%\Minidump", r"%SystemRoot%\LiveKernelReports"),
        requires_admin=True,
    ),
    JunkRule(
        id="win_cbs_logs",
        name="系统组件安装日志",
        category="崩溃与日志",
        risk=RISK_SYSTEM,
        mode=MODE_CHILDREN,
        roots=(r"%SystemRoot%\Logs\CBS",),
        requires_admin=True,
    ),
    JunkRule(
        id="win_panther",
        name="Windows 安装/升级日志",
        category="崩溃与日志",
        risk=RISK_SYSTEM,
        mode=MODE_CHILDREN,
        roots=(r"%SystemRoot%\Panther",),
        requires_admin=True,
    ),
    JunkRule(
        id="win_temp",
        name="Windows 临时文件",
        category="崩溃与日志",
        risk=RISK_SYSTEM,
        mode=MODE_CHILDREN,
        roots=(r"%SystemRoot%\Temp",),
        requires_admin=True,
    ),
    # ---------------------------------------------------------------- 缩略图
    JunkRule(
        id="thumbnails",
        name="缩略图与图标缓存",
        category="缩略图缓存",
        risk=RISK_CAUTION,
        mode=MODE_FILES,
        roots=(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer",),
        file_globs=("thumbcache_*.db", "iconcache_*.db"),
        note="资源管理器占用中，能删掉的通常只是一部分；删后缩略图会重建",
    ),
    # ---------------------------------------------------------------- 专用通道
    JunkRule(
        id="defender_old_platforms",
        name="Defender 旧平台版本",
        category="系统组件",
        risk=RISK_SYSTEM,
        mode=MODE_SPECIAL,
        roots=(r"%ProgramData%\Microsoft\Windows Defender\Platform",),
        requires_admin=True,
        special="defender_platforms",
        note="保留最新版本，删除更早的平台目录",
    ),
    JunkRule(
        id="recycle_bin",
        name="回收站",
        category="回收站",
        risk=RISK_CAUTION,
        mode=MODE_SPECIAL,
        roots=(),
        special="recycle_bin",
        note="清空后文件不可恢复，请确认没有需要找回的内容",
    ),
)

RULES_BY_ID: dict[str, JunkRule] = {rule.id: rule for rule in RULES}


# --------------------------------------------------------------------------- 解析
def expand_root_template(template: str) -> str:
    """展开环境变量；无法解析的模板返回空串。"""

    if not template:
        return ""
    expanded = os.path.expandvars(template)
    if "%" in expanded or "$" in expanded:
        return ""
    return expanded


def resolve_roots(rule: JunkRule) -> list[str]:
    """把规则的根模板解析成真实存在的目录（去重、跳过重解析点、用长路径显示）。"""

    roots: list[str] = []
    seen: set[str] = set()
    for template in rule.roots:
        expanded = expand_root_template(template)
        if not expanded:
            continue
        candidates = glob.glob(expanded) if any(char in expanded for char in "*?[") else [expanded]
        for candidate in candidates:
            try:
                if not os.path.isdir(candidate):
                    continue
            except OSError:
                continue
            if is_reparse_point(candidate) is True:
                continue
            key = canonical_key(candidate)
            if not key or key in seen:
                continue
            seen.add(key)
            roots.append(to_long_path(candidate))
    return roots


def rules_by_category() -> dict[str, list[JunkRule]]:
    grouped: dict[str, list[JunkRule]] = {}
    for rule in RULES:
        grouped.setdefault(rule.category, []).append(rule)
    return grouped


def select_rules(
    *,
    include_caution: bool = False,
    include_system: bool = False,
) -> list[JunkRule]:
    """按用户勾选的风险等级挑选规则（system 规则仍会返回，由执行层要求管理员）。"""

    allowed = {RISK_SAFE}
    if include_caution:
        allowed.add(RISK_CAUTION)
    if include_system:
        allowed.add(RISK_SYSTEM)
    return [rule for rule in RULES if rule.risk in allowed]


def default_checked_risk() -> str:
    return RISK_SAFE


def risk_sort_key(risk: str) -> int:
    return RISK_ORDER.get(risk, 99)


# --------------------------------------------------------------------------- 自检
def _system_allowlist_resolved() -> tuple[str, ...]:
    resolved: list[str] = []
    for template in SYSTEM_ROOT_ALLOWLIST:
        expanded = expand_root_template(template)
        if expanded:
            resolved.append(expanded)
    return tuple(resolved)


def validate_rules() -> list[str]:
    """规则库自检：返回问题列表（空列表 = 通过）。测试中强制断言为空。"""

    problems: list[str] = []
    seen_ids: set[str] = set()
    user_data = known_user_data_roots()
    system_allow = tuple(os.path.normcase(os.path.normpath(item)) for item in _system_allowlist_resolved())
    special_exempt = {"recycle_bin", "defender_platforms"}

    for rule in RULES:
        if rule.id in seen_ids:
            problems.append(f"[{rule.id}] 规则 id 重复")
        seen_ids.add(rule.id)
        if rule.risk not in RISK_ORDER:
            problems.append(f"[{rule.id}] 非法风险等级：{rule.risk}")
        if rule.mode not in {"children", "tree", "files", "special"}:
            problems.append(f"[{rule.id}] 非法模式：{rule.mode}")
        if not rule.roots:
            if rule.special not in special_exempt:
                problems.append(f"[{rule.id}] 未声明根目录")
            continue
        if rule.mode == MODE_FILES and not rule.file_globs:
            problems.append(f"[{rule.id}] files 模式未声明 file_globs")
        for template in rule.roots:
            expanded = expand_root_template(template)
            if not expanded:
                problems.append(f"[{rule.id}] 根模板无法展开：{template}")
                continue
            if is_drive_root(expanded):
                problems.append(f"[{rule.id}] 根目录不得是卷根：{expanded}")
            if rule.special not in special_exempt and find_forbidden(expanded) is not None:
                problems.append(f"[{rule.id}] 根目录命中受保护路径：{expanded}")
            if is_under(expanded, user_data):
                problems.append(f"[{rule.id}] 根目录位于用户数据区：{expanded}")
            normalized = os.path.normcase(os.path.normpath(expanded))
            windows_root = os.path.normcase(
                os.path.normpath(os.environ.get("SystemRoot", r"C:\Windows"))
            )
            under_windows = normalized == windows_root or normalized.startswith(
                windows_root + os.sep
            )
            if under_windows and not any(
                normalized == allowed or normalized.startswith(allowed + os.sep)
                for allowed in system_allow
            ):
                problems.append(f"[{rule.id}] Windows 目录根不在系统白名单：{expanded}")
    return problems


__all__ = [
    "RULES",
    "RULES_BY_ID",
    "SYSTEM_ROOT_ALLOWLIST",
    "VENDOR_ROOT_ALLOWLIST",
    "default_checked_risk",
    "defender_platform_dir",
    "expand_root_template",
    "resolve_roots",
    "risk_sort_key",
    "rules_by_category",
    "select_rules",
    "validate_rules",
]
