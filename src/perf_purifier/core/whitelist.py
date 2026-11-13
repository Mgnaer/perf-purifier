"""白名单与受保护清单（安全核心，阶段 2 的动作保护也依赖本模块）。

分清两件事：
1. **分析白名单**（本模块 ``Whitelist``）：抑制启发式误报，比如系统目录里
   大量 catalog 签名文件不应被报"无签名"。
2. **动作黑名单**（``NEVER_TERMINATE_NAMES`` / ``PROTECTED_PATH_MARKERS``）：
   阶段 2 的处置功能"永不触碰"的进程/路径。阶段 1A 只定义并由测试锁定，
   防止后续误用。
"""

from __future__ import annotations

import os
import tempfile
from functools import cache, lru_cache

# 阶段 2 起：结束进程动作永不触碰的进程名（小写）
NEVER_TERMINATE_NAMES: frozenset[str] = frozenset(
    {
        "system",
        "system idle process",
        "registry",
        "memory compression",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "wudfhost.exe",
        "trustedinstaller.exe",
        "msmpeng.exe",
    }
)

# 阶段 2 起：删除动作永不触碰的路径标记
PROTECTED_PATH_MARKERS: tuple[str, ...] = (
    "\\system volume information",
    "\\$recycle.bin",
    "\\windows\\winsxs",
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\system32\\config",
)

# 系统关键进程名 -> 预期所在目录（相对 SystemRoot）。用于识别"同名伪装"。
_SYSTEM32_NAMES: frozenset[str] = frozenset(
    {
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "conhost.exe",
        "taskhostw.exe",
        "spoolsv.exe",
        "sihost.exe",
        "runtimebroker.exe",
        "searchindexer.exe",
        "searchprotocolhost.exe",
        "searchfilterhost.exe",
        "smartscreen.exe",
        "securityhealthservice.exe",
        "lsm.exe",
        "wudfhost.exe",
    }
)
_SYSTEM_ROOT_NAMES: frozenset[str] = frozenset({"explorer.exe", "helppane.exe"})


def normalize_path(path: str | None) -> str:
    """路径归一化：绝对化 + 去掉尾部分隔符 + 小写（Windows 大小写不敏感）。"""

    if not path:
        return ""
    try:
        normalized = os.path.normcase(os.path.abspath(path))
    except (OSError, ValueError):
        return path.casefold()
    return normalized.rstrip("\\") if normalized.endswith("\\") and len(normalized) > 3 else normalized


def is_under(path: str | None, roots: tuple[str, ...]) -> bool:
    """路径是否位于任一根目录之下（按目录边界匹配，防止前缀骗术）。"""

    normalized = normalize_path(path)
    if not normalized:
        return False
    for root in roots:
        if not root:
            continue
        if normalized == root or normalized.startswith(root + os.sep):
            return True
    return False


def _system_root() -> str:
    return os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"


@lru_cache(maxsize=1)
def trusted_path_roots() -> tuple[str, ...]:
    """受信任的安装/系统目录（这些目录下的文件不因"无签名"被标记）。"""

    system_root = _system_root()
    roots: list[str] = [
        system_root,
        os.path.join(system_root, "System32"),
        os.path.join(system_root, "SysWOW64"),
        os.path.join(system_root, "WinSxS"),
    ]
    for env_name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"):
        value = os.environ.get(env_name)
        if value:
            roots.append(value)
    normalized: list[str] = []
    for root in roots:
        candidate = normalize_path(root)
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return tuple(normalized)


@cache
def expected_paths_for(name: str) -> tuple[str, ...]:
    """系统关键进程名的预期完整路径；非关键进程返回空元组。"""

    if not name:
        return ()
    lower_name = name.casefold()
    system_root = _system_root()
    if lower_name in _SYSTEM32_NAMES:
        return (normalize_path(os.path.join(system_root, "System32", lower_name)),)
    if lower_name in _SYSTEM_ROOT_NAMES:
        return (normalize_path(os.path.join(system_root, lower_name)),)
    return ()


@lru_cache(maxsize=1)
def suspicious_location_roots() -> tuple[str, ...]:
    """用户可写、且可执行文件不应长期存在的位置（临时/下载目录）。"""

    candidates: list[str] = []
    for env_name in ("TEMP", "TMP"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(value)
    try:
        candidates.append(tempfile.gettempdir())
    except OSError:
        pass
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(os.path.join(local_app_data, "Temp"))
        candidates.append(os.path.join(local_app_data, "Downloads"))
    profile = os.environ.get("USERPROFILE")
    if profile:
        candidates.append(os.path.join(profile, "Downloads"))
    normalized: list[str] = []
    for candidate in candidates:
        path = normalize_path(candidate)
        if path and path not in normalized:
            normalized.append(path)
    return tuple(normalized)


def is_suspicious_location(path: str | None) -> bool:
    """可执行文件是否位于临时/下载等用户可写目录。"""

    return is_under(path, suspicious_location_roots())


class Whitelist:
    """分析白名单：抑制误报，不做安全担保。"""

    def __init__(
        self,
        extra_paths: list[str] | None = None,
        extra_names: list[str] | None = None,
    ) -> None:
        self._extra_paths: tuple[str, ...] = tuple(
            normalized
            for normalized in (normalize_path(path) for path in (extra_paths or []))
            if normalized
        )
        self._extra_names_lower: frozenset[str] = frozenset(
            name.casefold() for name in (extra_names or []) if name
        )

    @classmethod
    def from_config(cls, config: object) -> Whitelist:
        """从 AppConfig 构造（duck typing，避免循环导入）。"""

        paths = getattr(config, "analysis_whitelist_paths", None) or []
        names = getattr(config, "analysis_whitelist_names", None) or []
        return cls(list(paths), list(names))

    def is_trusted_path(self, path: str | None) -> bool:
        if not path:
            return False
        if is_under(path, trusted_path_roots()):
            return True
        return bool(self._extra_paths) and is_under(path, self._extra_paths)

    def is_extra_name(self, name: str | None) -> bool:
        return bool(name) and name.casefold() in self._extra_names_lower

    def is_expected_system_binary(self, info: object) -> bool:
        """进程名与路径是否匹配预期的系统二进制（用于抑制"孤儿"误报）。"""

        name = getattr(info, "name", "") or ""
        exe = getattr(info, "exe", None)
        if not exe:
            return False
        expected = expected_paths_for(name)
        if expected:
            return normalize_path(exe) in expected
        return self.is_trusted_path(exe)
