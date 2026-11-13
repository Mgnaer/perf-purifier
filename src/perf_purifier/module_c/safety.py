"""模块 C 安全核心：路径归一、受保护路径、删除前身份重验。

与模块 A/B 的 ``core/whitelist.py`` 共享路径归一化口径，并针对「磁盘清理」补充：

1. **受保护路径段序列**：WinSxS / System32\\config / drivers / WindowsApps /
   System Volume Information / $Recycle.Bin / Boot / EFI / Recovery 等，
   任何规则都不得越过；匹配按路径段序列进行，避免 ``C:\\Users\\x\\bootleg`` 误伤；
2. **用户数据区永不禁用**：桌面/文档/下载/图片/音乐/视频（含被重定向后的真实位置）
   一律拒绝删除，即使规则配置出错也一样；
3. **不跟随重解析点**：符号链接/junction 一律拒绝（扫描时也不统计）；
4. **Defender 旧平台专用判定**：只允许删除「Platform 目录下、非最新版本、
   非 CurrentVersion 链接」的目录。
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from functools import lru_cache

from ..core.whitelist import is_under as _core_is_under
from ..core.whitelist import normalize_path as _core_normalize_path
from ..core.winapi import FILE_ATTRIBUTE_REPARSE_POINT, get_file_attributes, is_admin, is_reparse_point

IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- 路径
def normalize_path(path: str | None) -> str:
    """与 core.whitelist 同口径，但把卷根也归一化为 ``c:``（便于边界匹配）。"""

    normalized = _core_normalize_path(path)
    if len(normalized) == 3 and normalized.endswith(os.sep):
        return normalized.rstrip(os.sep)
    return normalized


def path_segments(path: str | None) -> tuple[str, ...]:
    """路径拆分（小写、去掉空段），用于精确的序列匹配。"""

    return tuple(part for part in normalize_path(path).split(os.sep) if part)


def is_under(path: str | None, roots: tuple[str, ...] | list[str]) -> bool:
    """目录边界匹配（复用 core.whitelist 实现，入参先做本模块归一化）。"""

    normalized = normalize_path(path)
    if not normalized:
        return False
    return _core_is_under(normalized, tuple(normalize_path(root) for root in roots))


def to_long_path(path: str | None) -> str:
    """把 8.3 短路径解析成长路径（失败时返回原路径）。"""

    if not path:
        return ""
    try:
        real = os.path.realpath(path)
    except (OSError, ValueError):
        return path
    if real.startswith("\\\\?\\UNC\\"):
        real = "\\\\" + real[8:]
    elif real.startswith("\\\\?\\"):
        real = real[4:]
    return real


def canonical_key(path: str | None) -> str:
    """物理路径去重键：解析短名/链接后归一化（用于跨规则去重）。"""

    return normalize_path(to_long_path(path)) if path else ""


def is_drive_root(path: str | None) -> bool:
    normalized = normalize_path(path)
    stripped = normalized.rstrip("\\")
    return len(stripped) == 2 and stripped[1] == ":"


def drive_root_of(path: str) -> str:
    try:
        drive, _ = os.path.splitdrive(os.path.abspath(path))
    except (OSError, ValueError):
        return ""
    return (drive + os.sep) if drive else ""


def is_cloud_placeholder(path: str) -> bool:
    """云占位文件（读取会触发下载，扫描时跳过）。"""

    from ..core.winapi import (
        FILE_ATTRIBUTE_OFFLINE,
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_RECALL_ON_OPEN,
    )

    attributes = get_file_attributes(path)
    if attributes is None:
        return False
    mask = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    return bool(attributes & mask)


def stat_attributes(stat_result: os.stat_result) -> int:
    return int(getattr(stat_result, "st_file_attributes", 0) or 0)


def stat_is_reparse(stat_result: os.stat_result) -> bool:
    return bool(stat_attributes(stat_result) & FILE_ATTRIBUTE_REPARSE_POINT)


# --------------------------------------------------------------------------- 保护
FORBIDDEN_SEQUENCES: tuple[tuple[str, ...], ...] = (
    ("system volume information",),
    ("$recycle.bin",),
    ("windows", "winsxs"),
    ("windows", "system32", "config"),
    ("windows", "system32", "drivers"),
    ("windows", "system32", "catroot"),
    ("windows", "system32", "catroot2"),
    ("windows", "system32", "driverstore"),
    ("windows", "system32", "logfiles"),
    ("windows", "assembly"),
    ("windows", "boot"),
    ("windows", "systemapps"),
    ("windows", "servicing", "packages"),
    ("boot",),
    ("efi",),
    ("recovery",),
    ("program files", "windowsapps"),
    ("programdata", "microsoft", "windows defender", "platform"),
    ("programdata", "microsoft", "crypto"),
    ("programdata", "microsoft", "systemcertificates"),
)
"""任何规则都不得越过的受保护路径段序列。

``...\\Windows Defender\\Platform`` 也在此列：Defender 旧平台清理走
:func:`is_defender_platform_old_version` 专用通道，而不是通用路径删除。
"""


def _contains_sequence(segments: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    if not sequence or len(sequence) > len(segments):
        return False
    for start in range(len(segments) - len(sequence) + 1):
        if segments[start : start + len(sequence)] == sequence:
            return True
    return False


def find_forbidden(path: str | None) -> tuple[str, ...] | None:
    """返回命中的受保护路径序列；未命中返回 ``None``。"""

    segments = path_segments(path)
    if not segments:
        return None
    for sequence in FORBIDDEN_SEQUENCES:
        if _contains_sequence(segments, sequence):
            return sequence
    return None


def _known_folder_value(raw: str) -> str:
    expanded = os.path.expandvars(raw)
    try:
        return os.path.abspath(expanded)
    except (OSError, ValueError):
        return expanded


@lru_cache(maxsize=1)
def known_user_data_roots() -> tuple[str, ...]:
    """用户数据目录（桌面/文档/下载/图片/音乐/视频 + OneDrive），永不允许删除。

    通过 ``HKCU`` 的 *User Shell Folders* 读取真实位置（兼容桌面/文档被重定向到
    其他盘的情况）；卷根因范围过大被排除。
    """

    raw_values: list[str] = []
    try:
        import winreg  # noqa: PLC0415 - 仅 Windows 可用，延迟导入

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            for index in range(64):
                try:
                    name, value, _kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                if not isinstance(value, str) or not value.strip():
                    continue
                folded = name.casefold()
                if (
                    "desktop" in folded
                    or "personal" in folded
                    or "download" in folded
                    or "picture" in folded
                    or "music" in folded
                    or "video" in folded
                    or "{374de290-123f-4565-9164-39c4925e467b}" in folded
                    or "{f42ee2d3-909f-4907-8871-4c22fc0bf756}" in folded
                    or "{4c5c32ff-bb9d-43b0-b5b4-2d72e54eaaa4}" in folded
                ):
                    raw_values.append(value)
    except (OSError, ImportError, AttributeError):
        pass

    profile = os.environ.get("USERPROFILE")
    if profile:
        for sub in ("Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos", "OneDrive"):
            raw_values.append(os.path.join(profile, sub))

    roots: list[str] = []
    for raw in raw_values:
        candidate = normalize_path(_known_folder_value(raw))
        if not candidate or is_drive_root(candidate) or candidate in roots:
            continue
        roots.append(candidate)
    return tuple(roots)


# --------------------------------------------------------------------------- 校验
@dataclass(frozen=True, slots=True)
class DeletableCheck:
    """删除前检查结果；``ok=False`` 时 ``code`` 为稳定错误码（写入审计）。"""

    ok: bool
    code: str = ""
    detail: str = ""


def check_deletable(
    path: str,
    allowed_root: str,
    *,
    expected_size: int | None = None,
    expected_mtime: float | None = None,
) -> DeletableCheck:
    """执行前最后一道闸门：路径/受保护/用户数据/重解析点/身份一致性。"""

    if not path:
        return DeletableCheck(False, "invalid_path", "路径为空")
    normalized = normalize_path(path)
    if not normalized:
        return DeletableCheck(False, "invalid_path", "路径无法归一化")
    if is_drive_root(normalized):
        return DeletableCheck(False, "drive_root", "拒绝对卷根执行删除")
    if not os.path.exists(normalized):
        return DeletableCheck(False, "stale", "目标已不存在（扫描后发生变化）")
    if not is_under(normalized, (allowed_root,)):
        return DeletableCheck(False, "outside_root", "目标不在规则声明的根目录内")

    marker = find_forbidden(normalized)
    if marker is not None:
        return DeletableCheck(False, "protected_path", "命中受保护路径：" + "\\".join(marker))
    if is_under(normalized, known_user_data_roots()):
        return DeletableCheck(False, "user_data", "目标位于用户数据目录，永不删除")

    reparse = is_reparse_point(normalized)
    if reparse is True:
        return DeletableCheck(False, "reparse_point", "目标为符号链接/junction，拒绝删除")
    if reparse is None:
        return DeletableCheck(False, "unreadable", "无法确认目标属性（权限不足）")

    try:
        stat_result = os.stat(normalized, follow_symlinks=False)
    except OSError as exc:
        return DeletableCheck(False, "stat_failed", f"{type(exc).__name__}: {exc}")

    if expected_size is not None and int(stat_result.st_size) != int(expected_size):
        return DeletableCheck(
            False, "identity_changed", f"大小已变化（扫描 {expected_size} B，当前 {stat_result.st_size} B）"
        )
    if expected_mtime is not None and expected_mtime > 0:
        if int(stat_result.st_mtime) != int(expected_mtime):
            return DeletableCheck(False, "identity_changed", "修改时间已变化，请重新扫描")
    return DeletableCheck(True)


# --------------------------------------------------------------------------- Defender
def defender_platform_dir() -> str:
    program_data = os.environ.get("ProgramData") or r"C:\ProgramData"
    return os.path.join(program_data, "Microsoft", "Windows Defender", "Platform")


def is_defender_platform_old_version(path: str, *, keep_newest: bool = True) -> bool:
    """判断 ``path`` 是否为可清理的 Defender 旧平台版本目录。"""

    parent = normalize_path(defender_platform_dir())
    normalized = normalize_path(path)
    if not normalized or not parent:
        return False
    if os.path.dirname(normalized) != parent:
        return False
    name = os.path.basename(normalized)
    if not name or name.casefold() == "currentversion":
        return False
    if is_reparse_point(normalized) is not False:
        return False
    if not keep_newest:
        return True
    try:
        siblings = [
            entry
            for entry in os.scandir(parent)
            if entry.is_dir(follow_symlinks=False) and entry.name.casefold() != "currentversion"
        ]
    except OSError:
        return False

    def version_key(entry: os.DirEntry[str]) -> tuple[int, ...]:
        parts: list[int] = []
        for chunk in entry.name.split("-")[0].split("."):
            try:
                parts.append(int(chunk))
            except ValueError:
                parts.append(0)
        while len(parts) < 4:
            parts.append(0)
        return tuple(parts)

    directories = [entry for entry in siblings if is_reparse_point(entry.path) is not True]
    if not directories:
        return False
    newest = max(directories, key=version_key)
    return normalize_path(newest.path) != normalized


# --------------------------------------------------------------------------- 回收站
SHFILEOP_FLAGS_ALLOWUNDO = 0x0040
SHFILEOP_FLAGS_NOCONFIRMATION = 0x0010
SHFILEOP_FLAGS_SILENT = 0x0004
SHFILEOP_FLAGS_NOERRORUI = 0x0400


def _shell32():
    if not IS_WINDOWS:
        return None
    try:
        return ctypes.WinDLL("shell32", use_last_error=True)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None


def query_recycle_bin(drive_root: str) -> tuple[int, int]:
    """返回 C 盘回收站 ``(条目数, 字节数)``；查询失败返回 ``(0, 0)``。"""

    if not IS_WINDOWS:
        return 0, 0
    try:
        from ctypes import wintypes  # noqa: PLC0415 - 仅 Windows

        class _SHQUERYRBINFO(ctypes.Structure):  # noqa: N801 - Win32 命名
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("i64Size", ctypes.c_longlong),
                ("i64NumItems", ctypes.c_longlong),
            ]

        shell32 = _shell32()
        if shell32 is None:
            return 0, 0
        shell32.SHQueryRecycleBinW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SHQUERYRBINFO)]
        shell32.SHQueryRecycleBinW.restype = ctypes.c_long
        info = _SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(_SHQUERYRBINFO)
        code = int(shell32.SHQueryRecycleBinW(drive_root, ctypes.byref(info)))
        if code != 0:
            return 0, 0
        return int(info.i64NumItems), int(info.i64Size)
    except (AttributeError, OSError, ValueError):
        return 0, 0


def empty_recycle_bin(drive_root: str) -> tuple[bool, str]:
    """清空指定卷回收站；返回 ``(是否成功, 说明)``。"""

    if not IS_WINDOWS:
        return False, "仅 Windows 支持"
    try:
        from ctypes import wintypes  # noqa: PLC0415

        shell32 = _shell32()
        if shell32 is None:
            return False, "无法加载 shell32"
        shell32.SHEmptyRecycleBinW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.DWORD]
        shell32.SHEmptyRecycleBinW.restype = ctypes.c_long
        flags = 0x1 | 0x2 | 0x4  # 不确认 / 不显示进度 / 不播声音
        result = int(shell32.SHEmptyRecycleBinW(None, drive_root, flags))
    except (AttributeError, OSError, ValueError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if result != 0:
        return False, f"清空回收站失败（代码 0x{result:X}）"
    return True, "回收站已清空"


__all__ = [
    "DeletableCheck",
    "FORBIDDEN_SEQUENCES",
    "IS_WINDOWS",
    "canonical_key",
    "check_deletable",
    "defender_platform_dir",
    "drive_root_of",
    "empty_recycle_bin",
    "find_forbidden",
    "is_admin",
    "is_cloud_placeholder",
    "is_defender_platform_old_version",
    "is_drive_root",
    "is_reparse_point",
    "is_under",
    "known_user_data_roots",
    "normalize_path",
    "path_segments",
    "query_recycle_bin",
    "stat_attributes",
    "stat_is_reparse",
    "to_long_path",
]
