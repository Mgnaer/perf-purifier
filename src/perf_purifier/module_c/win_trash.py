"""回收站查询/清空（模块 C 用，ctypes 直接调 shell32，不依赖第三方库）。

与 ``core.trash`` 的分工：
* ``core.trash`` 负责"把单个路径移到回收站"（send2trash，可注入记录后端）；
* 本模块只负责"查询回收站大小/条目"与"清空回收站"两个只读/系统级操作。
"""

from __future__ import annotations

import ctypes
import os

IS_WINDOWS = os.name == "nt"

SHERB_NOCONFIRMATION = 0x00000001
SHERB_NOPROGRESSUI = 0x00000002
SHERB_NOSOUND = 0x00000004


def _shell32():
    if not IS_WINDOWS:
        return None
    try:
        return ctypes.WinDLL("shell32", use_last_error=True)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None


def query_recycle_bin(drive_root: str) -> tuple[int, int]:
    """返回回收站 ``(条目数, 字节数)``；查询失败返回 ``(0, 0)``。"""

    if not IS_WINDOWS:
        return 0, 0
    try:
        from ctypes import wintypes  # noqa: PLC0415

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
        flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
        result = int(shell32.SHEmptyRecycleBinW(None, drive_root, flags))
    except (AttributeError, OSError, ValueError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if result != 0:
        return False, f"清空回收站失败（代码 0x{result:X}）"
    return True, "回收站已清空"


__all__ = ["IS_WINDOWS", "empty_recycle_bin", "query_recycle_bin"]
