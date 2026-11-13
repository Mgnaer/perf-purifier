"""Windows 平台薄封装（ctypes）。

原则：
* 只封装少量、语义明确的 API，不重复造 psutil / pywin32 已有的轮子；
* 所有函数失败时返回 ``None`` / ``False`` 并记录原因由调用方降级，不抛异常。

阶段 1B 新增：只读的"文件是否被占用"探测（``CreateFileW`` 共享模式 0）。
该探测**不会修改文件**，但杀软干扰可能造成误判，调用方必须标注为"可能被占用"。
"""

from __future__ import annotations

import ctypes
import os

from .models import Occupancy

IS_WINDOWS = os.name == "nt"

# Win32 常量（与 winnt.h / winbase.h / winerror.h 对齐）
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_ARCHIVE = 0x00000020
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000

INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

ERROR_ACCESS_DENIED = 5
ERROR_SHARING_VIOLATION = 32
ERROR_LOCK_VIOLATION = 33


def is_admin() -> bool:
    """当前进程是否以管理员（提升）权限运行。"""

    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def get_file_attributes(path: str) -> int | None:
    """读取文件属性位；失败（不存在/无权限）返回 ``None``。"""

    if not IS_WINDOWS or not path:
        return None
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetFileAttributesW.restype = ctypes.c_uint32
        attributes = int(kernel32.GetFileAttributesW(path))
    except (AttributeError, OSError, ValueError):
        return None
    if attributes == INVALID_FILE_ATTRIBUTES:
        return None
    return attributes


def is_reparse_point(path: str) -> bool | None:
    """是否为重解析点（符号链接 / junction / 云占位等）。

    返回 ``None`` 表示无法判定（不存在或无权限），调用方应按"未知"降级处理。
    """

    attributes = get_file_attributes(path)
    if attributes is None:
        return None
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def is_cloud_placeholder(path: str) -> bool:
    """是否为 OneDrive 等云占位文件（读取会触发下载，扫描时应跳过）。"""

    attributes = get_file_attributes(path)
    if attributes is None:
        return False
    mask = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    return bool(attributes & mask)


def to_extended_path(path: str) -> str:
    """把路径转换为 Win32 扩展长度路径（``\\\\?\\`` 前缀），用于超长路径兜底。

    仅在普通 API 失败时作为重试手段，避免 URL/相对路径被误加前缀。
    """

    if not IS_WINDOWS or not path or path.startswith("\\\\?\\"):
        return path
    try:
        absolute = os.path.abspath(path)
    except (OSError, ValueError):
        return path
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
STORAGE_DEVICE_SEEK_PENALTY_PROPERTY = 7
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002


def detect_storage_media(path: str) -> str:
    """探测路径所在卷的介质类型：``"ssd"`` / ``"hdd"`` / ``"unknown"``。

    通过 ``IOCTL_STORAGE_QUERY_PROPERTY``（StorageDeviceSeekPenaltyProperty）判断
    设备是否有寻道惩罚：有 → HDD（并发读会因随机寻道变慢，应串行）；无 → SSD。

    任何失败（非 Windows/UNC 路径/权限/虚拟磁盘不支持）都返回 ``"unknown"``，
    调用方按保守策略处理，绝不因此中断扫描。
    """

    if not IS_WINDOWS or not path:
        return "unknown"
    try:
        drive = os.path.splitdrive(os.path.abspath(path))[0]
        if not drive or drive.startswith("\\\\"):
            return "unknown"
        volume = "\\\\.\\" + drive
        kernel32 = ctypes.windll.kernel32
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(volume, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
        if handle is None or handle == INVALID_HANDLE_VALUE:
            return "unknown"
        try:
            device_io_control = kernel32.DeviceIoControl
            device_io_control.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.c_void_p,
            ]
            device_io_control.restype = ctypes.c_int

            # STORAGE_PROPERTY_QUERY { PropertyId, QueryType, AdditionalParameters[1] }
            query = ctypes.create_string_buffer(12)
            ctypes.memmove(query, ctypes.byref(ctypes.c_uint32(STORAGE_DEVICE_SEEK_PENALTY_PROPERTY)), 4)
            ctypes.memmove(ctypes.byref(query, 4), ctypes.byref(ctypes.c_uint32(0)), 4)
            # DEVICE_SEEK_PENALTY_DESCRIPTOR { Version, IncursSeekPenalty }
            output = ctypes.create_string_buffer(8)
            returned = ctypes.c_uint32(0)
            ok = device_io_control(
                ctypes.c_void_p(handle),
                IOCTL_STORAGE_QUERY_PROPERTY,
                ctypes.cast(query, ctypes.c_void_p),
                12,
                ctypes.cast(output, ctypes.c_void_p),
                8,
                ctypes.byref(returned),
                None,
            )
            if not ok or returned.value < 8:
                return "unknown"
            incurs_seek_penalty = output.raw[4] != 0
            return "hdd" if incurs_seek_penalty else "ssd"
        finally:
            try:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
            except (AttributeError, OSError):
                pass
    except (AttributeError, OSError, ValueError):
        return "unknown"


def get_volume_filesystem(path: str) -> str | None:
    """返回路径所在卷的文件系统名（如 ``"NTFS"``）；失败/UNC 返回 ``None``。"""

    if not IS_WINDOWS or not path:
        return None
    try:
        drive = os.path.splitdrive(os.path.abspath(path))[0]
        if not drive or drive.startswith("\\\\"):
            return None
        volume_root = drive + "\\"
        kernel32 = ctypes.windll.kernel32
        get_volume_information = kernel32.GetVolumeInformationW
        get_volume_information.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        get_volume_information.restype = ctypes.c_int
        buffer = ctypes.create_unicode_buffer(256)
        ok = get_volume_information(volume_root, None, 0, None, None, None, buffer, 256)
        if not ok:
            return None
        return buffer.value or None
    except (AttributeError, OSError, ValueError):
        return None


def is_ntfs_volume(path: str) -> bool | None:
    """路径所在卷是否为 NTFS；无法判定返回 ``None``（调用方按保守策略处理）。"""

    filesystem = get_volume_filesystem(path)
    if not filesystem:
        return None
    return filesystem.casefold() == "ntfs"


def probe_file_occupancy(path: str) -> tuple[Occupancy, int]:
    """只读探测文件是否被其它进程以独占方式占用。

    实现：``CreateFileW(GENERIC_READ, dwShareMode=0)``。共享模式为 0 时，
    若已有进程持有该文件句柄，Windows 返回共享冲突 → 判定"可能被占用"。

    返回 ``(状态, Win32 错误码)``。注意：
    * 该调用不写文件、不改变文件内容，但会短暂打开句柄；
    * 杀毒软件/索引服务可能造成额外共享冲突，结论只能作为提示；
    * 目录不适用本探测；``ACCESS_DENIED`` 单独标记为"无访问权限"。
    """

    if not IS_WINDOWS or not path:
        return Occupancy.NOT_PROBED, 0
    try:
        kernel32 = ctypes.windll.kernel32
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int

        handle = create_file(path, GENERIC_READ, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    except (AttributeError, OSError, ValueError):
        return Occupancy.NOT_PROBED, 0

    if handle is None or handle == INVALID_HANDLE_VALUE:
        error_code = int(ctypes.GetLastError())
        if error_code in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION):
            return Occupancy.LOCKED, error_code
        if error_code == ERROR_ACCESS_DENIED:
            return Occupancy.NO_ACCESS, error_code
        return Occupancy.NOT_PROBED, error_code

    try:
        kernel32.CloseHandle(handle)
    except (AttributeError, OSError):
        pass
    return Occupancy.FREE, 0
