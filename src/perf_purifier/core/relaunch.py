"""阶段 3C：管理员重启引导（显式、单次、可失败；不自动提权）。

安全约束（docs/05 S3-6）：
* 只由用户点击按钮触发，必须二次确认；程序不自动提权、不循环弹窗；
* 目标可执行文件固定为当前 ``sys.executable``（不接受配置/日志中的任意命令）；
* 仅调用一次 ``ShellExecuteW`` + ``runas``；UAC 由系统控制；
* 用户取消 UAC / 调用失败时留在当前进程并提示。
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
from collections.abc import Callable, Sequence

SW_SHOWNORMAL = 1
ERROR_CANCELLED = 1223
ERROR_ACCESS_DENIED = 5
MIN_SUCCESS_CODE = 32

_ShellExecute = Callable[[str, str, str, str, str], int]


def build_relaunch_parameters(argv: Sequence[str]) -> str:
    """把启动参数转成 Windows 命令行（用于以管理员身份重启自身）。"""

    return subprocess.list2cmdline([str(item) for item in argv])


def default_shell_execute(verb: str, file: str, params: str, cwd: str) -> int:
    """真实 ShellExecuteW 调用（返回 >32 表示成功）。"""

    shell32 = ctypes.windll.shell32
    function = shell32.ShellExecuteW
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    function.restype = ctypes.c_void_p
    result = function(None, verb, file, params, cwd, SW_SHOWNORMAL)
    if result is None:
        return 0
    return int(result)


def relaunch_as_admin(
    argv: Sequence[str] | None = None,
    *,
    shell_execute: _ShellExecute | None = None,
) -> tuple[bool, str]:
    """尝试以管理员身份重启自身；返回 (是否已启动, 错误消息)。"""

    arguments = list(argv) if argv is not None else list(sys.argv)
    executable = sys.executable
    if getattr(sys, "frozen", False):
        # PyInstaller 冻结环境：sys.executable 就是 exe 自身，参数不含脚本路径
        arguments = (list(argv)[1:] if argv is not None else list(sys.argv[1:]))
    if not executable:
        return False, "无法确定当前 Python 解释器路径，不能自动重启"
    if shell_execute is None:
        if not hasattr(ctypes, "windll"):
            return False, "当前环境不支持管理员重启（仅 Windows）"
        shell_execute = default_shell_execute
    parameters = build_relaunch_parameters(arguments)
    try:
        code = shell_execute("runas", executable, parameters, str(sys.path[0] or "."))
    except OSError as exc:
        return False, f"启动失败：{exc}"
    except Exception as exc:  # noqa: BLE001 - 失败不崩溃，提示用户
        return False, f"启动失败：{type(exc).__name__}: {exc}"
    if code == ERROR_CANCELLED:
        return False, "已取消管理员授权（UAC），程序继续以当前权限运行"
    if code == ERROR_ACCESS_DENIED:
        return False, "系统拒绝了管理员授权请求，程序继续以当前权限运行"
    if code >= MIN_SUCCESS_CODE:
        return True, ""
    return False, f"启动失败（ShellExecuteW 返回码 {code}），程序继续以当前权限运行"
