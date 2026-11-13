"""用资源管理器打开文件/目录（只读辅助动作，可安全调用）。"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def open_containing_folder(path: str | None) -> tuple[bool, str]:
    """在资源管理器中定位文件（``/select,``）或打开所在目录。

    注意：``explorer.exe`` 即使成功也常返回退出码 1，因此不检查返回码，
    只在启动失败（OSError）时报告错误。
    """

    if sys.platform != "win32":
        return False, "该功能仅支持 Windows"
    if not path:
        return False, "路径不可用"
    target = Path(path)
    try:
        if target.is_file():
            subprocess.Popen(
                ["explorer.exe", "/select,", str(target)],
                close_fds=True,
            )
            return True, ""
        folder = target if target.is_dir() else target.parent
        if not folder.is_dir():
            return False, f"目录不存在：{folder}"
        subprocess.Popen(["explorer.exe", str(folder)], close_fds=True)
        return True, ""
    except OSError as exc:
        return False, f"打开资源管理器失败：{exc}"
