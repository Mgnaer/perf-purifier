"""启动冒烟：无头模式走完整的 ``app.main()`` 启动链路（含字体选择、免责声明跳过）。

与 ``smoke_e2e.py`` 的区别：本脚本验证入口/配置/主窗口装配，不触发扫描。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import perf_purifier.app as app_module  # noqa: E402
from perf_purifier.core.config import AppConfig  # noqa: E402

AUTO_QUIT_MS = 1500


class _SmokeConfig(AppConfig):
    """不读写用户真实配置，也不弹免责声明。"""

    @classmethod
    def load(cls, path=None) -> "_SmokeConfig":  # type: ignore[override]
        return cls(disclaimer_ack=True)

    def save(self, path=None) -> tuple[bool, str]:  # type: ignore[override]
        return True, ""


class _AutoQuitApplication(QApplication):
    """启动后自动退出，避免冒烟脚本卡在事件循环。"""

    def exec(self) -> int:  # type: ignore[override]
        QTimer.singleShot(AUTO_QUIT_MS, self.quit)
        return super().exec()


def main() -> int:
    app_module.AppConfig = _SmokeConfig  # type: ignore[assignment]
    app_module.QApplication = _AutoQuitApplication  # type: ignore[assignment]
    code = app_module.main([])
    print(f"OK: app.main 正常启动并退出，返回码={code}")
    return 0 if code == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
