"""应用入口：日志 → QApplication → 主窗口 → 首次免责声明。"""

from __future__ import annotations

import sys

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

from . import __app_id__, __app_name__, __version__
from .core.config import AppConfig, config_path, log_dir
from .core.logging_setup import install_excepthook, setup_logging
from .core.whitelist import Whitelist
from .core.winapi import is_admin
from .ui.dialogs.disclaimer_dialog import DisclaimerDialog
from .ui.main_window import MainWindow

_PREFERRED_FONTS = ("Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", "Noto Sans CJK SC")


def _apply_font(app: QApplication) -> None:
    """优先使用中文显示效果好的字体；失败则沿用 Qt 默认字体。"""

    try:
        families = set(QFontDatabase.families())
    except Exception:  # noqa: BLE001 - 字体枚举失败不影响启动
        return
    for family in _PREFERRED_FONTS:
        if family in families:
            app.setFont(QFont(family, 9))
            return


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv if argv is None else argv)

    logger = setup_logging(log_dir())
    install_excepthook(logger)
    logger.info("启动 %s v%s（默认只读，执行层默认关闭）", __app_name__, __version__)

    app = QApplication(args)
    app.setApplicationName(__app_name__)
    app.setApplicationDisplayName(f"{__app_name__} {__version__}")
    app.setOrganizationName(__app_id__)
    _apply_font(app)

    config = AppConfig.load()
    whitelist = Whitelist.from_config(config)
    admin = is_admin()
    logger.info("管理员权限：%s，配置文件：%s", admin, config_path())

    window = MainWindow(config, whitelist, is_admin=admin, logger=logger)
    window.show()

    if not config.disclaimer_ack:
        dialog = DisclaimerDialog(window)
        dialog.exec()
        if not dialog.accepted:
            logger.info("用户拒绝使用须知，退出")
            window.close()
            return 0
        config.disclaimer_ack = True
        ok, error = config.save()
        if not ok:
            logger.warning("免责声明确认状态保存失败：%s", error)

    return app.exec()
