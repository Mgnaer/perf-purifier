"""阶段 5C 测试：关于/安全说明对话框（只读、无执行入口）。"""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QPushButton

from perf_purifier.core.config import AppConfig
from perf_purifier.ui.dialogs.about_dialog import AboutDialog
from perf_purifier.ui.pages.page_settings import SettingsPage


def _dispose(widget, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    widget.setParent(None)
    widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


def test_about_dialog_shows_version_paths_and_safety(qapp, tmp_path) -> None:
    dialog = AboutDialog(
        is_admin=False,
        app_version="1.0.0",
        config_file=tmp_path / "config.json",
        log_directory=tmp_path / "logs",
    )
    try:
        labels = [label.text() for label in dialog.findChildren(QLabel)]
        text = "\n".join(labels)
        assert "1.0.0" in text
        assert "普通用户" in text
        assert "安全边界" in text
        assert "不联网" in text and "默认关闭" in text
        assert str(tmp_path / "config.json") in text
    finally:
        _dispose(dialog, qapp)


def test_about_dialog_has_no_action_buttons(qapp) -> None:
    dialog = AboutDialog(is_admin=True, app_version="1.0.0")
    try:
        for button in dialog.findChildren(QPushButton):
            assert not any(
                keyword in button.text()
                for keyword in ("删除", "结束进程", "硬链接", "清理", "执行")
            )
    finally:
        _dispose(dialog, qapp)


def test_settings_page_has_about_button(qapp, tmp_path) -> None:
    page = SettingsPage(
        AppConfig(), is_admin=False, app_version="1.0.0", config_path=tmp_path / "config.json"
    )
    try:
        assert page._btn_about.text() == "关于 / 安全说明"
        assert page._btn_about.isEnabled()
    finally:
        _dispose(page, qapp)
