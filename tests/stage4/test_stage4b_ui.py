"""阶段 4B UI 接线冒烟测试（按钮状态 + 首次预演闸门；不执行真实动作）。"""

from __future__ import annotations

from PySide6.QtWidgets import QMessageBox

from perf_purifier.core.config import AppConfig
from perf_purifier.ui.pages.page_duplicates import DuplicatesPage


def _make_page(qapp, config: AppConfig, tmp_path) -> DuplicatesPage:
    page = DuplicatesPage(config, is_admin=False, app_version="0.1.0")
    page._audit_dir = tmp_path / "logs"
    page._config_save_path = tmp_path / "config.json"
    return page


def _dispose_page(page, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    page.setParent(None)
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


def test_detach_buttons_respect_switches(qapp, tmp_path, synthetic_file_result) -> None:
    page = _make_page(qapp, AppConfig(), tmp_path)
    try:
        page.set_result(synthetic_file_result)
        assert page._btn_detach_preview.isEnabled() is True
        assert page._btn_detach.isEnabled() is False  # 默认关闭
    finally:
        _dispose_page(page, qapp)


def test_detach_enabled_with_config(qapp, tmp_path, synthetic_file_result) -> None:
    config = AppConfig()
    config.stage2_enabled = True
    config.allow_hardlink_detach = True
    page = _make_page(qapp, config, tmp_path)
    try:
        page.set_result(synthetic_file_result)
        assert page._btn_detach.isEnabled() is True
    finally:
        _dispose_page(page, qapp)


def test_detach_blocked_by_first_preview_gate(qapp, tmp_path, synthetic_file_result, monkeypatch) -> None:
    config = AppConfig()
    config.stage2_enabled = True
    config.allow_hardlink_detach = True
    page = _make_page(qapp, config, tmp_path)
    try:
        page.set_result(synthetic_file_result)
        calls: list[tuple] = []
        monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: calls.append(args))
        monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: calls.append(args))
        page._start_detach()
        assert calls, "未预演时应提示先预演"
        assert "预演" in str(calls[0])
        assert page.is_action_running() is False
        assert not (tmp_path / "logs").exists()
    finally:
        _dispose_page(page, qapp)
