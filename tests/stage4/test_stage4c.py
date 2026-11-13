"""阶段 4C 测试：设置页分析白名单 / 扫描排除规则管理（不影响动作授权）。"""

from __future__ import annotations

import json

from PySide6.QtWidgets import QMessageBox

from perf_purifier.core.config import AppConfig
from perf_purifier.ui.pages.page_settings import SettingsPage


def _make_page(qapp, tmp_path) -> SettingsPage:
    return SettingsPage(
        AppConfig(), is_admin=False, app_version="0.1.0", config_path=tmp_path / "config.json"
    )


def _dispose_page(page, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    page.setParent(None)
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


def test_add_and_remove_analysis_whitelist(qapp, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)
    page = _make_page(qapp, tmp_path)
    try:
        edit = page._rule_edits["analysis_whitelist_paths"]
        edit.setText(r"C:\Tools\my_tool.exe")
        page._add_rule("analysis_whitelist_paths", edit)
        assert page._config.analysis_whitelist_paths == [r"C:\Tools\my_tool.exe"]
        assert page._rule_lists["analysis_whitelist_paths"].count() == 1
        saved = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
        assert saved["analysis_whitelist_paths"] == [r"C:\Tools\my_tool.exe"]

        # 重复条目不重复添加
        edit.setText(r"C:\Tools\my_tool.exe")
        page._add_rule("analysis_whitelist_paths", edit)
        assert page._config.analysis_whitelist_paths == [r"C:\Tools\my_tool.exe"]

        widget = page._rule_lists["analysis_whitelist_paths"]
        widget.setCurrentRow(0)
        page._remove_rule("analysis_whitelist_paths")
        assert page._config.analysis_whitelist_paths == []
        assert widget.count() == 0
    finally:
        _dispose_page(page, qapp)


def test_add_name_and_exclude_rules(qapp, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    page = _make_page(qapp, tmp_path)
    try:
        name_edit = page._rule_edits["analysis_whitelist_names"]
        name_edit.setText("my_tool.exe")
        page._add_rule("analysis_whitelist_names", name_edit)
        pattern_edit = page._rule_edits["file_scan_exclude_patterns"]
        pattern_edit.setText("*.iso")
        page._add_rule("file_scan_exclude_patterns", pattern_edit)
        assert page._config.analysis_whitelist_names == ["my_tool.exe"]
        assert page._config.file_scan_exclude_patterns == ["*.iso"]
        # 动作开关与动作黑名单不受影响
        assert page._config.stage2_enabled is False
        assert page._config.allow_delete_temp is False
        assert page._config.allow_kill_process is False
    finally:
        _dispose_page(page, qapp)


def test_rules_limit(qapp, tmp_path, monkeypatch) -> None:
    import perf_purifier.ui.pages.page_settings as settings_module

    monkeypatch.setattr(settings_module, "MAX_WHITELIST_ITEMS", 1)
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)
    page = _make_page(qapp, tmp_path)
    try:
        edit = page._rule_edits["file_scan_exclude_patterns"]
        edit.setText("*.tmp")
        page._add_rule("file_scan_exclude_patterns", edit)
        edit.setText("*.bak")
        page._add_rule("file_scan_exclude_patterns", edit)
        assert page._config.file_scan_exclude_patterns == ["*.tmp"]
    finally:
        _dispose_page(page, qapp)


def test_empty_input_rejected(qapp, tmp_path, monkeypatch) -> None:
    seen: list[tuple] = []
    monkeypatch.setattr(
        QMessageBox, "information", lambda *args, **kwargs: seen.append(args)
    )
    page = _make_page(qapp, tmp_path)
    try:
        edit = page._rule_edits["analysis_whitelist_paths"]
        page._add_rule("analysis_whitelist_paths", edit)
        assert page._config.analysis_whitelist_paths == []
        assert seen
    finally:
        _dispose_page(page, qapp)
