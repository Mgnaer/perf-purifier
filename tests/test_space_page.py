"""磁盘空间页（模块 C）无头 UI 测试：结果灌入、默认勾选、执行层闸门、页签存在。"""

from __future__ import annotations

import logging

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from perf_purifier.core.config import AppConfig  # noqa: E402
from perf_purifier.core.whitelist import Whitelist  # noqa: E402
from perf_purifier.module_c.models import RISK_CAUTION, RISK_SAFE  # noqa: E402
from perf_purifier.ui.main_window import MainWindow  # noqa: E402
from perf_purifier.ui.pages.page_space import SpacePage  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def _dispose(page, app) -> None:
    page.deleteLater()
    app.processEvents()


def test_page_result_filled_and_default_selection(qapp, synthetic_space_result) -> None:
    page = SpacePage(AppConfig(), is_admin=False, app_version="1.2.0")
    try:
        page.set_result(synthetic_space_result)
        assert page._overview_model.rowCount() == 3
        assert page._junk_model.rowCount() == 3
        assert page._large_model.rowCount() == 2
        # 默认只勾选安全级规则
        assert page._junk_model.checked_rule_ids() == ["temp_user"]
        assert page._junk_model.checked_count() == 2
        assert page._junk_model.checked_bytes() == 3072
        assert page.selected_drive() == "C:\\"
        assert "可用" in page._usage_label.text()
        # 执行层默认关闭 → 清理按钮禁用
        assert page._clean_enabled() is False
        assert page._btn_clean.isEnabled() is False
        assert "默认关闭" in page._btn_clean.toolTip()
        # 没有回收站条目 → 清空按钮禁用
        assert page._recycle_bin_item() is None
        assert page._btn_empty_trash.isEnabled() is False
    finally:
        _dispose(page, qapp)


def test_page_clean_enabled_when_stage2_on(qapp, synthetic_space_result) -> None:
    config = AppConfig()
    config.stage2_enabled = True
    config.allow_clean_space = True
    page = SpacePage(config, is_admin=False, app_version="1.2.0")
    try:
        page.set_result(synthetic_space_result)
        assert page._clean_enabled() is True
        assert page._btn_clean.isEnabled() is True

        page._clear_selection()
        assert page._btn_clean.isEnabled() is False
        assert page._junk_model.checked_count() == 0

        page._select_by_risk({RISK_SAFE, RISK_CAUTION})
        assert page._junk_model.checked_count() == 3
        items = page.checked_items()
        assert len(items) == 3
        assert any(item.rule_id == "gpu_shader_caches" for item in items)
    finally:
        _dispose(page, qapp)


def test_page_select_all_respects_toggles(qapp, synthetic_space_result) -> None:
    page = SpacePage(AppConfig(), is_admin=False, app_version="1.2.0")
    try:
        page.set_result(synthetic_space_result)
        page._select_all()
        # 默认不含谨慎级
        assert page._junk_model.checked_rule_ids() == ["temp_user"]
        page._chk_caution.setChecked(True)
        page._select_all()
        assert page._junk_model.checked_count() == 3
        # 非管理员勾选系统级也不会被选中
        page._chk_system.setChecked(True)
        page._select_all()
        assert all(
            result.rule.risk != "system" for result in page._junk_model.checked_results()
        )
    finally:
        _dispose(page, qapp)


def test_page_reset_clears_ui(qapp, synthetic_space_result) -> None:
    page = SpacePage(AppConfig(), is_admin=False, app_version="1.2.0")
    try:
        page.set_result(synthetic_space_result)
        page.set_result(None)
        assert page._overview_model.rowCount() == 0
        assert page._junk_model.rowCount() == 0
        assert page._large_model.rowCount() == 0
        assert "尚未扫描" in page._hint.text()
        assert page._junk_model.checked_count() == 0
    finally:
        _dispose(page, qapp)


def test_main_window_has_space_tab(qapp) -> None:
    logger = logging.getLogger("test-space-page")
    window = MainWindow(AppConfig(), Whitelist(), is_admin=False, logger=logger)
    try:
        page = window.space_page()
        assert isinstance(page, SpacePage)
        titles = [window._tabs.tabText(index) for index in range(window._tabs.count())]
        assert "磁盘空间" in titles
        assert titles.index("磁盘空间") == titles.index("大文件排行") + 1
    finally:
        window.close()
