"""无头（offscreen）UI 冒烟测试：窗口/模型可构建，搜索保留祖先路径。"""

from __future__ import annotations

import logging

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from perf_purifier.core.config import AppConfig  # noqa: E402
from perf_purifier.core.models import ProcessInfo, Severity  # noqa: E402
from perf_purifier.core.whitelist import Whitelist  # noqa: E402
from perf_purifier.module_a.tree_builder import build_tree  # noqa: E402
from perf_purifier.ui.main_window import MainWindow  # noqa: E402
from perf_purifier.ui.models.process_tree_model import ProcessTreeModel  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def test_main_window_constructs_without_scanning(qapp) -> None:
    logger = logging.getLogger("test")
    window = MainWindow(AppConfig(), Whitelist(), is_admin=False, logger=logger)
    window.show()
    assert "只读" in window.windowTitle()
    assert window.centralWidget() is not None
    window.close()


def test_pages_accept_scan_result(qapp, synthetic_result) -> None:
    logger = logging.getLogger("test")
    window = MainWindow(AppConfig(), Whitelist(), is_admin=False, logger=logger)
    connections_page = window.connections_page()
    temp_page = window.temp_page()
    connections_page.set_result(synthetic_result)
    temp_page.set_result(synthetic_result)
    assert connections_page._model.rowCount() == 2  # noqa: SLF001 - 冒烟测试直接检查模型
    assert temp_page._model.rowCount() == 1  # noqa: SLF001
    window.close()


def test_file_pages_accept_result(qapp, synthetic_file_result) -> None:
    logger = logging.getLogger("test")
    window = MainWindow(AppConfig(), Whitelist(), is_admin=False, logger=logger)
    duplicates = window.duplicates_page()
    large = window.large_files_page()
    duplicates.set_result(synthetic_file_result)
    large.set_result(synthetic_file_result)
    assert duplicates._group_model.rowCount() == 2  # noqa: SLF001 - 冒烟测试直接检查模型
    assert duplicates._file_model.rowCount() == 2  # noqa: SLF001 - 默认选中第一组
    assert large._model.rowCount() == len(synthetic_file_result.large_files)  # noqa: SLF001
    window.close()


def test_tree_model_hierarchy(qapp) -> None:
    tree = build_tree(
        [
            ProcessInfo(pid=4, ppid=0, name="System"),
            ProcessInfo(pid=100, ppid=4, name="services.exe", create_time=100.0),
            ProcessInfo(pid=200, ppid=100, name="svchost.exe", create_time=200.0),
        ]
    )
    model = ProcessTreeModel()
    model.set_tree(tree)
    assert model.rowCount() == 1
    root = model.index(0, 0)
    assert root.isValid()
    assert model.rowCount(root) == 1
    child = model.index(0, 0, root)
    assert child.isValid()
    assert model.rowCount(child) == 1
    grandchild = model.index(0, 0, child)
    assert grandchild.isValid()
    assert model.node_for_index(grandchild) is not None
    assert model.node_for_index(grandchild).info.pid == 200
    assert model.parent(grandchild).internalId() == 100


def test_tree_model_search_keeps_ancestors(qapp) -> None:
    tree = build_tree(
        [
            ProcessInfo(pid=4, ppid=0, name="System"),
            ProcessInfo(pid=100, ppid=4, name="services.exe"),
            ProcessInfo(pid=200, ppid=100, name="target.exe"),
            ProcessInfo(pid=300, ppid=4, name="other.exe"),
        ]
    )
    model = ProcessTreeModel()
    model.set_tree(tree)
    model.set_filters("target", Severity.INFO)
    assert model.rowCount() == 1  # 只剩 System 根
    root = model.index(0, 0)
    assert model.rowCount(root) == 1  # services 作为祖先保留
    service = model.index(0, 0, root)
    assert model.rowCount(service) == 1  # 命中节点保留
    hit = model.index(0, 0, service)
    assert model.node_for_index(hit) is not None
    assert model.node_for_index(hit).info.pid == 200
