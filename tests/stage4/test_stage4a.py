"""阶段 4A 测试：只读快照构建/读写/基线对比 + 进程页按钮（无副作用）。"""

from __future__ import annotations

import json

from PySide6.QtWidgets import QMessageBox

from perf_purifier.core.config import AppConfig
from perf_purifier.core.models import ProcessScanResult
from perf_purifier.core.snapshots import (
    build_snapshot,
    compare_snapshot,
    delete_snapshot,
    diff_summary,
    load_snapshot,
    save_snapshot,
)
from perf_purifier.core.whitelist import Whitelist
from perf_purifier.module_a.tree_builder import build_tree
from perf_purifier.ui.pages.page_process_tree import ProcessTreePage

NOW = 1_700_000_000.0


def _result_with(make_info, entries, base: ProcessScanResult | None = None) -> ProcessScanResult:
    tree = build_tree(entries)
    return ProcessScanResult(
        tree=tree,
        started_at=NOW,
        finished_at=NOW + 1,
        connections=base.connections if base else None,
        temp=base.temp if base else None,
    )


def test_build_snapshot_from_scan(synthetic_result) -> None:
    snapshot = build_snapshot(synthetic_result)
    assert snapshot.total_processes == synthetic_result.tree.total_processes
    assert len(snapshot.processes) == len(synthetic_result.tree.nodes)
    assert snapshot.remote_endpoints  # 合成结果包含远端连接
    assert snapshot.temp_total_files == synthetic_result.temp.total_files
    identities = {entry.identity for entry in snapshot.processes}
    assert len(identities) == len(snapshot.processes)


def test_save_load_roundtrip_and_corruption(tmp_path, synthetic_result) -> None:
    path = tmp_path / "baseline.json"
    snapshot = build_snapshot(synthetic_result)
    ok, message = save_snapshot(snapshot, path)
    assert ok, message
    loaded, error = load_snapshot(path)
    assert loaded is not None, error
    assert loaded.created_at == snapshot.created_at
    assert loaded.processes == snapshot.processes
    assert loaded.remote_endpoints == snapshot.remote_endpoints

    missing, error = load_snapshot(tmp_path / "nope.json")
    assert missing is None and "尚未保存基线" in error

    (tmp_path / "bad.json").write_text("not-json", encoding="utf-8")
    bad, error = load_snapshot(tmp_path / "bad.json")
    assert bad is None and "不可读" in error

    (tmp_path / "wrong.json").write_text(json.dumps([1, 2]), encoding="utf-8")
    wrong, error = load_snapshot(tmp_path / "wrong.json")
    assert wrong is None and "格式" in error


def test_compare_detects_new_and_gone(make_info, synthetic_result) -> None:
    baseline = build_snapshot(synthetic_result)
    entries = [
        make_info(4, 0, "System", exe=None),
        make_info(100, 4, "evil.exe", create_time=1_700_000_100.0),
        make_info(300, 4, "newcomer.exe", create_time=1_700_000_300.0),
    ]
    current = _result_with(make_info, entries, synthetic_result)
    diff = compare_snapshot(baseline, current)
    new_pids = {entry.pid for entry in diff.new_processes}
    gone_pids = {entry.pid for entry in diff.gone_processes}
    assert 300 in new_pids
    assert 200 in gone_pids
    assert diff.has_changes is True
    assert "新增进程" in diff_summary(diff)


def test_pid_reuse_detected_as_new_and_gone(make_info, synthetic_result) -> None:
    baseline = build_snapshot(synthetic_result)
    entries = [
        make_info(4, 0, "System", exe=None),
        make_info(100, 4, "evil.exe", create_time=1_700_999_999.0),  # 同 pid 不同 create_time
        make_info(200, 4, "notepad.exe"),
    ]
    current = _result_with(make_info, entries, synthetic_result)
    diff = compare_snapshot(baseline, current)
    assert any(entry.pid == 100 and entry.create_time == 1_700_999_999.0 for entry in diff.new_processes)
    assert any(entry.pid == 100 for entry in diff.gone_processes)


def test_no_change_diff(make_info, synthetic_result) -> None:
    baseline = build_snapshot(synthetic_result)
    entries = [
        make_info(4, 0, "System", exe=None),
        make_info(100, 4, "evil.exe", create_time=1_700_000_100.0),
        make_info(200, 4, "notepad.exe"),
    ]
    current = _result_with(make_info, entries, synthetic_result)
    diff = compare_snapshot(baseline, current)
    assert diff.new_processes == ()
    assert diff.gone_processes == ()
    assert "未发现差异" in diff_summary(diff)


# ---------------------------------------------------------------- UI（只读按钮）
def _dispose_page(page, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    page.setParent(None)
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


def test_process_page_baseline_buttons(qapp, tmp_path, synthetic_result, monkeypatch) -> None:
    page = ProcessTreePage(AppConfig(), Whitelist(), is_admin=False, app_version="0.1.0")
    page._snapshot_path = tmp_path / "baseline.json"
    page.set_result(synthetic_result)
    assert page._btn_snapshot_save.isEnabled() is True
    assert page._btn_snapshot_compare.isEnabled() is False
    assert page._btn_snapshot_delete.isEnabled() is False

    calls: list[str] = []
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: calls.append(args[1]))
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: calls.append(args[1]))
    monkeypatch.setattr(
        QMessageBox, "question", lambda *args, **kwargs: QMessageBox.StandardButton.Yes
    )

    page.save_baseline()
    assert (tmp_path / "baseline.json").exists()
    assert page._btn_snapshot_compare.isEnabled() is True
    assert page._btn_snapshot_delete.isEnabled() is True

    page.compare_baseline()
    page.delete_baseline()
    assert not (tmp_path / "baseline.json").exists()
    assert page._btn_snapshot_compare.isEnabled() is False
    assert "已保存基线" in calls and "基线对比结果" in calls
    _dispose_page(page, qapp)


def test_snapshot_delete_missing_is_ok(tmp_path) -> None:
    ok, message = delete_snapshot(tmp_path / "missing.json")
    assert ok is True
    assert "不存在" in message
