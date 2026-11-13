"""阶段 3A 测试：首次预演闸门、审计轮转、设置页安全开关、预演零副作用。

所有测试都只操作临时目录/临时配置；预演使用 DryRunExecutor，不产生任何真实动作。
"""

from __future__ import annotations

import json
import os

from PySide6.QtWidgets import QMessageBox

from perf_purifier.core.action_policy import ActionKind
from perf_purifier.core.audit import (
    rotate_audit_log,
)
from perf_purifier.core.config import AppConfig
from perf_purifier.core.first_run import (
    is_preview_required,
    mark_preview_done,
    reset_preview_flags,
)
from perf_purifier.core.models import (
    Completeness,
    DuplicateGroup,
    FileRecord,
    FileScanOptions,
    FileScanResult,
    Occupancy,
    ProcessScanResult,
    ProcessTree,
    TempEntry,
    TempRoot,
    TempScanResult,
)
from perf_purifier.module_a.tree_builder import build_tree
from perf_purifier.ui.pages.page_duplicates import DuplicatesPage
from perf_purifier.ui.pages.page_process_tree import ProcessTreePage
from perf_purifier.ui.pages.page_settings import SettingsPage
from perf_purifier.ui.pages.page_temp import TempPage

NOW = 1_700_000_000.0


def _dispose_page(page, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    page.setParent(None)
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


# ---------------------------------------------------------------- 首次预演闸门
def test_first_run_flags() -> None:
    config = AppConfig()
    for kind in ActionKind:
        assert is_preview_required(kind, config) is True
    assert mark_preview_done(config, ActionKind.DELETE_TEMP) is True
    assert mark_preview_done(config, ActionKind.DELETE_TEMP) is False
    assert is_preview_required(ActionKind.DELETE_TEMP, config) is False
    assert is_preview_required(ActionKind.KILL_PROCESS, config) is True
    assert reset_preview_flags(config) is True
    assert reset_preview_flags(config) is False
    for kind in ActionKind:
        assert is_preview_required(kind, config) is True


# ---------------------------------------------------------------- 审计轮转
def test_rotate_small_file_noop(tmp_path) -> None:
    (tmp_path / "operations.jsonl").write_text("{}\n", encoding="utf-8")
    assert rotate_audit_log(tmp_path, max_bytes=10 * 1024 * 1024) is None
    assert (tmp_path / "operations.jsonl").exists()


def test_rotate_large_file_and_unique_names(tmp_path) -> None:
    path = tmp_path / "operations.jsonl"
    path.write_text("x" * 100, encoding="utf-8")
    rotated = rotate_audit_log(tmp_path, now=NOW, max_bytes=10)
    assert rotated is not None and rotated.exists()
    assert rotated.name.startswith("operations-")
    assert not path.exists()

    path.write_text("x" * 100, encoding="utf-8")
    rotated_again = rotate_audit_log(tmp_path, now=NOW, max_bytes=10)
    assert rotated_again is not None
    assert rotated_again != rotated
    assert rotated_again.name.endswith("-1.jsonl")


def test_rotate_prunes_keep_and_retention(tmp_path) -> None:
    logs = tmp_path
    for index in range(5):
        candidate = logs / f"operations-2024010{index}-000000.jsonl"
        candidate.write_text("old\n", encoding="utf-8")
        old_time = NOW - (5 - index) * 3600
        os.utime(candidate, (old_time, old_time))
    (logs / "operations.jsonl").write_text("x" * 100, encoding="utf-8")

    rotate_audit_log(tmp_path, now=NOW, max_bytes=10, keep=2, retention_days=30)
    remaining = sorted(path.name for path in logs.glob("operations-*.jsonl"))
    # 轮转产生 1 个新文件 + 保留最新 1 个旧文件（keep=2）
    assert len(remaining) == 2

    stale = logs / "operations-20230101-000000.jsonl"
    stale.write_text("stale\n", encoding="utf-8")
    old_time = NOW - 40 * 86400
    os.utime(stale, (old_time, old_time))
    (logs / "operations.jsonl").write_text("x" * 100, encoding="utf-8")
    rotate_audit_log(tmp_path, now=NOW, max_bytes=10, keep=10, retention_days=30)
    assert not stale.exists()


# ---------------------------------------------------------------- 设置页
def test_settings_page_disable_all_actions(qapp, tmp_path, monkeypatch) -> None:
    from perf_purifier.ui.pages.page_settings import _ACTION_SWITCHES

    config = AppConfig()
    config.stage2_enabled = True
    config.allow_delete_temp = True
    config.allow_kill_process = True
    config.allow_clean_space = True
    config_path = tmp_path / "config.json"
    page = SettingsPage(config, is_admin=False, app_version="0.1.0", config_path=config_path)

    assert page._switch_table.rowCount() == len(_ACTION_SWITCHES)
    assert page._switch_table.item(0, 1).text() == "开启"
    assert "普通用户" in page._info_labels["admin"].text()
    signal_hits: list[bool] = []
    page.actions_disabled.connect(lambda: signal_hits.append(True))
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)

    page._on_disable_actions()
    assert config.stage2_enabled is False
    assert config.allow_delete_temp is False
    assert config.allow_hardlink_dedupe is False
    assert config.allow_kill_process is False
    assert config.allow_clean_space is False
    assert signal_hits == [True]
    saved = json.loads(config_path.read_text(encoding="utf-8"))
    assert saved["stage2_enabled"] is False
    assert saved["allow_clean_space"] is False
    assert page._btn_disable.isEnabled() is False
    assert "全部关闭" in page._hint.text()
    _dispose_page(page, qapp)


def test_settings_page_reset_preview_flags(qapp, tmp_path, monkeypatch) -> None:
    config = AppConfig()
    mark_preview_done(config, ActionKind.KILL_PROCESS)
    config_path = tmp_path / "config.json"
    page = SettingsPage(config, is_admin=True, app_version="0.1.0", config_path=config_path)
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    page._on_reset_preview_flags()
    assert is_preview_required(ActionKind.KILL_PROCESS, config) is True
    assert json.loads(config_path.read_text(encoding="utf-8"))["kill_preview_done"] is False
    _dispose_page(page, qapp)


# ---------------------------------------------------------------- 预演零副作用
def _patch_messages(monkeypatch) -> list[tuple]:
    calls: list[tuple] = []

    def record(*args, **kwargs):
        calls.append((args, kwargs))
        return None

    monkeypatch.setattr(QMessageBox, "information", record)
    monkeypatch.setattr(QMessageBox, "warning", record)
    monkeypatch.setattr(QMessageBox, "critical", record)
    return calls


def test_temp_preview_no_side_effect(qapp, tmp_path, monkeypatch) -> None:
    root = str(tmp_path)
    target = tmp_path / "a.tmp"
    target.write_bytes(b"preview-me")
    stat_result = os.stat(target)
    entry = TempEntry(
        root=root,
        path=str(target),
        is_dir=False,
        size=int(stat_result.st_size),
        file_count=1,
        mtime=float(stat_result.st_mtime),
        occupancy=Occupancy.FREE,
    )
    temp = TempScanResult(
        roots=[TempRoot(path=root, kind="temp", exists=True)],
        entries=[entry],
        total_size=entry.size,
        total_files=1,
        unreadable=0,
        completeness=Completeness.FULL,
    )
    result = ProcessScanResult(
        tree=ProcessTree(), started_at=NOW, finished_at=NOW + 1, temp=temp
    )
    config = AppConfig()  # 动作开关默认关闭，但预演不受开关限制
    page = TempPage(config, is_admin=False, app_version="0.1.0")
    page._audit_dir = tmp_path / "logs"
    page._config_save_path = tmp_path / "config.json"
    page.set_result(result)
    model = page._model
    assert model.setData(model.index(0, 0), 2, 10)  # Qt.CheckState.Checked
    calls = _patch_messages(monkeypatch)

    page._start_preview()

    assert calls, "预演完成后应弹出结果提示"
    assert target.read_bytes() == b"preview-me"  # 文件未被删除/修改
    assert config.delete_temp_preview_done is True
    saved = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert saved["delete_temp_preview_done"] is True
    audit = (tmp_path / "logs" / "operations.jsonl").read_text(encoding="utf-8").splitlines()
    header = json.loads(audit[0])
    assert header["record_type"] == "action_header"
    assert header["dry_run"] is True
    assert json.loads(audit[1])["result"] == "dry_run"
    _dispose_page(page, qapp)


def test_first_preview_gate_blocks_real_action(qapp, tmp_path, monkeypatch) -> None:
    config = AppConfig()
    config.stage2_enabled = True
    config.allow_delete_temp = True
    page = TempPage(config, is_admin=False, app_version="0.1.0")
    page._audit_dir = tmp_path / "logs"
    root = str(tmp_path)
    target = tmp_path / "b.tmp"
    target.write_bytes(b"x")
    stat_result = os.stat(target)
    entry = TempEntry(
        root=root,
        path=str(target),
        is_dir=False,
        size=int(stat_result.st_size),
        file_count=1,
        mtime=float(stat_result.st_mtime),
        occupancy=Occupancy.FREE,
    )
    temp = TempScanResult(
        roots=[TempRoot(path=root, kind="temp", exists=True)],
        entries=[entry],
        total_size=entry.size,
        total_files=1,
        unreadable=0,
        completeness=Completeness.FULL,
    )
    page.set_result(
        ProcessScanResult(tree=ProcessTree(), started_at=NOW, finished_at=NOW + 1, temp=temp)
    )
    model = page._model
    assert model.setData(model.index(0, 0), 2, 10)
    calls = _patch_messages(monkeypatch)

    page._start_delete()
    messages = " ".join(str(call) for call in calls)
    assert "预演" in messages
    assert page.is_action_running() is False
    assert not (tmp_path / "logs" / "operations.jsonl").exists()
    assert target.exists()
    _dispose_page(page, qapp)


def test_hardlink_preview_no_side_effect(qapp, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "perf_purifier.module_b.hardlink_action.is_ntfs_volume", lambda path: True
    )
    keep = tmp_path / "keep.bin"
    dup = tmp_path / "dup.bin"
    keep.write_bytes(b"same-content")
    dup.write_bytes(b"same-content")
    records = []
    for path in (keep, dup):
        stat_result = os.stat(path)
        records.append(
            FileRecord(
                path=str(path),
                size=int(stat_result.st_size),
                mtime=float(stat_result.st_mtime),
                dev=int(stat_result.st_dev),
                ino=int(stat_result.st_ino),
            )
        )
    group = DuplicateGroup(
        group_id=1,
        size=records[0].size,
        full_sha256="a" * 64,
        files=tuple(records),
        distinct_inodes=2,
        suggested_keep_path=records[0].path,
    )
    result = FileScanResult(
        root=str(tmp_path),
        options=FileScanOptions(root=str(tmp_path)),
        started_at=NOW,
        finished_at=NOW + 1,
        files_scanned=2,
        duplicate_groups=[group],
    )
    config = AppConfig()
    page = DuplicatesPage(config, is_admin=False, app_version="0.1.0")
    page._audit_dir = tmp_path / "logs"
    page._config_save_path = tmp_path / "config.json"
    page.set_result(result)
    model = page._group_model
    assert model.setData(model.index(0, 0), 2, 10)
    calls = _patch_messages(monkeypatch)

    page._start_preview()

    assert calls
    assert config.hardlink_preview_done is True
    assert os.stat(keep).st_ino != os.stat(dup).st_ino  # 未建立硬链接
    records_json = (tmp_path / "logs" / "operations.jsonl").read_text(encoding="utf-8")
    assert '"dry_run": true' in records_json
    _dispose_page(page, qapp)


def test_kill_preview_no_side_effect(qapp, monkeypatch) -> None:
    from pathlib import Path

    from perf_purifier.core.whitelist import Whitelist

    config = AppConfig()
    page = ProcessTreePage(config, Whitelist(), is_admin=False, app_version="0.1.0")
    page._audit_dir = Path(os.path.dirname(os.path.abspath(__file__))) / "_kill_preview_audit"
    page._config_save_path = (
        Path(os.path.dirname(os.path.abspath(__file__))) / "_kill_preview_config.json"
    )
    infos = [
        {"pid": 1000, "ppid": 0, "name": "demo.exe", "create_time": 1_700_000_000.0, "exe": None},
        {"pid": 1001, "ppid": 1000, "name": "child.exe", "create_time": 1_700_000_001.0, "exe": None},
    ]
    from perf_purifier.core.models import ProcessInfo

    tree = build_tree(
        [
            ProcessInfo(pid=info["pid"], ppid=info["ppid"], name=info["name"], create_time=info["create_time"], exe=info["exe"])
            for info in infos
        ]
    )
    page.set_result(ProcessScanResult(tree=tree, started_at=NOW, finished_at=NOW + 1))
    selection = page._view.selectionModel()
    from PySide6.QtCore import QItemSelectionModel

    child_index = page._model.index(0, 0, page._model.index(0, 0))
    selection.select(
        child_index,
        QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
    )
    assert page._selected_pids()
    calls = _patch_messages(monkeypatch)

    page._start_preview()

    try:
        assert calls
        assert config.kill_preview_done is True
    finally:
        import shutil

        for path in (page._audit_dir,):
            shutil.rmtree(path, ignore_errors=True)
        config_file = page._config_save_path
        if config_file and os.path.exists(config_file):
            os.unlink(config_file)
        _dispose_page(page, qapp)
