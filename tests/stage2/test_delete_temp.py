"""阶段 2C 删除 Temp 测试（假回收站后端；不污染真实回收站、不需要管理员）。

覆盖：完整度适配、目标构建、策略预览、执行器身份重验、回收站失败语义、
ActionJob 全流程（审计顺序/结果隔离）、UI 勾选规则与默认关闭。
"""

from __future__ import annotations

import json
import os

from PySide6.QtCore import Qt

from perf_purifier.core.action_policy import ActionKind, ActionPolicy
from perf_purifier.core.audit import ActionAuditWriter
from perf_purifier.core.config import AppConfig
from perf_purifier.core.judgements import CompletenessVerdict, Reason
from perf_purifier.core.models import (
    Completeness,
    Occupancy,
    ProcessScanResult,
    ProcessTree,
    ScanWarning,
    TempEntry,
    TempRoot,
    TempScanResult,
)
from perf_purifier.core.trash import RecordingTrashBackend, Send2TrashBackend
from perf_purifier.jobs.action_job import ActionJob, ActionSessionResult
from perf_purifier.module_a.temp_delete import (
    DeleteTempExecutor,
    build_delete_preview,
    delete_targets_from_entries,
    entry_selectable,
    temp_scan_verdict,
)
from perf_purifier.ui.pages.page_temp import TempPage

NOW = 1_700_000_000.0


def _dispose_page(page, qapp) -> None:
    """显式销毁 QWidget，避免 QApplication 先于控件析构导致进程退出崩溃。"""

    from PySide6.QtCore import QCoreApplication, QEvent

    page.setParent(None)
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


# ---------------------------------------------------------------- 夹具/工厂
def make_temp_result(
    root: str,
    entries: list[TempEntry],
    *,
    completeness: Completeness = Completeness.FULL,
    warnings: list[ScanWarning] | None = None,
    unreadable: int = 0,
) -> TempScanResult:
    return TempScanResult(
        roots=[TempRoot(path=root, kind="temp", exists=True)],
        entries=entries,
        total_size=sum(entry.size for entry in entries),
        total_files=sum(entry.file_count for entry in entries),
        unreadable=unreadable,
        completeness=completeness,
        warnings=warnings or [],
        probe_note="测试",
    )


def make_entry(
    root: str,
    name: str,
    *,
    size: int = 1024,
    occupancy: Occupancy = Occupancy.FREE,
    is_dir: bool = False,
    mtime: float = NOW,
) -> TempEntry:
    return TempEntry(
        root=root,
        path=os.path.join(root, name),
        is_dir=is_dir,
        size=size,
        file_count=1,
        mtime=mtime,
        occupancy=occupancy,
    )


def enabled_policy() -> ActionPolicy:
    return ActionPolicy(stage2_enabled=True, allow_delete_temp=True)


def partial_verdict() -> CompletenessVerdict:
    return CompletenessVerdict("partial", (Reason("permission_limited", "非管理员"),))


def process_result(temp: TempScanResult) -> ProcessScanResult:
    return ProcessScanResult(
        tree=ProcessTree(),
        started_at=NOW,
        finished_at=NOW + 1,
        temp=temp,
    )


# ---------------------------------------------------------------- 完整度适配
def test_temp_verdict_non_admin_is_partial() -> None:
    result = make_temp_result(r"C:\Temp", [make_entry(r"C:\Temp", "a.tmp")], completeness=Completeness.PARTIAL)
    assert temp_scan_verdict(result, is_admin=False).level == "partial"
    assert temp_scan_verdict(result, is_admin=True).level == "full"


def test_temp_verdict_budget_is_limited() -> None:
    result = make_temp_result(
        r"C:\Temp",
        [make_entry(r"C:\Temp", "a.tmp")],
        warnings=[ScanWarning("temp_budget", "预算上限")],
    )
    assert temp_scan_verdict(result, is_admin=True).level == "limited"


def test_temp_verdict_no_data_is_limited() -> None:
    result = make_temp_result(r"C:\Temp", [])
    assert temp_scan_verdict(result, is_admin=True).level == "limited"


# ---------------------------------------------------------------- 目标与勾选
def test_entry_selectable_rules() -> None:
    root = r"C:\Temp"
    assert entry_selectable(make_entry(root, "a.tmp")) is True
    assert entry_selectable(make_entry(root, "b.tmp", occupancy=Occupancy.NOT_PROBED)) is True
    assert entry_selectable(make_entry(root, "c.tmp", occupancy=Occupancy.LOCKED)) is False
    assert entry_selectable(make_entry(root, "d.tmp", occupancy=Occupancy.NO_ACCESS)) is False
    assert entry_selectable(make_entry(root, "sub", is_dir=True)) is False


def test_delete_targets_from_entries() -> None:
    root = r"C:\Temp"
    targets = delete_targets_from_entries(
        [make_entry(root, "a.tmp")],
        [TempRoot(path=root, kind="temp", exists=True)],
    )
    assert len(targets) == 1
    assert targets[0].path == os.path.join(root, "a.tmp")
    assert targets[0].root_allowed is True
    assert targets[0].mtime == NOW


def test_build_delete_preview_allowed_and_refused(tmp_path) -> None:
    root = str(tmp_path)
    entry = make_entry(root, "a.tmp")
    result = make_temp_result(root, [entry])
    targets, decision, token = build_delete_preview(
        [entry],
        result.roots,
        policy=enabled_policy(),
        verdict=partial_verdict(),
        now=NOW,
        token_id="t1",
    )
    assert decision.allowed is True and token is not None
    assert token.item_count == 1 and token.total_bytes == entry.size
    assert len(targets) == 1

    disabled = ActionPolicy()  # 默认关闭
    _targets, refused_decision, refused_token = build_delete_preview(
        [entry], result.roots, policy=disabled, verdict=partial_verdict(), now=NOW, token_id="t2"
    )
    assert refused_decision.allowed is False and refused_token is None


# ---------------------------------------------------------------- 执行器
def _executor_target(tmp_path, name: str = "a.tmp", content: bytes = b"x" * 100):
    from perf_purifier.core.action_policy import DeleteTarget

    path = tmp_path / name
    path.write_bytes(content)
    stat_result = os.stat(path)
    return DeleteTarget(
        path=str(path),
        root=str(tmp_path),
        size=int(stat_result.st_size),
        mtime=float(stat_result.st_mtime),
        occupancy="free",
    )


def test_executor_success_and_backend_called(tmp_path) -> None:
    backend = RecordingTrashBackend()
    target = _executor_target(tmp_path)
    result = DeleteTempExecutor(backend)(target)
    assert result.result == "success"
    assert backend.sent == [target.path]
    assert os.path.exists(target.path)  # fake backend 不真正删除


def test_executor_stale_missing_file(tmp_path) -> None:
    from perf_purifier.core.action_policy import DeleteTarget

    target = DeleteTarget(path=str(tmp_path / "gone.tmp"), root=str(tmp_path), size=1)
    result = DeleteTempExecutor(RecordingTrashBackend())(target)
    assert result.result == "refused"
    assert result.error_code == "stale"


def test_executor_identity_changed(tmp_path) -> None:
    from dataclasses import replace

    target = _executor_target(tmp_path)
    changed = replace(target, size=target.size + 1)
    assert DeleteTempExecutor(RecordingTrashBackend())(changed).error_code == "identity_changed"


def test_executor_refuses_directory(tmp_path) -> None:
    from perf_purifier.core.action_policy import DeleteTarget

    directory = tmp_path / "dir"
    directory.mkdir()
    target = DeleteTarget(path=str(directory), root=str(tmp_path), size=0)
    assert DeleteTempExecutor(RecordingTrashBackend())(target).error_code == "dir_not_supported"


def test_executor_refuses_reparse(monkeypatch, tmp_path) -> None:
    target = _executor_target(tmp_path)
    monkeypatch.setattr(
        "perf_purifier.module_a.temp_delete.is_reparse_point", lambda path: True
    )
    assert DeleteTempExecutor(RecordingTrashBackend())(target).error_code == "reparse_point"


def test_executor_refuses_outside_root(tmp_path) -> None:
    from dataclasses import replace

    target = _executor_target(tmp_path)
    other_root = tmp_path / "other"
    other_root.mkdir()
    changed = replace(target, root=str(other_root))
    assert DeleteTempExecutor(RecordingTrashBackend())(changed).error_code == "outside_root"


def test_executor_refuses_protected_path() -> None:
    from perf_purifier.core.action_policy import DeleteTarget

    target = DeleteTarget(
        path=r"C:\Windows\System32\drivers\evil.tmp",
        root=r"C:\Windows\System32",
        size=100,
    )
    assert DeleteTempExecutor(RecordingTrashBackend())(target).error_code == "protected_path"


def test_executor_backend_failure(tmp_path) -> None:
    target = _executor_target(tmp_path)
    backend = RecordingTrashBackend(fail_paths=frozenset({target.path}), error_code="trash_failed")
    result = DeleteTempExecutor(backend)(target)
    assert result.result == "failed"
    assert result.error_code == "trash_failed"


# ---------------------------------------------------------------- 端到端（假后端）
def test_delete_job_full_flow_with_fake_backend(tmp_path) -> None:
    targets_files = [_executor_target(tmp_path, "a.tmp"), _executor_target(tmp_path, "b.tmp")]
    root = str(tmp_path)
    entries = [
        make_entry(
            root,
            "a.tmp",
            size=targets_files[0].size,
            mtime=targets_files[0].mtime,
        ),
        make_entry(
            root,
            "b.tmp",
            size=targets_files[1].size,
            mtime=targets_files[1].mtime,
        ),
    ]
    temp_result = make_temp_result(root, entries)
    temp_roots = temp_result.roots
    policy = enabled_policy()
    targets, decision, token = build_delete_preview(
        entries, temp_roots, policy=policy, verdict=partial_verdict(), now=NOW, token_id="token-1"
    )
    assert token is not None and decision.allowed
    backend = RecordingTrashBackend(fail_paths=frozenset({targets_files[1].path}))
    audit = ActionAuditWriter(tmp_path / "logs")
    job = ActionJob(
        action=ActionKind.DELETE_TEMP,
        token=token,
        targets=targets,
        allowed_indices=decision.allowed_indices,
        executor=DeleteTempExecutor(backend),
        audit=audit,
        verdict=partial_verdict(),
        is_admin=False,
        app_version="0.1.0",
        session_id="session-1",
        dry_run=False,
        clock=lambda: NOW,
    )
    box: dict = {}
    job.finished.connect(lambda result: box.setdefault("result", result))
    job.run()
    session: ActionSessionResult = box["result"]
    assert [item.result for item in session.results] == ["success", "failed"]
    assert backend.sent == [targets_files[0].path, targets_files[1].path]
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert records[0]["record_type"] == "action_header"
    assert records[0]["action"] == "delete_temp"
    assert records[0]["dry_run"] is False
    assert records[2]["error_code"] == "trash_failed"


# ---------------------------------------------------------------- 真实后端（不移动文件！）
def test_send2trash_backend_unavailable(monkeypatch) -> None:
    monkeypatch.setattr("perf_purifier.core.trash._send2trash", None)
    outcome = Send2TrashBackend().send(r"C:\Temp\never-moved.tmp")
    assert outcome.result == "failed"
    assert outcome.error_code == "backend_unavailable"


# ---------------------------------------------------------------- UI 勾选规则
def test_temp_page_checkbox_and_default_off(qapp, tmp_path) -> None:
    root = str(tmp_path)
    entries = [
        make_entry(root, "free.tmp", size=1000),
        make_entry(root, "locked.tmp", size=2000, occupancy=Occupancy.LOCKED),
    ]
    page = TempPage(AppConfig(), is_admin=False, app_version="0.1.0")
    page.set_result(process_result(make_temp_result(root, entries)))

    model = page._model
    free_index = model.index(0, 0)
    locked_index = model.index(1, 0)
    assert model.flags(free_index) & Qt.ItemFlag.ItemIsUserCheckable
    assert not (model.flags(locked_index) & Qt.ItemFlag.ItemIsUserCheckable)

    assert model.setData(free_index, Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
    assert model.checked_count == 1
    assert model.checked_bytes == 1000
    assert "已选 1 项" in page._selection_label.text()
    # 默认配置下删除功能关闭 → 按钮仍不可用
    assert page._btn_delete.isEnabled() is False
    _dispose_page(page, qapp)


def test_temp_page_delete_enabled_only_with_stage2_config(qapp, tmp_path) -> None:
    root = str(tmp_path)
    entries = [make_entry(root, "free.tmp", size=1000)]
    config = AppConfig()
    config.stage2_enabled = True
    config.allow_delete_temp = True
    page = TempPage(config, is_admin=False, app_version="0.1.0")
    page.set_result(process_result(make_temp_result(root, entries)))
    model = page._model
    assert not page._btn_delete.isEnabled()
    model.setData(model.index(0, 0), Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
    assert page._btn_delete.isEnabled()
    page._on_clear_selection()
    assert not page._btn_delete.isEnabled()
    _dispose_page(page, qapp)
