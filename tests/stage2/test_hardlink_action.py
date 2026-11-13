"""阶段 2D 硬链接去重测试（真实临时文件 + 假/真卷探测；不触碰系统文件）。

覆盖：完整度适配、组可选择性、目标构建、预览 token、执行器安全替换/冲突拒绝、
ActionJob 端到端（真实硬链接 + 审计）、UI 勾选与默认关闭。
"""

from __future__ import annotations

import hashlib
import json
import os

from PySide6.QtCore import Qt

from perf_purifier.core.action_policy import ActionKind, ActionPolicy
from perf_purifier.core.audit import ActionAuditWriter
from perf_purifier.core.config import AppConfig
from perf_purifier.core.judgements import CompletenessVerdict, FileMeta, Reason
from perf_purifier.core.models import (
    Completeness,
    DuplicateGroup,
    FileRecord,
    FileScanOptions,
    FileScanResult,
)
from perf_purifier.jobs.action_job import ActionJob, ActionSessionResult
from perf_purifier.module_b.hardlink_action import (
    HardlinkExecutor,
    build_hardlink_preview,
    canonical_for_group,
    file_scan_verdict,
    group_selectable,
    hardlink_targets_from_groups,
)
from perf_purifier.ui.pages.page_duplicates import DuplicatesPage

NOW = 1_700_000_000.0


def enabled_policy() -> ActionPolicy:
    return ActionPolicy(stage2_enabled=True, allow_hardlink_dedupe=True)


def partial_verdict() -> CompletenessVerdict:
    return CompletenessVerdict("partial", (Reason("permission_limited", "非管理员"),))


def _sha256(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record(path) -> FileRecord:
    stat_result = os.stat(path)
    return FileRecord(
        path=str(path),
        size=int(stat_result.st_size),
        mtime=float(stat_result.st_mtime),
        dev=int(stat_result.st_dev),
        ino=int(stat_result.st_ino),
    )


def _group(paths, content_sha: str) -> DuplicateGroup:
    records = [_record(path) for path in paths]
    return DuplicateGroup(
        group_id=1,
        size=records[0].size,
        full_sha256=content_sha,
        files=tuple(records),
        distinct_inodes=len(records),
        suggested_keep_path=records[0].path,
    )


def _make_pair(tmp_path, content: bytes):
    canonical = tmp_path / "keep.bin"
    redundant = tmp_path / "dup.bin"
    canonical.write_bytes(content)
    redundant.write_bytes(content)
    return canonical, redundant


def _meta(record: FileRecord) -> FileMeta:
    return FileMeta(path=record.path, st_dev=record.dev, st_ino=record.ino, size=record.size)


# ---------------------------------------------------------------- 完整度/组选择
def test_file_scan_verdict_mapping() -> None:
    base = dict(
        root=r"C:\data",
        options=FileScanOptions(root=r"C:\data"),
        started_at=NOW,
        finished_at=NOW + 1,
        files_scanned=100,
    )
    full = FileScanResult(**base, completeness=Completeness.FULL)
    assert file_scan_verdict(full, is_admin=True).level == "full"
    assert file_scan_verdict(full, is_admin=False).level == "full"
    partial = FileScanResult(**base, completeness=Completeness.PARTIAL)
    assert file_scan_verdict(partial, is_admin=False).level == "partial"
    truncated = FileScanResult(**base, completeness=Completeness.FULL, truncated=True)
    assert file_scan_verdict(truncated, is_admin=True).level == "limited"


def test_group_selectable_and_canonical(tmp_path) -> None:
    canonical, redundant = _make_pair(tmp_path, b"same-content")
    group = _group([canonical, redundant], _sha256(canonical))
    assert group_selectable(group) is True
    assert canonical_for_group(group).path == str(canonical)

    linked = DuplicateGroup(
        group_id=2,
        size=group.size,
        full_sha256=group.full_sha256,
        files=group.files,
        distinct_inodes=1,
        has_hardlinks=True,
        already_hardlinked=True,
    )
    assert group_selectable(linked) is False


# ---------------------------------------------------------------- 目标与预览
def test_targets_and_preview(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "perf_purifier.module_b.hardlink_action.is_ntfs_volume", lambda path: True
    )
    canonical, redundant = _make_pair(tmp_path, b"same-content")
    group = _group([canonical, redundant], _sha256(canonical))
    targets = hardlink_targets_from_groups([group])
    assert len(targets) == 1
    assert targets[0].canonical.path == str(canonical)
    assert targets[0].redundant.path == str(redundant)
    assert targets[0].same_volume is True
    assert targets[0].ntfs is True

    _targets, decision, token = build_hardlink_preview(
        [group], policy=enabled_policy(), verdict=partial_verdict(), now=NOW, token_id="t1"
    )
    assert decision.allowed is True and token is not None
    assert token.item_count == 1 and token.total_bytes == group.size

    _targets, refused, refused_token = build_hardlink_preview(
        [group], policy=ActionPolicy(), verdict=partial_verdict(), now=NOW, token_id="t2"
    )
    assert refused.allowed is False and refused_token is None


# ---------------------------------------------------------------- 执行器
def test_executor_success_replaces_with_hardlink(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "perf_purifier.module_b.hardlink_action.is_ntfs_volume", lambda path: True
    )
    canonical, redundant = _make_pair(tmp_path, b"same-content-123")
    sha = _sha256(canonical)
    group = _group([canonical, redundant], sha)
    target = hardlink_targets_from_groups([group])[0]
    result = HardlinkExecutor()(target)
    assert result.result == "success"
    canonical_stat = os.stat(canonical)
    redundant_stat = os.stat(redundant)
    assert (canonical_stat.st_dev, canonical_stat.st_ino) == (
        redundant_stat.st_dev,
        redundant_stat.st_ino,
    )
    assert redundant.read_bytes() == b"same-content-123"
    assert canonical_stat.st_nlink == 2


def test_executor_refuses_content_mismatch(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "perf_purifier.module_b.hardlink_action.is_ntfs_volume", lambda path: True
    )
    canonical, redundant = _make_pair(tmp_path, b"same-content")
    group = _group([canonical, redundant], "f" * 64)  # 故意错误的哈希
    target = hardlink_targets_from_groups([group])[0]
    result = HardlinkExecutor()(target)
    assert result.result == "refused"
    assert result.error_code == "content_changed"
    # 文件未被替换
    assert os.stat(canonical).st_ino != os.stat(redundant).st_ino


def test_executor_refuses_non_ntfs(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "perf_purifier.module_b.hardlink_action.is_ntfs_volume", lambda path: False
    )
    canonical, redundant = _make_pair(tmp_path, b"same-content")
    group = _group([canonical, redundant], _sha256(canonical))
    target = hardlink_targets_from_groups([group])[0]
    assert HardlinkExecutor()(target).error_code == "non_ntfs"


def test_executor_refuses_stale(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "perf_purifier.module_b.hardlink_action.is_ntfs_volume", lambda path: True
    )
    canonical, redundant = _make_pair(tmp_path, b"same-content")
    group = _group([canonical, redundant], _sha256(canonical))
    target = hardlink_targets_from_groups([group])[0]
    redundant.unlink()
    assert HardlinkExecutor()(target).error_code == "stale"


def test_executor_replace_failure_keeps_data(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "perf_purifier.module_b.hardlink_action.is_ntfs_volume", lambda path: True
    )
    canonical, redundant = _make_pair(tmp_path, b"same-content")
    group = _group([canonical, redundant], _sha256(canonical))
    target = hardlink_targets_from_groups([group])[0]

    import perf_purifier.module_b.hardlink_action as module

    def broken_replace(source, destination):
        raise OSError("模拟替换失败")

    monkeypatch.setattr(module.os, "replace", broken_replace)
    result = HardlinkExecutor()(target)
    assert result.result == "failed"
    assert result.error_code == "replace_failed"
    assert redundant.read_bytes() == b"same-content"
    leftovers = [name for name in os.listdir(tmp_path) if ".pp-link-" in name]
    assert leftovers == []


# ---------------------------------------------------------------- 端到端（真实硬链接）
def test_hardlink_job_full_flow(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "perf_purifier.module_b.hardlink_action.is_ntfs_volume", lambda path: True
    )
    canonical, redundant = _make_pair(tmp_path, b"same-content")
    sha = _sha256(canonical)
    group = _group([canonical, redundant], sha)
    targets, decision, token = build_hardlink_preview(
        [group], policy=enabled_policy(), verdict=partial_verdict(), now=NOW, token_id="token-1"
    )
    assert token is not None and decision.allowed
    audit = ActionAuditWriter(tmp_path / "logs")
    job = ActionJob(
        action=ActionKind.HARDLINK_DEDUPE,
        token=token,
        targets=targets,
        allowed_indices=decision.allowed_indices,
        executor=HardlinkExecutor(),
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
    assert [item.result for item in session.results] == ["success"]
    assert os.stat(canonical).st_ino == os.stat(redundant).st_ino
    records = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["action"] == "hardlink_dedupe"
    assert records[1]["result"] == "success"


# ---------------------------------------------------------------- UI 勾选与默认关闭
def _dispose_page(page, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    page.setParent(None)
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


def test_duplicates_page_group_checkbox_and_default_off(qapp, synthetic_file_result) -> None:
    page = DuplicatesPage(AppConfig(), is_admin=False, app_version="0.1.0")
    page.set_result(synthetic_file_result)
    model = page._group_model
    # synthetic_file_result：组 1 普通重复组（可选），组 2 已互为硬链接（不可选）
    assert model.flags(model.index(0, 0)) & Qt.ItemFlag.ItemIsUserCheckable
    assert not (model.flags(model.index(1, 0)) & Qt.ItemFlag.ItemIsUserCheckable)
    assert model.setData(
        model.index(0, 0), Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole
    )
    assert model.checked_count == 1
    assert "已选 1 个重复组" in page._group_selection_label.text()
    # 默认配置关闭 → 按钮不可用
    assert page._btn_hardlink.isEnabled() is False
    _dispose_page(page, qapp)


def test_duplicates_page_hardlink_enabled_with_config(qapp, synthetic_file_result) -> None:
    config = AppConfig()
    config.stage2_enabled = True
    config.allow_hardlink_dedupe = True
    page = DuplicatesPage(config, is_admin=False, app_version="0.1.0")
    page.set_result(synthetic_file_result)
    model = page._group_model
    assert not page._btn_hardlink.isEnabled()
    model.setData(model.index(0, 0), Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
    assert page._btn_hardlink.isEnabled()
    page._on_clear_group_selection()
    assert not page._btn_hardlink.isEnabled()
    _dispose_page(page, qapp)
