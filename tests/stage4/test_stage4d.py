"""阶段 4D 测试：审计 action_end 结束记录 + 历史页未完成会话提示。"""

from __future__ import annotations

import json

from perf_purifier.core.action_history import incomplete_sessions, load_history
from perf_purifier.core.action_policy import ActionKind, build_preview_token
from perf_purifier.core.audit import ActionAuditWriter, AuditEnd
from perf_purifier.core.judgements import CompletenessVerdict, Reason
from perf_purifier.jobs.action_job import ActionJob, DryRunExecutor
from perf_purifier.ui.pages.page_history import HistoryPage

NOW = 1_700_000_000.0


def _dispose_page(page, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    page.setParent(None)
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


def test_audit_end_record_shape(tmp_path) -> None:
    writer = ActionAuditWriter(tmp_path)
    writer.write_end(
        AuditEnd(ts="2026-01-01T10:00:00", session_id="s1", action="delete_temp", status="completed")
    )
    record = json.loads(writer.path.read_text(encoding="utf-8").splitlines()[0])
    assert record["record_type"] == "action_end"
    assert record["session_id"] == "s1"


def test_action_job_writes_end_record(qapp, tmp_path) -> None:
    token = build_preview_token(
        action=ActionKind.DELETE_TEMP,
        target_signature_value="sig",
        item_count=1,
        total_bytes=0,
        token_id="t1",
        now=NOW,
    )
    from perf_purifier.core.action_policy import DeleteTarget

    target = DeleteTarget(path=r"C:\Temp\a.tmp", root=r"C:\Temp", size=0)
    audit = ActionAuditWriter(tmp_path)
    job = ActionJob(
        action=ActionKind.DELETE_TEMP,
        token=token,
        targets=[target],
        allowed_indices=[0],
        executor=DryRunExecutor(),
        audit=audit,
        verdict=CompletenessVerdict("partial", (Reason("permission_limited", "非管理员"),)),
        is_admin=False,
        app_version="0.1.0",
        session_id="session-end",
        dry_run=True,
        clock=lambda: NOW,
    )
    job.run()
    records = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines()]
    assert [record["record_type"] for record in records] == [
        "action_header",
        "action_item",
        "action_end",
    ]
    assert records[2]["status"] == "completed"
    assert records[2]["total"] == 1


def test_history_marks_finished_and_incomplete(tmp_path) -> None:
    header = {
        "record_type": "action_header",
        "ts": "t",
        "session_id": "s1",
        "action": "delete_temp",
        "item_count": 1,
    }
    item = {
        "record_type": "action_item",
        "ts": "t",
        "session_id": "s1",
        "action": "delete_temp",
        "target": "a",
        "result": "success",
    }
    end = {
        "record_type": "action_end",
        "ts": "t",
        "session_id": "s1",
        "action": "delete_temp",
        "status": "completed",
    }
    path = tmp_path / "operations.jsonl"
    path.write_text(
        "\n".join(json.dumps(record) for record in (header, item, end)) + "\n", encoding="utf-8"
    )
    loaded = load_history(tmp_path)
    summary = loaded.sessions[0]
    assert summary.finished is True
    assert incomplete_sessions(loaded.sessions) == ()

    path.write_text("\n".join(json.dumps(record) for record in (header, item)) + "\n", encoding="utf-8")
    loaded = load_history(tmp_path)
    assert loaded.sessions[0].finished is False
    assert len(incomplete_sessions(loaded.sessions)) == 1


def test_history_page_warns_incomplete(qapp, tmp_path) -> None:
    header = {
        "record_type": "action_header",
        "ts": "t",
        "session_id": "s1",
        "action": "delete_temp",
    }
    item = {
        "record_type": "action_item",
        "ts": "t",
        "session_id": "s1",
        "action": "delete_temp",
        "result": "success",
    }
    (tmp_path / "operations.jsonl").write_text(
        "\n".join(json.dumps(record) for record in (header, item)) + "\n", encoding="utf-8"
    )
    page = HistoryPage(log_directory=tmp_path)
    assert "未完成会话" in page._summary.text()
    _dispose_page(page, qapp)
