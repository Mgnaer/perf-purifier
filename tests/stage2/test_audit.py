"""2A 审计日志测试：record 结构、header→items 顺序、严格失败（AuditWriteError）。"""

from __future__ import annotations

import json

import pytest

from perf_purifier.core.audit import (
    ActionAuditWriter,
    AuditHeader,
    AuditItem,
    AuditWriteError,
    format_audit_timestamp,
)

NOW = 1_700_000_000.0


def _header() -> AuditHeader:
    return AuditHeader(
        ts=format_audit_timestamp(NOW),
        session_id="session-1",
        token_id="token-1",
        action="delete_temp",
        policy_version="2a.1",
        verdict_level="partial",
        verdict_codes=("permission_limited",),
        is_admin=False,
        item_count=2,
        total_bytes=2048,
        app_version="0.1.0",
        dry_run=True,
    )


def _item(index: int = 0) -> AuditItem:
    return AuditItem(
        ts=format_audit_timestamp(NOW),
        session_id="session-1",
        action="delete_temp",
        target=rf"C:\Temp\f{index}.tmp",
        identity="path=...;size=100",
        result="dry_run",
        error_code="",
        detail="未执行任何真实动作",
        duration_ms=1,
    )


def test_header_and_item_record_shapes() -> None:
    header = _header().to_dict()
    assert header["record_type"] == "action_header"
    assert header["verdict_codes"] == ["permission_limited"]
    assert header["dry_run"] is True
    item = _item().to_dict()
    assert item["record_type"] == "action_item"
    assert item["session_id"] == "session-1"
    assert json.dumps(header, ensure_ascii=False)


def test_writer_appends_header_then_items(tmp_path) -> None:
    writer = ActionAuditWriter(tmp_path)
    writer.write_header(_header())
    writer.write_item(_item(0))
    writer.write_item(_item(1))

    lines = writer.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    records = [json.loads(line) for line in lines]
    assert [record["record_type"] for record in records] == [
        "action_header",
        "action_item",
        "action_item",
    ]
    assert records[0]["session_id"] == records[1]["session_id"]
    assert writer.path.name == "operations.jsonl"


def test_writer_is_append_only_across_instances(tmp_path) -> None:
    ActionAuditWriter(tmp_path).write_header(_header())
    ActionAuditWriter(tmp_path).write_item(_item())
    assert len(ActionAuditWriter(tmp_path).path.read_text(encoding="utf-8").splitlines()) == 2


def test_writer_raises_on_io_failure(tmp_path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    writer = ActionAuditWriter(blocker)
    with pytest.raises(AuditWriteError):
        writer.write_header(_header())


def test_timestamp_format_is_stable() -> None:
    ts = format_audit_timestamp(NOW)
    assert "T" in ts
    assert len(ts) >= 19
