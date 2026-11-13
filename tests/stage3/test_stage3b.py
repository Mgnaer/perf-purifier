"""阶段 3B 测试：动作历史只读解析 + 历史页（容错/筛选/只读/无危险入口）。"""

from __future__ import annotations

import json

from perf_purifier.core.action_history import (
    filter_records,
    load_history,
    summarize_sessions,
)
from perf_purifier.ui.pages.page_history import HistoryPage


def _write_jsonl(path, records) -> None:
    path.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )


def _header(session: str, action: str = "delete_temp", **overrides) -> dict:
    record = {
        "record_type": "action_header",
        "ts": "2026-01-01T10:00:00",
        "session_id": session,
        "action": action,
        "policy_version": "2a.1",
        "verdict_level": "partial",
        "verdict_codes": ["permission_limited"],
        "is_admin": False,
        "item_count": 2,
        "total_bytes": 100,
        "app_version": "0.1.0",
        "dry_run": False,
    }
    record.update(overrides)
    return record


def _item(session: str, result: str, target: str, action: str = "delete_temp", **overrides) -> dict:
    record = {
        "record_type": "action_item",
        "ts": "2026-01-01T10:00:01",
        "session_id": session,
        "action": action,
        "target": target,
        "identity": "path=...",
        "result": result,
        "error_code": "" if result == "success" else "perm_denied",
        "detail": "",
        "duration_ms": 3,
    }
    record.update(overrides)
    return record


# ---------------------------------------------------------------- 解析
def test_load_records_and_sessions(tmp_path) -> None:
    _write_jsonl(
        tmp_path / "operations.jsonl",
        [
            _header("s1"),
            _item("s1", "success", r"C:\Temp\a.tmp"),
            _item("s1", "failed", r"C:\Temp\b.tmp"),
        ],
    )
    _write_jsonl(
        tmp_path / "operations-20260101-090000.jsonl",
        [_header("s0", action="kill_process"), _item("s0", "success", "PID 123", action="kill_process")],
    )

    result = load_history(tmp_path)
    assert result.files_read == 2
    assert len(result.records) == 5
    assert {summary.session_id for summary in result.sessions} == {"s1", "s0"}
    s1 = next(summary for summary in result.sessions if summary.session_id == "s1")
    assert s1.success == 1 and s1.failed == 1 and s1.verdict_level == "partial"
    # 最新文件（主文件）的记录排在前面
    assert result.records[0].session_id == "s1"


def test_bad_lines_are_skipped_not_fatal(tmp_path) -> None:
    path = tmp_path / "operations.jsonl"
    path.write_text(
        "\n".join(
            [
                "",
                "not-json",
                '{"record_type":"unknown","session_id":"x","action":"y"}',
                "[1,2,3]",
                '{"record_type":"action_item","action":"delete_temp"}',  # 缺 session_id
                "x" * (64 * 1024 + 10),  # 超长行
                json.dumps(_header("s1"), ensure_ascii=False),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = load_history(tmp_path)
    assert len(result.records) == 1
    assert result.records[0].session_id == "s1"
    assert result.skipped_lines >= 4


def test_truncated_by_byte_budget(tmp_path) -> None:
    records = [_header("s1")] + [
        _item("s1", "success" if index % 2 else "failed", rf"C:\Temp\f{index}.tmp")
        for index in range(40)
    ]
    _write_jsonl(tmp_path / "operations.jsonl", records)
    result = load_history(tmp_path, max_bytes=300)
    assert result.truncated is True
    assert 0 < len(result.records) < len(records)
    assert result.bytes_read <= 300


def test_filter_records() -> None:
    history = load_history_from_records(
        [
            _header("s1"),
            _item("s1", "success", r"C:\Temp\a.tmp"),
            _item("s1", "failed", r"C:\Temp\b.tmp"),
            _header("s2", action="kill_process"),
            _item("s2", "success", "PID 456", action="kill_process"),
        ]
    )
    assert len(filter_records(history, action="kill_process")) == 2
    assert len(filter_records(history, result="failed")) == 1
    assert len(filter_records(history, search="b.tmp")) == 1
    assert len(filter_records(history, session_id="s2")) == 2
    assert len(filter_records(history, action="delete_temp", result="success")) == 1


def load_history_from_records(records):
    from perf_purifier.core.action_history import HistoryRecord

    parsed = []
    for record in records:
        parsed.append(
            HistoryRecord(
                ts=record.get("ts", ""),
                record_type=record["record_type"],
                session_id=record["session_id"],
                action=record["action"],
                target=record.get("target", ""),
                result=record.get("result", ""),
                error_code=record.get("error_code", ""),
                dry_run=bool(record.get("dry_run", False)),
                raw=record,
            )
        )
    return tuple(parsed)


def test_missing_header_still_summarized(tmp_path) -> None:
    _write_jsonl(tmp_path / "operations.jsonl", [_item("s9", "refused", "PID 1")])
    result = load_history(tmp_path)
    summary = result.sessions[0]
    assert summary.session_id == "s9"
    assert summary.refused == 1
    assert summary.ts == ""


def test_summarize_sessions_counts_dry_run() -> None:
    records = load_history_from_records(
        [
            _header("s1", dry_run=True),
            _item("s1", "dry_run", "a"),
            _item("s1", "dry_run", "b"),
        ]
    )
    summary = summarize_sessions(records)[0]
    assert summary.dry_run == 2


# ---------------------------------------------------------------- 历史页（只读 UI）
def _dispose_page(page, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    page.setParent(None)
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


def test_history_page_is_read_only(qapp, tmp_path) -> None:
    log_file = tmp_path / "operations.jsonl"
    _write_jsonl(
        log_file,
        [
            _header("s1"),
            _item("s1", "success", r"C:\Temp\a.tmp"),
            _item("s1", "failed", r"C:\Temp\b.tmp"),
        ],
    )
    before = log_file.read_bytes()
    page = HistoryPage(log_directory=tmp_path)
    assert page._model.rowCount() == 3
    assert "只读" in page._summary.text()

    # 筛选：动作 / 结果
    page._action_combo.setCurrentIndex(1)  # 删除到回收站
    assert page._model.rowCount() == 3
    page._result_combo.setCurrentIndex(2)  # 失败
    assert page._model.rowCount() == 1

    # 详情只显示原始 JSON 文本
    page._view.setCurrentIndex(page._model.index(0, 0))
    page._show_detail(page._model.index(0, 0))
    detail = page._detail.toPlainText()
    assert "session_id" in detail and "s1" in detail

    # 只读：日志文件未被修改
    assert log_file.read_bytes() == before

    # 无任何可触发动作的按钮（只读页）
    from PySide6.QtWidgets import QPushButton

    for button in page.findChildren(QPushButton):
        text = button.text()
        assert not any(keyword in text for keyword in ("删除", "执行", "结束", "硬链接", "撤销", "重做"))
    _dispose_page(page, qapp)


def test_history_page_empty_directory(qapp, tmp_path) -> None:
    page = HistoryPage(log_directory=tmp_path)
    assert page._model.rowCount() == 0
    assert "暂无动作历史" in page._summary.text()
    _dispose_page(page, qapp)
