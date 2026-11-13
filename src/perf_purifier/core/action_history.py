"""阶段 3B：动作历史只读解析（``operations.jsonl`` + 轮转文件）。

安全约束（docs/05）：
* 只读：不写日志、不执行日志中的任何内容；
* 字节上限：从最新日志的尾部读取，超出上限标记 ``truncated``；
* 容错：坏行/非法 JSON/超长行跳过并计数，不抛异常；
* 解码使用 ``errors="replace"``，不因非法字节崩溃。
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import AUDIT_FILENAME, ROTATED_PREFIX

DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_RECORDS = 20_000
MAX_LINE_BYTES = 64 * 1024

ACTION_LABELS: dict[str, str] = {
    "delete_temp": "删除到回收站",
    "hardlink_dedupe": "硬链接去重",
    "kill_process": "结束进程",
    "hardlink_detach": "硬链接独立化",
    "clean_space": "磁盘清理",
}
RESULT_LABELS: dict[str, str] = {
    "success": "成功",
    "failed": "失败",
    "refused": "拒绝",
    "skipped": "跳过",
    "dry_run": "预演",
}
RESULT_KEYS: tuple[str, ...] = ("success", "failed", "refused", "skipped", "dry_run")


@dataclass(frozen=True, slots=True)
class HistoryRecord:
    ts: str
    record_type: str
    session_id: str
    action: str
    target: str = ""
    result: str = ""
    error_code: str = ""
    dry_run: bool = False
    raw: dict[str, Any] = field(default_factory=dict)
    source_file: str = ""

    @property
    def is_header(self) -> bool:
        return self.record_type == "action_header"

    @property
    def is_end(self) -> bool:
        return self.record_type == "action_end"


@dataclass(frozen=True, slots=True)
class SessionSummary:
    session_id: str
    action: str
    ts: str = ""
    verdict_level: str = ""
    item_count: int = 0
    success: int = 0
    failed: int = 0
    refused: int = 0
    skipped: int = 0
    dry_run: int = 0
    finished: bool = False
    end_status: str = ""


def incomplete_sessions(sessions: tuple[SessionSummary, ...]) -> tuple[SessionSummary, ...]:
    """未写 action_end 的会话（可能中断/崩溃，只做提示，不推断原因）。"""

    return tuple(summary for summary in sessions if not summary.finished)


@dataclass(frozen=True, slots=True)
class HistoryLoadResult:
    records: tuple[HistoryRecord, ...] = ()
    sessions: tuple[SessionSummary, ...] = ()
    skipped_lines: int = 0
    truncated: bool = False
    files_read: int = 0
    bytes_read: int = 0


def _history_files(directory: Path) -> list[Path]:
    """主文件最新 → 轮转文件按修改时间从新到旧。"""

    files: list[Path] = []
    main = directory / AUDIT_FILENAME
    if main.exists():
        files.append(main)
    rotated: list[Path] = []
    try:
        for candidate in directory.glob(f"{ROTATED_PREFIX}*.jsonl"):
            try:
                rotated.append((candidate.stat().st_mtime, candidate))  # type: ignore[arg-type]
            except OSError:
                continue
    except OSError:
        rotated = []
    for _mtime, path in sorted(rotated, key=lambda item: item[0], reverse=True):
        files.append(path)
    return files


def _parse_record(raw: dict[str, Any], source: str) -> HistoryRecord | None:
    record_type = str(raw.get("record_type", ""))
    if record_type not in ("action_header", "action_item", "action_end"):
        return None
    session_id = str(raw.get("session_id", ""))
    action = str(raw.get("action", ""))
    if not session_id or not action:
        return None
    return HistoryRecord(
        ts=str(raw.get("ts", "")),
        record_type=record_type,
        session_id=session_id,
        action=action,
        target=str(raw.get("target", "")),
        result=str(raw.get("result", "")),
        error_code=str(raw.get("error_code", "")),
        dry_run=bool(raw.get("dry_run", False)),
        raw=raw,
        source_file=source,
    )


def load_history(
    log_directory: Path | str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> HistoryLoadResult:
    """从日志目录（含轮转文件）加载历史；任何 IO/格式问题都不抛异常。"""

    directory = Path(log_directory)
    budget = max(0, int(max_bytes))
    records: list[HistoryRecord] = []
    skipped_lines = 0
    truncated = False
    files_read = 0
    bytes_read = 0

    for path in _history_files(directory):
        if budget <= 0 or len(records) >= max_records:
            truncated = True
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0:
            continue
        take = min(size, budget)
        try:
            with path.open("rb") as handle:
                handle.seek(size - take)
                data = handle.read()
        except OSError:
            continue
        files_read += 1
        bytes_read += len(data)
        budget -= len(data)
        if take < size:
            truncated = True
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if take < size and lines:
            lines = lines[1:]  # 丢弃可能被截断的首行
        file_records: list[HistoryRecord] = []
        for line in lines:
            if len(line.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
                skipped_lines += 1
                continue
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except ValueError:
                skipped_lines += 1
                continue
            if not isinstance(raw, dict):
                skipped_lines += 1
                continue
            record = _parse_record(raw, path.name)
            if record is None:
                skipped_lines += 1
                continue
            file_records.append(record)
        records.extend(reversed(file_records))  # 文件内越新越靠后 → 反转成新到旧
        if len(records) >= max_records:
            truncated = True
            records = records[:max_records]
            break

    return HistoryLoadResult(
        records=tuple(records),
        sessions=summarize_sessions(records),
        skipped_lines=skipped_lines,
        truncated=truncated,
        files_read=files_read,
        bytes_read=bytes_read,
    )


def summarize_sessions(records: Iterable[HistoryRecord]) -> tuple[SessionSummary, ...]:
    """按 session_id 汇总（保持首次出现顺序；缺失 header 时用 item 补位）。"""

    order: list[str] = []
    actions: dict[str, str] = {}
    headers: dict[str, HistoryRecord] = {}
    counts: dict[str, dict[str, int]] = {}
    end_status: dict[str, str] = {}

    for record in records:
        session = record.session_id
        if session not in actions:
            order.append(session)
            actions[session] = record.action
            counts[session] = {key: 0 for key in RESULT_KEYS}
        if record.is_header:
            headers[session] = record
            continue
        if record.is_end:
            end_status[session] = str(record.raw.get("status", "completed"))
            continue
        if record.result in counts[session]:
            counts[session][record.result] += 1
        # 兼容未带 result 的旧记录：忽略计数

    summaries: list[SessionSummary] = []
    for session in order:
        header = headers.get(session)
        summary = SessionSummary(
            session_id=session,
            action=actions[session],
            ts=header.ts if header else "",
            verdict_level=str(header.raw.get("verdict_level", "")) if header else "",
            item_count=int(header.raw.get("item_count", 0)) if header else 0,
            success=counts[session]["success"],
            failed=counts[session]["failed"],
            refused=counts[session]["refused"],
            skipped=counts[session]["skipped"],
            dry_run=counts[session]["dry_run"],
            finished=session in end_status,
            end_status=end_status.get(session, ""),
        )
        summaries.append(summary)
    return tuple(summaries)


def filter_records(
    records: Iterable[HistoryRecord],
    *,
    action: str | None = None,
    result: str | None = None,
    search: str = "",
    session_id: str | None = None,
) -> tuple[HistoryRecord, ...]:
    """只读过滤：动作 / 结果 / 会话 / 文本（大小写不敏感）。"""

    keyword = search.strip().casefold()
    filtered: list[HistoryRecord] = []
    for record in records:
        if action and record.action != action:
            continue
        if result and record.result != result:
            continue
        if session_id and record.session_id != session_id:
            continue
        if keyword:
            haystack = " ".join(
                (record.ts, record.session_id, record.target, record.action, record.result, record.error_code)
            ).casefold()
            if keyword not in haystack:
                continue
        filtered.append(record)
    return tuple(filtered)


def action_label(action: str) -> str:
    return ACTION_LABELS.get(action, action or "—")


def result_label(result: str) -> str:
    return RESULT_LABELS.get(result, result or "—")
