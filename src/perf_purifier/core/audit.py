"""阶段 2 动作审计日志（``operations.jsonl``，append-only，严格模式）。

设计依据（docs/04）：**先写 session header 再执行**；逐项写 item；
写入失败立即抛 ``AuditWriteError``，由 ActionJob 中止后续动作并上报。
审计内容不含文件内容；命令行等敏感字段只允许写入脱敏后的文本。
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

AUDIT_FILENAME = "operations.jsonl"
ROTATED_PREFIX = "operations-"
AUDIT_MAX_BYTES = 10 * 1024 * 1024
AUDIT_KEEP_ROTATED = 10
AUDIT_RETENTION_DAYS = 30


class AuditWriteError(RuntimeError):
    """审计日志写入失败（必须在执行前或执行中中止，不允许静默继续）。"""


def format_audit_timestamp(now: float) -> str:
    """本地时区 ISO 时间（审计日志用；``now`` 由调用方注入保证可测试）。"""

    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now))


@dataclass(frozen=True, slots=True)
class AuditHeader:
    """一次动作会话的 header（执行前写入）。"""

    ts: str
    session_id: str
    token_id: str
    action: str
    policy_version: str
    verdict_level: str
    verdict_codes: tuple[str, ...]
    is_admin: bool
    item_count: int
    total_bytes: int
    app_version: str
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "action_header",
            "ts": self.ts,
            "session_id": self.session_id,
            "token_id": self.token_id,
            "action": self.action,
            "policy_version": self.policy_version,
            "verdict_level": self.verdict_level,
            "verdict_codes": list(self.verdict_codes),
            "is_admin": self.is_admin,
            "item_count": self.item_count,
            "total_bytes": self.total_bytes,
            "app_version": self.app_version,
            "dry_run": self.dry_run,
        }


@dataclass(frozen=True, slots=True)
class AuditItem:
    """单个执行项的结果记录（执行后立即写入）。"""

    ts: str
    session_id: str
    action: str
    target: str
    identity: str
    result: str
    error_code: str = ""
    detail: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "action_item",
            "ts": self.ts,
            "session_id": self.session_id,
            "action": self.action,
            "target": self.target,
            "identity": self.identity,
            "result": self.result,
            "error_code": self.error_code,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
        }


@dataclass(frozen=True, slots=True)
class AuditEnd:
    """动作会话结束记录（阶段 4D：用于识别"未完成/中断"会话）。"""

    ts: str
    session_id: str
    action: str
    status: str  # completed
    success: int = 0
    failed: int = 0
    total: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "action_end",
            "ts": self.ts,
            "session_id": self.session_id,
            "action": self.action,
            "status": self.status,
            "success": self.success,
            "failed": self.failed,
            "total": self.total,
        }


class ActionAuditWriter:
    """append-only 写入器；任何 I/O 失败都转成 :class:`AuditWriteError`。"""

    def __init__(self, log_directory: Path | str) -> None:
        self._path = Path(log_directory) / AUDIT_FILENAME

    @property
    def path(self) -> Path:
        return self._path

    def write_header(self, header: AuditHeader) -> None:
        self._append(header.to_dict())

    def write_item(self, item: AuditItem) -> None:
        self._append(item.to_dict())

    def write_end(self, end: AuditEnd) -> None:
        self._append(end.to_dict())

    def _append(self, record: Mapping[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(dict(record), ensure_ascii=False) + "\n"
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
        except OSError as exc:
            raise AuditWriteError(f"审计日志写入失败：{exc}") from exc


def rotate_audit_log(
    log_directory: Path | str,
    *,
    now: float | None = None,
    max_bytes: int = AUDIT_MAX_BYTES,
    keep: int = AUDIT_KEEP_ROTATED,
    retention_days: int = AUDIT_RETENTION_DAYS,
) -> Path | None:
    """动作会话结束后按大小轮转 ``operations.jsonl``（S3-7）。

    * 只在主文件超过 ``max_bytes`` 时轮转，重命名为 ``operations-YYYYmmdd-HHMMSS.jsonl``；
    * 轮转只发生在动作会话之外（由 UI 在 finished/failed/cancelled 后调用），
      不破坏 append-only 语义；
    * 保留最近 ``keep`` 份，并删除超过 ``retention_days`` 的轮转文件；
    * 任何 I/O 失败静默返回 ``None``（日志轮转不得影响主流程）。
    """

    directory = Path(log_directory)
    path = directory / AUDIT_FILENAME
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size < max_bytes:
        return None
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now if now is not None else time.time()))
    target = path.with_name(f"{ROTATED_PREFIX}{timestamp}.jsonl")
    suffix = 1
    while target.exists():
        target = path.with_name(f"{ROTATED_PREFIX}{timestamp}-{suffix}.jsonl")
        suffix += 1
    try:
        path.replace(target)
    except OSError:
        return None
    _prune_rotated(directory, now=now, keep=keep, retention_days=retention_days)
    return target


def _rotated_files(directory: Path) -> list[Path]:
    files: list[Path] = []
    try:
        for candidate in directory.glob(f"{ROTATED_PREFIX}*.jsonl"):
            try:
                candidate.stat()
            except OSError:
                continue
            files.append(candidate)
    except OSError:
        return []
    return sorted(files, key=lambda item: item.stat().st_mtime, reverse=True)


def _prune_rotated(
    directory: Path,
    *,
    now: float | None,
    keep: int,
    retention_days: int,
) -> list[Path]:
    current = now if now is not None else time.time()
    cutoff = current - max(0, retention_days) * 86400
    removed: list[Path] = []
    for index, candidate in enumerate(_rotated_files(directory)):
        try:
            mtime = candidate.stat().st_mtime
        except OSError:
            continue
        if index >= max(1, keep) or mtime < cutoff:
            try:
                candidate.unlink()
                removed.append(candidate)
            except OSError:
                pass
    return removed
