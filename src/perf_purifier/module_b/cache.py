"""SQLite 哈希缓存（阶段 1C 增强）。

目的：再次扫描同一目录时，若文件未变化（大小 + 修改时间一致），直接复用上次的
SHA-256 结果，跳过全文件读取，明显加快重复扫描。

失效与安全：
* 以 ``(大小, 修改时间)`` 判定失效，任何一项变化都会重新哈希；
* 默认 30 天 TTL 清理陈旧记录（可配置）；
* 数据库被占用/损坏等任何异常都降级为"无缓存"，绝不影响扫描主流程；
* 仅缓存"路径 → 哈希"，不缓存文件内容，不读取文件，不涉及隐私数据。
"""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path

from ..core.models import FileRecord

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS file_hashes (
    path       TEXT PRIMARY KEY,
    size       INTEGER NOT NULL,
    mtime      INTEGER NOT NULL,
    sha256     TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_hashes_updated ON file_hashes(updated_at);
"""

_FLUSH_THRESHOLD = 500


class HashCache:
    """线程内单连接使用；哈希工作线程只做纯读取，不访问本类。"""

    def __init__(self, path: str | Path, *, ttl_days: int = 30) -> None:
        self._path = str(path)
        self._ttl_days = max(0, int(ttl_days))
        self._connection = sqlite3.connect(self._path, timeout=5.0)
        self._connection.executescript(_SCHEMA)
        self._connection.commit()
        self._pending: dict[str, tuple[int, int, str]] = {}
        self._disabled = False
        self._closed = False
        self._hits = 0

    # ------------------------------------------------------------- 查询/写入
    @property
    def hits(self) -> int:
        return self._hits

    @property
    def disabled(self) -> bool:
        return self._disabled

    def lookup(self, record: FileRecord) -> str | None:
        """命中且未失效时返回缓存的 SHA-256；否则返回 None。"""

        if self._disabled:
            return None
        try:
            row = self._connection.execute(
                "SELECT size, mtime, sha256 FROM file_hashes WHERE path = ?",
                (record.path,),
            ).fetchone()
        except sqlite3.Error as exc:
            logger.warning("哈希缓存读取失败，已停用缓存：%s", exc)
            self._disabled = True
            return None
        if row is None:
            return None
        size, mtime, digest = row
        if int(size) == record.size and int(mtime) == int(record.mtime):
            self._hits += 1
            return str(digest)
        return None

    def store(self, record: FileRecord, digest: str) -> None:
        if self._disabled or not digest:
            return
        self._pending[record.path] = (record.size, int(record.mtime), digest)
        if len(self._pending) >= _FLUSH_THRESHOLD:
            self.flush()

    def flush(self) -> None:
        if self._disabled or not self._pending or self._closed:
            return
        now = time.time()
        rows = [
            (path, size, mtime, digest, now)
            for path, (size, mtime, digest) in self._pending.items()
        ]
        try:
            self._connection.executemany(
                """
                INSERT INTO file_hashes(path, size, mtime, sha256, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    size = excluded.size,
                    mtime = excluded.mtime,
                    sha256 = excluded.sha256,
                    updated_at = excluded.updated_at
                """,
                rows,
            )
            self._connection.commit()
        except sqlite3.Error as exc:
            logger.warning("哈希缓存写入失败，已停用缓存：%s", exc)
            self._disabled = True
        finally:
            self._pending.clear()

    def prune(self) -> None:
        if self._disabled or self._ttl_days <= 0:
            return
        cutoff = time.time() - self._ttl_days * 86400
        try:
            self._connection.execute("DELETE FROM file_hashes WHERE updated_at < ?", (cutoff,))
            self._connection.commit()
        except sqlite3.Error:
            logger.debug("哈希缓存清理失败", exc_info=True)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.flush()
            self.prune()
        finally:
            try:
                self._connection.close()
            except sqlite3.Error:
                pass
            self._closed = True

    @staticmethod
    def default_path() -> Path:
        from ..core.config import app_data_dir

        return app_data_dir() / "file_hash_cache.sqlite3"
