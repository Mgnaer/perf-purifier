"""扫描取消令牌。

约定：所有长循环（进程枚举、目录遍历、哈希分块）必须在固定粒度检查
``CancelToken``；取消后不再发起新的 I/O，由调用方统一收尾。
"""

from __future__ import annotations

import threading


class ScanCancelled(Exception):
    """用户主动取消扫描。"""


class CancelToken:
    """线程安全的取消令牌。"""

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self, context: str = "") -> None:
        if self._event.is_set():
            raise ScanCancelled(context or "扫描已取消")
