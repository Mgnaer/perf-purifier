"""文件哈希原语（阶段 1C，只读）。

流水线：
1. 按文件大小分桶（大小不同必然不重复）；
2. 同大小的候选先读前 4KB 计算 SHA-256 快速指纹；
3. 指纹相同的候选再对全文件流式计算 SHA-256；
4. 读取前后各取一次 stat，内容/大小/修改时间变化则标记"扫描期间变动"并剔除。

超长路径：普通打开失败时用 ``\\\\?\\`` 前缀兜底重试。
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Callable

from ..core.cancel import CancelToken
from ..core.winapi import to_extended_path

logger = logging.getLogger(__name__)

PARTIAL_BYTES = 4 * 1024
CHUNK_BYTES = 1024 * 1024


def choose_hash_workers(media_type: str, configured: int = 0, cpu_count: int | None = None) -> int:
    """选择哈希并发数（HDD 自适应）。

    * ``configured > 0``：尊重用户显式配置；
    * HDD（有寻道惩罚）：串行 1 个，避免随机寻道拖慢整体；
    * SSD：最多 4 个（受 CPU 核数限制）；
    * ``unknown``（虚拟盘/检测失败）：保守用 2 个。
    """

    if configured > 0:
        return configured
    if media_type == "hdd":
        return 1
    cores = cpu_count if cpu_count is not None else (os.cpu_count() or 2)
    if media_type == "ssd":
        return max(1, min(4, cores))
    return max(1, min(2, cores))


def _open_binary(path: str):
    try:
        return open(path, "rb")
    except OSError:
        extended = to_extended_path(path)
        if extended == path:
            raise
        return open(extended, "rb")


def digest_partial(path: str) -> str:
    """读取前 4KB 计算 SHA-256 快速指纹（文件更小则整文件）。"""

    with _open_binary(path) as handle:
        chunk = handle.read(PARTIAL_BYTES)
    return hashlib.sha256(chunk).hexdigest()


def digest_full(
    path: str,
    token: CancelToken,
    on_chunk: Callable[[int], None] | None = None,
) -> tuple[str, int]:
    """流式计算全文件 SHA-256，返回 ``(十六进制摘要, 实际读取字节数)``。"""

    digest = hashlib.sha256()
    total_bytes = 0
    with _open_binary(path) as handle:
        while True:
            token.raise_if_cancelled("计算 SHA256")
            chunk = handle.read(CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            total_bytes += len(chunk)
            if on_chunk is not None:
                on_chunk(len(chunk))
    return digest.hexdigest(), total_bytes
