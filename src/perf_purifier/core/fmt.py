"""展示与导出用的格式化工具（字节、时间、状态、命令行脱敏）。

命令行脱敏规则已经抽到 :mod:`perf_purifier.core.redaction` 的纯函数
:func:`redact_cmdline_text`；本模块的 :func:`redact_cmdline` 保留阶段 1 的
Sequence 签名，只做拼接、换行规范化与长度截断（既有测试锁定行为）。
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from datetime import datetime

from .redaction import redact_cmdline_text

_BYTE_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KMGT]?B?)?\s*$", re.IGNORECASE)
_SIZE_FACTORS = {
    "": 1,
    "B": 1,
    "K": 1024,
    "KB": 1024,
    "M": 1024**2,
    "MB": 1024**2,
    "G": 1024**3,
    "GB": 1024**3,
    "T": 1024**4,
    "TB": 1024**4,
}

_STATUS_LABELS: dict[str, str] = {
    "running": "运行中",
    "sleeping": "等待",
    "disk-sleep": "磁盘等待",
    "wake-sleep": "唤醒等待",
    "stopped": "已暂停",
    "tracing-stop": "跟踪暂停",
    "zombie": "僵尸进程",
    "dead": "已结束",
    "locked": "锁定",
    "waiting": "等待",
    "parked": "驻留",
    "idle": "空闲",
}


def human_bytes(num: int | float) -> str:
    """把字节数格式化为易读字符串（1024 进制）。"""

    try:
        value = float(num)
    except (TypeError, ValueError):
        return "—"
    if value < 0:
        return "—"
    if value < 1024:
        return f"{int(value)} B"
    unit_index = 0
    while value >= 1024 and unit_index < len(_BYTE_UNITS) - 1:
        value /= 1024
        unit_index += 1
    return f"{value:.1f} {_BYTE_UNITS[unit_index]}"


def human_count(num: int | float | None) -> str:
    """千分位整数（用于文件数等展示）。"""

    try:
        return f"{int(num):,}"  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "—"


def parse_size(text: str | None) -> int | None:
    """解析 ``200MB`` / ``1.5G`` / ``1024`` 这类尺寸；非法返回 ``None``。"""

    if not text:
        return None
    match = _SIZE_RE.match(str(text))
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or "").upper()
    factor = _SIZE_FACTORS.get(unit)
    if factor is None:
        return None
    return int(number * factor)


def percent_text(part: int | float, whole: int | float) -> str:
    """百分比文本；``whole`` <= 0 时返回 ``—``。"""

    try:
        if float(whole) <= 0:
            return "—"
        return f"{float(part) / float(whole) * 100:.1f}%"
    except (TypeError, ValueError, ZeroDivisionError):
        return "—"


def bar(ratio: float, width: int = 20) -> str:
    """文本进度条，``ratio`` 会被裁剪到 [0, 1]。"""

    try:
        value = min(1.0, max(0.0, float(ratio)))
    except (TypeError, ValueError):
        value = 0.0
    width = max(1, int(width))
    filled = int(round(value * width))
    return "█" * filled + "░" * (width - filled)


def human_duration_ms(milliseconds: float) -> str:
    """把毫秒格式化为易读时长。"""

    try:
        value = max(0.0, float(milliseconds))
    except (TypeError, ValueError):
        return "—"
    if value < 1000:
        return f"{value:.0f} ms"
    if value < 60_000:
        return f"{value / 1000:.2f} s"
    minutes = int(value // 60_000)
    seconds = (value % 60_000) / 1000
    return f"{minutes} 分 {seconds:.0f} 秒"


def format_timestamp(timestamp: float) -> str:
    """把 Unix 时间戳格式化为本地时间字符串。"""

    try:
        value = float(timestamp)
        if value <= 0:
            return "—"
        return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "—"


def format_status(status: str) -> str:
    if not status:
        return "—"
    return _STATUS_LABELS.get(status.lower(), status)


def redact_cmdline(
    cmdline: Sequence[str],
    *,
    enabled: bool = True,
    max_chars: int = 200,
) -> str:
    """把命令行拼成单行文本：可选脱敏敏感参数，并限制长度。

    * ``enabled=True`` 时调用纯函数 :func:`redact_cmdline_text` 遮蔽疑似密码/令牌；
    * 风险判定使用 ``ProcessInfo.cmdline_text``（原文），不受此函数影响；
    * 脱敏规则（键名边界、空值、URL、Header、遗留 -p/-enc）见 ``core.redaction``。
    """

    text = " ".join(str(part) for part in cmdline)
    text = text.replace("\r", " ").replace("\n", " ")
    if enabled:
        text = redact_cmdline_text(text)
    if max_chars > 0 and len(text) > max_chars:
        text = text[: max_chars - 1] + "…"
    return text


def now_text() -> str:
    """当前时间（用于默认导出文件名）。"""

    return time.strftime("%Y%m%d_%H%M%S")
