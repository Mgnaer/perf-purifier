"""日志初始化：运行日志 + 未来的动作审计日志（JSONL）。

日志位置：``%LOCALAPPDATA%\\PerfPurifier\\logs\\``
* ``run.log``：诊断日志，5MB 轮转，保留 5 份；
* ``operations.jsonl``：阶段 2 处置动作的审计流水，append-only（阶段 1A 只定义契约）。
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import time
from pathlib import Path
from typing import Any

_LOGGER_NAME = "perf_purifier"
_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def setup_logging(log_directory: Path, *, level: int = logging.INFO) -> logging.Logger:
    """初始化并返回应用主 logger（幂等）。"""

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    if logger.handlers:
        return logger

    formatter = logging.Formatter(_LOG_FORMAT)
    try:
        log_directory.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_directory / "run.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:  # 日志不可用不应阻塞程序启动
        print(f"[PerfPurifier] 无法初始化文件日志：{exc}", file=sys.stderr)

    stream_handler = logging.StreamHandler(stream=sys.stderr)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.WARNING)
    logger.addHandler(stream_handler)
    return logger


def install_excepthook(logger: logging.Logger) -> None:
    """把未捕获异常写入日志（同时保留默认控制台输出）。"""

    original_hook = sys.excepthook

    def hook(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_tb: Any,
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            original_hook(exc_type, exc_value, exc_tb)
            return
        logger.critical("未捕获异常", exc_info=(exc_type, exc_value, exc_tb))
        crash_file = write_crash_log(
            log_directory_of_logger(logger) or Path("."),
            exc_type=exc_type,
            exc_value=exc_value,
            exc_tb=exc_tb,
        )
        if crash_file is not None:
            print(
                f"[PerfPurifier] 程序遇到未处理错误，崩溃日志已写入：{crash_file}",
                file=sys.stderr,
            )
        original_hook(exc_type, exc_value, exc_tb)

    sys.excepthook = hook


def log_operation(
    log_directory: Path,
    *,
    action: str,
    target: str,
    result: str,
    detail: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    """写入一条动作审计日志（阶段 2 处置功能使用；阶段 1A 无调用方）。"""

    record: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "action": action,
        "target": target,
        "result": result,
        "detail": detail,
    }
    if extra:
        record.update(extra)
    try:
        log_directory.mkdir(parents=True, exist_ok=True)
        with (log_directory / "operations.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def write_crash_log(
    log_directory: Path | str,
    *,
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_tb: Any,
) -> Path | None:
    """阶段 5A：写本地崩溃日志（版本/权限/堆栈；不含命令行原文），失败返回 None。"""

    import time
    import traceback

    directory = Path(log_directory)
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    target = directory / f"crash_{timestamp}.log"
    try:
        from .. import __version__

        version = __version__
    except Exception:  # noqa: BLE001
        version = "unknown"
    try:
        is_admin = False
        try:
            from .winapi import is_admin as _is_admin

            is_admin = bool(_is_admin())
        except Exception:  # noqa: BLE001
            pass
        directory.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            handle.write("PerfPurifier 崩溃日志（仅本地，不上传）\n")
            handle.write(f"时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            handle.write(f"版本：{version}\n")
            handle.write(f"权限：{'管理员' if is_admin else '普通用户'}\n")
            handle.write("\n--- 堆栈 ---\n")
            handle.write("".join(traceback.format_exception(exc_type, exc_value, exc_tb)))
        return target
    except OSError:
        return None


def log_directory_of_logger(logger: logging.Logger) -> Path | None:
    """从 logger 的 RotatingFileHandler 推断日志目录（供崩溃日志复用）。"""

    for handler in logger.handlers:
        base = getattr(handler, "baseFilename", None)
        if base:
            try:
                return Path(base).parent
            except (OSError, ValueError):
                return None
    return None
