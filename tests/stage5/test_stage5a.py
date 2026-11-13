"""阶段 5A 测试：崩溃日志（本地/无联网）与 run.log 轮转配置。"""

from __future__ import annotations

import sys

from perf_purifier.core.logging_setup import (
    install_excepthook,
    log_directory_of_logger,
    setup_logging,
    write_crash_log,
)


def _raise_and_return_tb():
    try:
        raise RuntimeError("模拟崩溃")
    except RuntimeError as exc:
        return type(exc), exc, exc.__traceback__


def test_write_crash_log_contains_metadata(tmp_path) -> None:
    exc_type, exc_value, exc_tb = _raise_and_return_tb()
    path = write_crash_log(tmp_path, exc_type=exc_type, exc_value=exc_value, exc_tb=exc_tb)
    assert path is not None and path.exists()
    text = path.read_text(encoding="utf-8")
    assert "崩溃日志" in text
    assert "版本：" in text
    assert "权限：" in text
    assert "RuntimeError" in text and "模拟崩溃" in text
    assert "仅本地" in text


def test_write_crash_log_failure_returns_none(tmp_path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    exc_type, exc_value, exc_tb = _raise_and_return_tb()
    assert write_crash_log(blocker, exc_type=exc_type, exc_value=exc_value, exc_tb=exc_tb) is None


def test_run_log_rotating_handler_config(tmp_path) -> None:
    logger = setup_logging(tmp_path)
    handler = next(h for h in logger.handlers if hasattr(h, "maxBytes"))
    assert handler.maxBytes == 5 * 1024 * 1024
    assert handler.backupCount == 5
    assert log_directory_of_logger(logger) == tmp_path


def test_install_excepthook_writes_crash_file(tmp_path) -> None:
    logger = setup_logging(tmp_path)
    logger.handlers.clear()  # 避免模块级 logger 复用上一测试的目录
    logger = setup_logging(tmp_path)
    install_excepthook(logger)
    exc_type, exc_value, exc_tb = _raise_and_return_tb()
    try:
        sys.excepthook(exc_type, exc_value, exc_tb)
    finally:
        sys.excepthook = sys.__excepthook__
    crash_files = list(tmp_path.glob("crash_*.log"))
    assert crash_files, "excepthook 应写崩溃日志"
    assert "模拟崩溃" in crash_files[0].read_text(encoding="utf-8")
