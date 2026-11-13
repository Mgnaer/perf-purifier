"""阶段 3C 测试：管理员重启命令构建/失败分支/主窗口按钮（不触发真实 UAC）。"""

from __future__ import annotations

import logging
import sys

import pytest
from PySide6.QtWidgets import QMessageBox

from perf_purifier.core.config import AppConfig
from perf_purifier.core.relaunch import build_relaunch_parameters, relaunch_as_admin
from perf_purifier.core.whitelist import Whitelist
from perf_purifier.ui.main_window import MainWindow


def test_build_relaunch_parameters_quoting() -> None:
    parameters = build_relaunch_parameters([r"C:\Program Files\App\run.py", "a b", "x"])
    assert '\\"Program Files\\App\\run.py\\"' in parameters or '"C:\\Program Files\\App\\run.py"' in parameters
    assert '"a b"' in parameters
    assert parameters.endswith("x")


def test_relaunch_success_builds_runas_call() -> None:
    captured: dict = {}

    def fake_shell_execute(verb: str, file: str, params: str, cwd: str) -> int:
        captured.update(verb=verb, file=file, params=params, cwd=cwd)
        return 42

    started, error = relaunch_as_admin(
        ["run.py", "--safe-mode"], shell_execute=fake_shell_execute
    )
    assert started is True and error == ""
    assert captured["verb"] == "runas"
    assert captured["file"] == sys.executable
    assert captured["params"] == "run.py --safe-mode"
    assert captured["cwd"]


@pytest.mark.parametrize(
    ("code", "keyword"),
    [(1223, "UAC"), (5, "拒绝"), (2, "返回码 2")],
)
def test_relaunch_failure_codes(code: int, keyword: str) -> None:
    started, error = relaunch_as_admin(["run.py"], shell_execute=lambda *args: code)
    assert started is False
    assert keyword in error


def test_relaunch_exception_is_handled() -> None:
    def broken(*args):
        raise OSError("模拟失败")

    started, error = relaunch_as_admin(["run.py"], shell_execute=broken)
    assert started is False
    assert "启动失败" in error


def test_relaunch_without_executable(monkeypatch) -> None:
    monkeypatch.setattr("perf_purifier.core.relaunch.sys.executable", "")
    started, error = relaunch_as_admin(["run.py"], shell_execute=lambda *args: 42)
    assert started is False
    assert "解释器" in error


# ---------------------------------------------------------------- 主窗口
def _make_window(qapp, *, is_admin: bool) -> MainWindow:
    window = MainWindow(
        AppConfig(),
        Whitelist(),
        is_admin=is_admin,
        logger=logging.getLogger("test.stage3c"),
    )
    return window


def _dispose_window(window: MainWindow, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    window.setParent(None)
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


def test_relaunch_button_visible_only_for_normal_user(qapp) -> None:
    normal = _make_window(qapp, is_admin=False)
    admin = _make_window(qapp, is_admin=True)
    try:
        assert normal._btn_relaunch is not None
        assert normal._btn_relaunch.isEnabled()
        assert admin._btn_relaunch is None
    finally:
        _dispose_window(normal, qapp)
        _dispose_window(admin, qapp)


def test_relaunch_handler_failure_keeps_window(qapp, monkeypatch) -> None:
    window = _make_window(qapp, is_admin=False)
    try:
        monkeypatch.setattr(
            "perf_purifier.ui.main_window.relaunch_as_admin",
            lambda: (False, "已取消管理员授权（UAC），程序继续以当前权限运行"),
        )
        monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: QMessageBox.StandardButton.Yes)
        calls: list[tuple] = []
        monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: calls.append(args))
        window._on_relaunch_as_admin()
        assert calls, "重启失败时应提示用户"
        assert "UAC" in str(calls[0])
    finally:
        _dispose_window(window, qapp)


def test_relaunch_handler_cancel_never_calls_system(qapp, monkeypatch) -> None:
    window = _make_window(qapp, is_admin=False)
    try:
        called: list[bool] = []
        monkeypatch.setattr(
            "perf_purifier.ui.main_window.relaunch_as_admin",
            lambda: called.append(True) or (True, ""),
        )
        monkeypatch.setattr(
            QMessageBox, "warning", lambda *args, **kwargs: QMessageBox.StandardButton.Cancel
        )
        window._on_relaunch_as_admin()
        assert called == []
    finally:
        _dispose_window(window, qapp)
