"""阶段 5B 测试：冻结环境自重启参数适配（不触发真实 UAC）与构建脚本约束。"""

from __future__ import annotations

import sys
from pathlib import Path

from perf_purifier.core.relaunch import relaunch_as_admin


def test_frozen_relaunch_drops_exe_argument(monkeypatch) -> None:
    captured: dict = {}

    def fake_shell_execute(verb: str, file: str, params: str, cwd: str) -> int:
        captured.update(verb=verb, file=file, params=params)
        return 42

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    started, error = relaunch_as_admin(
        [r"C:\Program Files\PerfPurifier\PerfPurifier.exe", "--safe-mode"],
        shell_execute=fake_shell_execute,
    )
    assert started is True and error == ""
    assert captured["verb"] == "runas"
    assert captured["file"] == sys.executable
    assert captured["params"] == "--safe-mode"


def test_non_frozen_relaunch_includes_script(monkeypatch) -> None:
    captured: dict = {}

    def fake_shell_execute(verb: str, file: str, params: str, cwd: str) -> int:
        captured.update(params=params)
        return 42

    monkeypatch.delattr(sys, "frozen", raising=False)
    started, _error = relaunch_as_admin(["run.py", "--x"], shell_execute=fake_shell_execute)
    assert started is True
    assert "run.py" in captured["params"]


def test_build_script_builds_gui_and_cli() -> None:
    """1.2.0 起发布脚本同时产出 GUI（onedir）与 CLI（onefile）。"""

    script = Path(__file__).resolve().parents[2] / "scripts" / "build_release.ps1"
    text = script.read_text(encoding="utf-8")
    assert "--onedir" in text  # GUI：one-folder，避免每次启动解压
    assert "--onefile" in text  # CLI：单文件，便于分发
    assert "run.py" in text
    assert "run_cli.py" in text
    assert "pyinstaller" in text.lower()
