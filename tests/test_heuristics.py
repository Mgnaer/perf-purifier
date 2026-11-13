"""启发式规则测试（依赖 Windows 系统路径，非 Windows 平台跳过）。

覆盖：伪装系统进程、命令行 LOLBin、孤儿、血缘、名称不一致、白名单抑制、动作黑名单契约。
"""

from __future__ import annotations

import os

import pytest

from perf_purifier.core.models import ProcessInfo, Severity
from perf_purifier.core.whitelist import NEVER_TERMINATE_NAMES, Whitelist, expected_paths_for
from perf_purifier.module_a.heuristics import RULES, analyze_tree
from perf_purifier.module_a.tree_builder import build_tree

pytestmark = pytest.mark.skipif(os.name != "nt", reason="规则依赖 Windows 系统路径")

SYSTEM_ROOT = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
SYSTEM32 = os.path.join(SYSTEM_ROOT, "System32")
TEMP_DIR = os.environ.get("TEMP") or os.path.join(
    os.environ.get("LOCALAPPDATA", r"C:\Users\Public"), "Temp"
)


def _info(
    pid: int,
    ppid: int,
    name: str,
    *,
    exe: str | None = None,
    cmdline: tuple[str, ...] = (),
    create_time: float = 1000.0,
) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        ppid=ppid,
        name=name,
        exe=exe,
        cmdline=cmdline,
        username="TEST\\user",
        create_time=create_time,
    )


def _analyzed(infos: list[ProcessInfo]):
    tree = build_tree(infos)
    analyze_tree(tree, Whitelist())
    return tree


def test_rule_catalog_is_wellformed() -> None:
    assert RULES["R04"].severity is Severity.HIGH
    assert RULES["R05"].severity is Severity.HIGH
    assert RULES["R06"].severity is Severity.HIGH
    for rule in RULES.values():
        assert rule.weight > 0
        assert rule.title


def test_fake_svchost_in_temp_is_high_risk() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(300, 4, "svchost.exe", exe=os.path.join(TEMP_DIR, "svchost.exe")),
        ]
    )
    node = tree.nodes[300]
    assert "R04" in node.flag_ids()
    assert "R01" in node.flag_ids()
    assert node.risk is Severity.HIGH


def test_legit_system_svchost_not_flagged() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(500, 4, "wininit.exe", exe=os.path.join(SYSTEM32, "wininit.exe")),
            _info(600, 500, "services.exe", exe=os.path.join(SYSTEM32, "services.exe")),
            _info(700, 600, "svchost.exe", exe=os.path.join(SYSTEM32, "svchost.exe")),
        ]
    )
    node = tree.nodes[700]
    assert node.flags == []
    assert node.risk is Severity.INFO


def test_svchost_wrong_parent_flagged() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(800, 4, "explorer.exe", exe=os.path.join(SYSTEM_ROOT, "explorer.exe")),
            _info(700, 800, "svchost.exe", exe=os.path.join(SYSTEM32, "svchost.exe")),
        ]
    )
    assert "R05" in tree.nodes[700].flag_ids()


def test_temp_process_flagged_r01() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(900, 4, "dropper.exe", exe=os.path.join(TEMP_DIR, "dropper.exe")),
        ]
    )
    node = tree.nodes[900]
    assert "R01" in node.flag_ids()
    assert node.risk is Severity.SUSPICIOUS


def test_orphan_rule() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(950, 424242, "portable.exe", exe=r"C:\Users\Public\portable\app.exe"),
        ]
    )
    node = tree.nodes[950]
    assert "R03" in node.flag_ids()
    assert node.risk is Severity.NOTICE


def test_lolbin_trusted_path_downgraded_to_notice() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(1000, 4, "explorer.exe", exe=os.path.join(SYSTEM_ROOT, "explorer.exe")),
            _info(
                1100,
                1000,
                "powershell.exe",
                exe=os.path.join(SYSTEM32, "powershell.exe"),
                cmdline=(
                    "powershell.exe",
                    "-enc",
                    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                    "-w",
                    "hidden",
                ),
            ),
        ]
    )
    node = tree.nodes[1100]
    assert "R06" in node.flag_ids()
    assert node.risk is Severity.NOTICE


def test_lolbin_untrusted_parent_is_high_risk() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(1200, 4, "updater.exe", exe=r"C:\Users\Public\updater.exe"),
            _info(
                1300,
                1200,
                "powershell.exe",
                exe=os.path.join(SYSTEM32, "powershell.exe"),
                cmdline=(
                    "powershell.exe",
                    "-w",
                    "hidden",
                    "-enc",
                    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                ),
            ),
        ]
    )
    node = tree.nodes[1300]
    flags = {flag.rule_id: flag for flag in node.flags}
    assert "R06" in flags
    assert flags["R06"].severity is Severity.HIGH
    assert node.risk is Severity.HIGH


def test_office_spawn_shell_flagged_r07() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(
                1500,
                4,
                "WINWORD.EXE",
                exe=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            ),
            _info(1600, 1500, "cmd.exe", exe=os.path.join(SYSTEM32, "cmd.exe")),
        ]
    )
    node = tree.nodes[1600]
    assert "R07" in node.flag_ids()
    assert node.risk is Severity.HIGH


def test_name_mismatch_r10() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(1700, 4, "notepad2.exe", exe=os.path.join(SYSTEM32, "notepad.exe")),
        ]
    )
    assert "R10" in tree.nodes[1700].flag_ids()


def test_benign_system_process_has_no_flags() -> None:
    tree = _analyzed(
        [
            _info(4, 0, "System"),
            _info(1800, 4, "notepad.exe", exe=os.path.join(SYSTEM32, "notepad.exe")),
        ]
    )
    node = tree.nodes[1800]
    assert node.flags == []
    assert node.score == 0
    assert node.risk is Severity.INFO


def test_action_blacklist_contract() -> None:
    for name in ("lsass.exe", "csrss.exe", "winlogon.exe", "svchost.exe", "services.exe"):
        assert name in NEVER_TERMINATE_NAMES


def test_expected_paths_for_critical_names() -> None:
    assert expected_paths_for("svchost.exe")
    assert expected_paths_for("lsass.exe")
    assert expected_paths_for("notepad.exe") == ()
