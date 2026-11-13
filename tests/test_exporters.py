"""导出格式测试：CSV 编码/行数、JSON 结构、命令行脱敏、网络/临时占用导出。"""

from __future__ import annotations

import json
import os
from pathlib import Path

from perf_purifier.core.config import AppConfig
from perf_purifier.core.fmt import redact_cmdline
from perf_purifier.core.models import SCHEMA_VERSION, ProcessInfo, ProcessScanResult
from perf_purifier.core.whitelist import Whitelist
from perf_purifier.module_a.heuristics import analyze_tree
from perf_purifier.module_a.report import (
    build_process_export,
    export_network_csv,
    export_process_csv,
    export_process_json,
    export_temp_csv,
)
from perf_purifier.module_a.tree_builder import build_tree


def _make_result() -> ProcessScanResult:
    temp_dir = os.environ.get("TEMP") or os.environ.get("TMP") or "."
    infos = [
        ProcessInfo(pid=4, ppid=0, name="System", username=None),
        ProcessInfo(
            pid=100,
            ppid=4,
            name="demo.exe",
            exe=os.path.join(temp_dir, "demo.exe"),
            username="TEST\\user",
            create_time=1_700_000_000.0,
            rss=5 * 1024 * 1024,
            cmdline=("demo.exe", "-p", "hunter2", "--token", "abc123"),
        ),
    ]
    tree = build_tree(infos)
    analyze_tree(tree, Whitelist())
    return ProcessScanResult(
        tree=tree,
        started_at=1_700_000_000.0,
        finished_at=1_700_000_002.5,
        is_admin=False,
    )


def test_csv_export_has_bom_and_all_rows(tmp_path: Path) -> None:
    result = _make_result()
    target = tmp_path / "processes.csv"
    ok, message = export_process_csv(str(target), result, AppConfig())
    assert ok, message
    raw = target.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf"), "CSV 必须带 UTF-8 BOM，Excel 中文才不乱码"
    text = raw.decode("utf-8-sig")
    lines = text.splitlines()
    assert lines[0].startswith("PID,父PID,层级")
    assert "数字签名" in lines[0]
    assert len(lines) == 1 + len(result.tree.nodes)
    assert "demo.exe" in text
    assert "hunter2" not in text, "默认导出必须脱敏密码"


def test_json_export_structure(tmp_path: Path) -> None:
    result = _make_result()
    target = tmp_path / "processes.json"
    ok, message = export_process_json(str(target), result, AppConfig())
    assert ok, message
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["read_only"] is True
    assert payload["scan"]["total_processes"] == 2
    assert payload["counts"]["flagged"] >= 1
    demo = next(item for item in payload["processes"] if item["name"] == "demo.exe")
    assert demo["cmdline_redacted"] is True
    assert "hunter2" not in demo["cmdline"]
    assert demo["flags"], "临时目录下的进程应命中 R01"
    # 只有进程数据时，网络/临时占用应为 None
    assert payload["network"] is None
    assert payload["temp"] is None


def test_json_export_includes_network_and_temp(synthetic_result, tmp_path: Path) -> None:
    target = tmp_path / "full.json"
    ok, message = export_process_json(str(target), synthetic_result, AppConfig())
    assert ok, message
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["network"] is not None
    assert payload["network"]["counts"]["needs_review"] == 1
    assert payload["network"]["connections"][0]["raddr"] == "8.8.8.8:443"
    assert payload["temp"] is not None
    assert payload["temp"]["total_size"] == 2 * 1024 * 1024
    assert payload["temp"]["entries"][0]["occupancy"] == "locked"


def test_network_csv_export(synthetic_result, tmp_path: Path) -> None:
    target = tmp_path / "network.csv"
    ok, message = export_network_csv(str(target), synthetic_result)
    assert ok, message
    raw = target.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    assert "远端地址" in text
    assert "8.8.8.8:443" in text
    assert "evil.exe" in text
    assert "需人工核实" in text


def test_temp_csv_export(synthetic_result, tmp_path: Path) -> None:
    target = tmp_path / "temp.csv"
    ok, message = export_temp_csv(str(target), synthetic_result)
    assert ok, message
    text = target.read_bytes().decode("utf-8-sig")
    assert "占用状态" in text
    assert "可能被占用" in text


def test_redact_cmdline_masks_secrets() -> None:
    text = redact_cmdline(
        ("tool.exe", "--password=hunter2", "--token", "abc123"),
        enabled=True,
        max_chars=200,
    )
    assert "hunter2" not in text
    assert "abc123" not in text
    assert "***" in text


def test_redact_cmdline_disabled_truncates_only() -> None:
    text = redact_cmdline(("tool.exe", "--password=hunter2"), enabled=False, max_chars=10)
    assert len(text) <= 10
    assert "hunter2" in text or text.endswith("…")


def test_build_export_counts_by_risk() -> None:
    payload = build_process_export(_make_result(), AppConfig())
    assert sum(payload["counts"]["by_risk"].values()) == 2
    assert payload["warnings"] == [] or isinstance(payload["warnings"], list)
