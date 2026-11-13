"""HTML 报告测试：结构完整、动态内容转义、可写入磁盘。"""

from __future__ import annotations

from pathlib import Path

from perf_purifier.core.config import AppConfig
from perf_purifier.module_a.report import build_report_html, export_report_html


def test_report_contains_sections(synthetic_result) -> None:
    report = build_report_html(synthetic_result, AppConfig())
    assert "性能与净化" in report
    assert "只读检查报告" in report
    assert "需人工核实" in report
    assert "临时文件占用" in report
    assert "evil.exe" in report
    assert "只读检查模式" in report
    # 自包含：不应引用外部资源
    assert "<script" not in report.lower()
    assert "http://" not in report
    assert "https://" not in report


def test_report_escapes_dynamic_content(synthetic_result) -> None:
    synthetic_result.tree.nodes[100].info = type(synthetic_result.tree.nodes[100].info)(
        pid=100,
        ppid=4,
        name="<script>alert(1)</script>.exe",
        exe='C:\\Temp\\<img src=x onerror=alert(1)>.exe',
    )
    report = build_report_html(synthetic_result, AppConfig())
    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;" in report
    assert "<img src=x" not in report
    assert "&lt;img" in report


def test_export_report_html_writes_file(synthetic_result, tmp_path: Path) -> None:
    target = tmp_path / "report.html"
    ok, message = export_report_html(str(target), synthetic_result, AppConfig())
    assert ok, message
    text = target.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "性能与净化" in text
