"""模块 B 导出测试：CSV（BOM/列）、JSON（schema/统计）、HTML（自包含/转义）。"""

from __future__ import annotations

import json
from pathlib import Path

from perf_purifier.core.models import (
    FILE_SCAN_SCHEMA_VERSION,
    Completeness,
    DuplicateGroup,
    FileRecord,
    FileScanOptions,
    FileScanResult,
)
from perf_purifier.module_b.report import (
    build_file_scan_export,
    export_duplicate_files_csv,
    export_duplicates_csv,
    export_file_report_html,
    export_file_scan_json,
    export_large_files_csv,
)


def test_duplicate_csv_exports(synthetic_file_result, tmp_path: Path) -> None:
    groups_csv = tmp_path / "groups.csv"
    ok, message = export_duplicates_csv(str(groups_csv), synthetic_file_result)
    assert ok, message
    raw = groups_csv.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    assert "组号" in text and "可回收(硬链接感知)" in text
    assert "one.bin" in text and "two.bin" in text
    assert "已互为硬链接" in text

    files_csv = tmp_path / "files.csv"
    ok, message = export_duplicate_files_csv(str(files_csv), synthetic_file_result)
    assert ok, message
    text = files_csv.read_bytes().decode("utf-8-sig")
    assert "文件路径" in text and "inode" in text
    assert "copy.bin" in text


def test_large_files_csv(synthetic_file_result, tmp_path: Path) -> None:
    target = tmp_path / "large.csv"
    ok, message = export_large_files_csv(str(target), synthetic_file_result)
    assert ok, message
    text = target.read_bytes().decode("utf-8-sig")
    assert "huge.bin" in text
    assert "3.0 MB" in text


def test_json_export(synthetic_file_result, tmp_path: Path) -> None:
    target = tmp_path / "scan.json"
    ok, message = export_file_scan_json(str(target), synthetic_file_result)
    assert ok, message
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["schema_version"] == FILE_SCAN_SCHEMA_VERSION
    assert payload["read_only"] is True
    assert payload["summary"]["duplicate_groups"] == 2
    assert payload["summary"]["duplicate_files"] == 4
    hardlinked = next(group for group in payload["duplicate_groups"] if group["already_hardlinked"])
    assert hardlinked["reclaimable_bytes"] == 0
    assert hardlinked["hardlink_text"].startswith("已互为硬链接")
    assert payload["large_files"][0]["rank"] == 1


def test_html_export_is_self_contained_and_escapes(tmp_path: Path) -> None:
    dangerous = FileRecord(
        path='C:\\data\\<script>alert(1)</script>.bin',
        size=4096,
        mtime=1_700_000_000.0,
        dev=1,
        ino=9,
    )
    result = FileScanResult(
        root="C:\\data",
        options=FileScanOptions(root="C:\\data"),
        started_at=1_700_000_000.0,
        finished_at=1_700_000_001.0,
        duplicate_groups=[
            DuplicateGroup(
                group_id=1,
                size=4096,
                full_sha256="c" * 64,
                files=(dangerous,),
                distinct_inodes=1,
                already_hardlinked=True,
            )
        ],
        completeness=Completeness.PARTIAL,
        elapsed_ms=1000,
    )
    target = tmp_path / "report.html"
    ok, message = export_file_report_html(str(target), result)
    assert ok, message
    text = target.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "重复文件" in text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
    assert "http://" not in text and "https://" not in text


def test_json_export_builder_matches_writer(synthetic_file_result) -> None:
    payload = build_file_scan_export(synthetic_file_result)
    assert payload["scan"]["root"] == synthetic_file_result.root
    assert payload["summary"]["files_scanned"] == 42
