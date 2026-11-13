"""模块 C 扫描器测试：递归统计、预算截断、取消、子项聚合、单遍概览。"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import make_junction

from perf_purifier.core.cancel import CancelToken, ScanCancelled
from perf_purifier.core.models import ScanWarning
from perf_purifier.module_c.scanner import (
    format_skips,
    largest_files,
    list_children,
    list_drives,
    overview_scan,
    resolve_drive_root,
    system_drive,
    walk_size,
)


def _build_tree(root: Path) -> None:
    (root / "a").mkdir()
    (root / "a" / "f1.bin").write_bytes(b"x" * 100)
    (root / "a" / "f2.bin").write_bytes(b"x" * 200)
    (root / "b").mkdir()
    (root / "b" / "f3.bin").write_bytes(b"x" * 50)
    (root / "root.txt").write_bytes(b"x" * 10)


def test_walk_size_totals(tmp_path: Path) -> None:
    _build_tree(tmp_path)
    stats = walk_size(str(tmp_path))
    assert stats.files == 4
    assert stats.total_bytes == 360
    assert stats.truncated is False


def test_walk_size_budget_truncates(tmp_path: Path) -> None:
    for index in range(200):
        directory = tmp_path / f"d{index}"
        directory.mkdir()
        (directory / "f.bin").write_bytes(b"x" * 10)
    stats = walk_size(str(tmp_path), max_entries=20)
    assert stats.truncated is True


def test_walk_size_cancelled_raises(tmp_path: Path) -> None:
    for index in range(50):
        directory = tmp_path / f"d{index}"
        directory.mkdir()
        (directory / "f.bin").write_bytes(b"x" * 10)
    token = CancelToken()
    token.cancel()
    with pytest.raises(ScanCancelled):
        walk_size(str(tmp_path), token=token)


def test_list_children_sizes_sorted(tmp_path: Path) -> None:
    _build_tree(tmp_path)
    children = list_children(str(tmp_path))
    assert [child.name for child in children][:2] == ["a", "b"]
    sizes = {child.name: child.size for child in children}
    assert sizes["a"] == 300
    assert sizes["b"] == 50
    assert sizes["root.txt"] == 10
    assert children[0].is_dir is True


def test_list_children_skips_junction_summary(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "f.bin").write_bytes(b"x" * 10)
    link = tmp_path / "link"
    if not make_junction(link, real):
        pytest.skip("当前环境无法创建 junction")
    try:
        children = list_children(str(tmp_path))
        entry = next(child for child in children if child.name == "link")
        assert entry.is_reparse is True
        assert entry.size == 0
    finally:
        os.rmdir(link)


def test_largest_files(tmp_path: Path) -> None:
    _build_tree(tmp_path)
    hits, stats = largest_files(str(tmp_path), top=2, min_size=0)
    assert [Path(hit.path).name for hit in hits] == ["f2.bin", "f1.bin"]
    assert hits[0].size == 200
    assert stats.files == 4

    filtered, _ = largest_files(str(tmp_path), top=10, min_size=150)
    assert len(filtered) == 1


def test_overview_scan_aggregates(tmp_path: Path) -> None:
    _build_tree(tmp_path)
    result = overview_scan(str(tmp_path), top_files=3, min_file_size=0)
    sizes = {entry.name: entry.size for entry in result.entries}
    assert sizes["a"] == 300
    assert sizes["b"] == 50
    assert sizes["root.txt"] == 10
    assert result.stats.files == 4
    assert len(result.top_files) == 3
    assert result.top_files[0].size == 200


def test_overview_scan_skips_junction(tmp_path: Path) -> None:
    _build_tree(tmp_path)
    real = tmp_path.parent / "outside_real"
    real.mkdir(exist_ok=True)
    (real / "huge.bin").write_bytes(b"x" * 5000)
    link = tmp_path / "huge_link"
    if not make_junction(link, real):
        pytest.skip("当前环境无法创建 junction")
    try:
        result = overview_scan(str(tmp_path), top_files=3, min_file_size=0)
        assert all(entry.name != "huge_link" for entry in result.entries)
        assert all(hit.size < 5000 for hit in result.top_files)
    finally:
        os.rmdir(link)


def test_overview_scan_budget_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from perf_purifier.module_c import scanner as scanner_module

    for index in range(100):
        directory = tmp_path / f"d{index}"
        directory.mkdir()
        (directory / "f.bin").write_bytes(b"x" * 10)

    class FakeTime:
        def __init__(self) -> None:
            self.value = 0.0

        def monotonic(self) -> float:
            self.value += 10.0
            return self.value

    monkeypatch.setattr(scanner_module, "time", FakeTime())
    result = overview_scan(str(tmp_path), top_files=3, budget_s=1.0)
    assert result.stats.truncated is True
    assert any(warning.code == "overview_budget" for warning in result.warnings)


def test_resolve_drive_root() -> None:
    assert resolve_drive_root("C") == "C:\\"
    assert resolve_drive_root("c:") == "C:\\"
    assert resolve_drive_root("C:\\") == "C:\\"
    assert resolve_drive_root("C:\\Windows") == "C:\\"
    assert resolve_drive_root("") is None
    assert resolve_drive_root("Q") is None


def test_system_drive_and_drives() -> None:
    root = system_drive()
    assert root.endswith(":\\")
    drives = list_drives(fixed_only=True)
    assert drives, "至少应枚举到一个固定磁盘"
    assert all(info.total_bytes > 0 for info in drives)


def test_format_skips() -> None:
    from perf_purifier.module_c.scanner import WalkStats

    notes = format_skips(
        WalkStats(skipped_reparse=1, skipped_unreadable=2, skipped_cloud=3, truncated=True)
    )
    assert len(notes) == 4
    assert any("junction" in note for note in notes)


def test_scan_warning_dataclass_shape() -> None:
    warning = ScanWarning("x", "message", path="C:\\a", phase="junk")
    assert warning.code == "x"
    assert warning.phase == "junk"
