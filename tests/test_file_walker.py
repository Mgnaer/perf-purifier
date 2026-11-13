"""模块 B 遍历器测试：文件统计、Top-N、预算截断、取消、junction 跳过。"""

from __future__ import annotations

import os
import subprocess

import pytest

from perf_purifier.core.cancel import CancelToken, ScanCancelled
from perf_purifier.core.models import Completeness
from perf_purifier.module_b.walker import walk_directory


def _write(path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        handle.truncate(size)


def test_collects_files_and_large_files(tmp_path) -> None:
    root = tmp_path / "root"
    _write(root / "a.bin", 100)
    _write(root / "sub" / "b.bin", 3000)
    _write(root / "sub" / "deep" / "c.bin", 500)

    result = walk_directory(str(root), CancelToken(), max_files=1000, budget_s=10.0, large_limit=2)
    assert result.files_scanned == 3
    assert result.total_bytes == 3600
    assert result.dirs_scanned >= 3
    assert len(result.large_files) == 2
    assert result.large_files[0].size == 3000
    assert result.completeness is Completeness.FULL
    assert result.truncated is False


def test_missing_root_degrades(tmp_path) -> None:
    result = walk_directory(str(tmp_path / "missing"), CancelToken(), max_files=100, budget_s=5.0)
    assert result.completeness is Completeness.DEGRADED
    assert result.records == []
    assert any(warning.code == "walk_root_missing" for warning in result.warnings)


def test_budget_truncates(tmp_path) -> None:
    root = tmp_path / "root"
    for index in range(10):
        _write(root / f"f{index}.bin", 10)
    result = walk_directory(str(root), CancelToken(), max_files=3, budget_s=10.0)
    assert result.truncated is True
    assert result.files_scanned <= 4
    assert result.completeness is Completeness.PARTIAL
    assert any(warning.code == "walk_truncated" for warning in result.warnings)


def test_cancelled_walk_raises(tmp_path) -> None:
    token = CancelToken()
    token.cancel()
    with pytest.raises(ScanCancelled):
        walk_directory(str(tmp_path), token)


@pytest.mark.skipif(os.name != "nt", reason="junction 为 Windows 特性")
def test_junction_skipped(tmp_path) -> None:
    real_dir = tmp_path / "real"
    _write(real_dir / "data.bin", 123)
    root = tmp_path / "root"
    root.mkdir()
    junction = root / "linkdir"
    creation = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(real_dir)],
        capture_output=True,
    )
    if creation.returncode != 0:
        detail = (creation.stdout + creation.stderr).decode("mbcs", errors="replace")
        pytest.skip(f"当前环境无法创建 junction：{detail}")

    result = walk_directory(str(root), CancelToken(), max_files=1000, budget_s=10.0)
    assert result.skipped_reparse >= 1
    assert result.files_scanned == 0  # junction 未被跟随，root 下没有真实文件
