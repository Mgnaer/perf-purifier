"""临时文件占用扫描测试：聚合口径 / 缺失根 / 取消 / 独占文件探测 / junction 跳过。"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import subprocess

import pytest

from perf_purifier.core.cancel import CancelToken, ScanCancelled
from perf_purifier.core.models import Completeness, Occupancy, TempRoot
from perf_purifier.module_a.temp_scan import PROBE_MIN_BYTES, scan_temp


def _write_file(path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        handle.truncate(size)


def test_aggregates_size_and_files(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.bin").write_bytes(b"x" * 100)
    sub = root / "sub"
    sub.mkdir()
    (sub / "b.bin").write_bytes(b"y" * 250)

    result = scan_temp(
        CancelToken(),
        roots=[TempRoot(path=str(root), kind="temp")],
        max_files=1000,
        budget_s=5.0,
        probe_max_files=0,
        probe_budget_s=0.0,
    )
    assert result.total_files == 2
    assert result.total_size == 350
    assert len(result.entries) == 2  # 一个文件 + 一个目录
    assert result.completeness is Completeness.FULL
    assert result.entries[0].size >= result.entries[-1].size  # 按大小降序


def test_missing_root_degrades(tmp_path) -> None:
    result = scan_temp(
        CancelToken(),
        roots=[TempRoot(path=str(tmp_path / "missing"), kind="temp", exists=False)],
        max_files=1000,
        budget_s=5.0,
        probe_max_files=0,
        probe_budget_s=0.0,
    )
    assert result.entries == []
    assert result.completeness is Completeness.DEGRADED
    assert any(warning.code == "temp_no_root" for warning in result.warnings)


def test_already_cancelled_raises(tmp_path) -> None:
    token = CancelToken()
    token.cancel()
    with pytest.raises(ScanCancelled):
        scan_temp(token, roots=[TempRoot(path=str(tmp_path), kind="temp")])


def test_budget_exceeded_marks_partial(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    for index in range(20):
        (root / f"f{index}.bin").write_bytes(b"z" * 10)
    result = scan_temp(
        CancelToken(),
        roots=[TempRoot(path=str(root), kind="temp")],
        max_files=5,
        budget_s=5.0,
        probe_max_files=0,
        probe_budget_s=0.0,
    )
    assert result.completeness is Completeness.PARTIAL
    assert any(warning.code == "temp_budget" for warning in result.warnings)


def _open_exclusive(path: str) -> int:
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(path, 0x80000000, 0, None, 3, 0x80, None)
    assert handle not in (None, ctypes.c_void_p(-1).value), "无法创建独占句柄"
    return int(handle)


@pytest.mark.skipif(os.name != "nt", reason="CreateFileW 共享冲突仅在 Windows 上可验证")
def test_locked_file_is_detected(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "locked.bin"
    _write_file(target, PROBE_MIN_BYTES + 1024)

    handle = _open_exclusive(str(target))
    try:
        result = scan_temp(
            CancelToken(),
            roots=[TempRoot(path=str(root), kind="temp")],
            max_files=1000,
            budget_s=5.0,
            probe_max_files=10,
            probe_budget_s=5.0,
        )
    finally:
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))

    entry = next(item for item in result.entries if item.path == str(target))
    assert entry.occupancy is Occupancy.LOCKED
    assert "被占用" in entry.occupancy_detail


@pytest.mark.skipif(os.name != "nt", reason="junction 为 Windows 特性")
def test_junction_is_skipped(tmp_path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    _write_file(real_dir / "data.bin", 512)
    junction = tmp_path / "root" / "link"
    junction.parent.mkdir()
    creation = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(real_dir)],
        capture_output=True,
    )
    if creation.returncode != 0:
        detail = (creation.stdout + creation.stderr).decode("mbcs", errors="replace")
        pytest.skip(f"当前环境无法创建 junction：{detail}")

    result = scan_temp(
        CancelToken(),
        roots=[TempRoot(path=str(junction.parent), kind="temp")],
        max_files=1000,
        budget_s=5.0,
        probe_max_files=0,
        probe_budget_s=0.0,
    )
    assert result.skipped_reparse >= 1
    paths = {entry.path for entry in result.entries}
    assert not any("link" in os.path.basename(path) for path in paths)
