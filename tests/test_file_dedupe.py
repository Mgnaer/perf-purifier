"""重复检测流水线测试：分组正确性、4KB 指纹过滤、硬链接识别、最小大小、取消。"""

from __future__ import annotations

import os

import pytest

from perf_purifier.core.cancel import CancelToken, ScanCancelled
from perf_purifier.module_b.dedupe import find_duplicates
from perf_purifier.module_b.walker import walk_directory


def _write(path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _scan(root, *, min_size: int = 1):
    walk = walk_directory(str(root), CancelToken(), max_files=10000, budget_s=30.0, large_limit=10)
    return find_duplicates(walk.records, CancelToken(), min_size=min_size)


def test_finds_groups_and_filters_partial_hash_collision(tmp_path) -> None:
    root = tmp_path / "data"
    _write(root / "a" / "one.bin", b"A" * 5000 + b"tail-1")
    _write(root / "b" / "two.bin", b"A" * 5000 + b"tail-1")
    # 前 4KB 相同、尾部不同：不能被 4KB 指纹误判为重复
    _write(root / "c" / "three.bin", b"A" * 5000 + b"tail-2")
    _write(root / "d" / "four.bin", b"B" * 3000)
    _write(root / "e" / "five.bin", b"B" * 3000)

    outcome = _scan(root)
    assert len(outcome.groups) == 2
    sizes = sorted(group.size for group in outcome.groups)
    assert sizes == [3000, 5006]
    group = next(item for item in outcome.groups if item.size == 5006)
    names = sorted(os.path.basename(record.path) for record in group.files)
    assert names == ["one.bin", "two.bin"]
    assert group.reclaimable_bytes == 5006
    assert group.has_hardlinks is False
    assert group.already_hardlinked is False
    all_paths = [record.path for item in outcome.groups for record in item.files]
    assert not any("three.bin" in path for path in all_paths)


def test_min_size_filters_small_files(tmp_path) -> None:
    root = tmp_path / "data"
    _write(root / "a.bin", b"x" * 100)
    _write(root / "b.bin", b"x" * 100)
    outcome = _scan(root, min_size=1024)
    assert outcome.groups == []


@pytest.mark.skipif(os.name != "nt", reason="硬链接测试依赖 Windows/NTFS")
def test_hardlinked_pair_is_detected(tmp_path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    original = root / "orig.bin"
    original.write_bytes(b"Z" * 6000)
    link = root / "copy.bin"
    try:
        os.link(original, link)
    except OSError as exc:
        pytest.skip(f"当前文件系统不支持硬链接：{exc}")

    outcome = _scan(root)
    assert len(outcome.groups) == 1
    group = outcome.groups[0]
    assert group.already_hardlinked is True
    assert group.has_hardlinks is True
    assert group.distinct_inodes == 1
    assert group.reclaimable_bytes == 0
    assert len(group.files) == 2


def test_cancel_raises(tmp_path) -> None:
    root = tmp_path / "data"
    _write(root / "a.bin", b"x" * 5000)
    _write(root / "b.bin", b"x" * 5000)
    walk = walk_directory(str(root), CancelToken(), max_files=100, budget_s=5.0)
    token = CancelToken()
    token.cancel()
    with pytest.raises(ScanCancelled):
        find_duplicates(walk.records, token, min_size=1)
