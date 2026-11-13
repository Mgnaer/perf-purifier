"""1C 增强测试：排除规则、类型/时间过滤、并行哈希、HDD 自适应、哈希缓存、保留建议。"""

from __future__ import annotations

import os
import time

import pytest

from perf_purifier.core.cancel import CancelToken
from perf_purifier.core.winapi import detect_storage_media
from perf_purifier.module_b.cache import HashCache
from perf_purifier.module_b.dedupe import find_duplicates, normalize_extensions
from perf_purifier.module_b.hasher import choose_hash_workers
from perf_purifier.module_b.walker import parse_exclude_patterns, walk_directory


def _write(path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _walk(root, *, exclude=()):
    return walk_directory(
        str(root),
        CancelToken(),
        max_files=10000,
        budget_s=30.0,
        large_limit=10,
        exclude_patterns=exclude,
    )


# ---------------------------------------------------------------- 排除规则
def test_parse_exclude_patterns() -> None:
    assert parse_exclude_patterns("node_modules, .git;*.tmp\nfoo") == (
        "node_modules",
        ".git",
        "*.tmp",
        "foo",
    )
    assert parse_exclude_patterns([]) == ()
    assert parse_exclude_patterns("  ") == ()


def test_walk_excludes_names_and_globs(tmp_path) -> None:
    root = tmp_path / "data"
    _write(root / "keep" / "a.bin", b"keep")
    _write(root / "node_modules" / "dep.bin", b"dependency")
    _write(root / "cache.tmp", b"temporary")

    result = _walk(root, exclude=("node_modules", "*.tmp"))
    names = sorted(os.path.basename(record.path) for record in result.records)
    assert names == ["a.bin"]
    assert result.skipped_excluded >= 2
    assert any(warning.code == "walk_excluded" for warning in result.warnings)


# ---------------------------------------------------------------- 类型/时间过滤
def test_normalize_extensions() -> None:
    assert normalize_extensions(("JPG", " .png ")) == (".jpg", ".png")
    assert normalize_extensions(()) == ()


def test_extension_filter(tmp_path) -> None:
    root = tmp_path / "data"
    _write(root / "a" / "one.jpg", b"IMG" * 2000)
    _write(root / "b" / "two.jpg", b"IMG" * 2000)
    _write(root / "a" / "one.txt", b"DOC" * 2000)
    _write(root / "b" / "two.txt", b"DOC" * 2000)
    walk = _walk(root)

    all_outcome = find_duplicates(walk.records, CancelToken(), min_size=1)
    assert len(all_outcome.groups) == 2

    image_outcome = find_duplicates(walk.records, CancelToken(), min_size=1, extensions=(".jpg",))
    assert len(image_outcome.groups) == 1
    assert image_outcome.groups[0].size == 6000
    assert all(record.suffix == ".jpg" for record in image_outcome.groups[0].files)


def test_mtime_filter(tmp_path) -> None:
    root = tmp_path / "data"
    _write(root / "a" / "one.bin", b"X" * 5000)
    _write(root / "b" / "two.bin", b"X" * 5000)
    walk = _walk(root)

    # 未来时间作为下限 → 所有文件都被过滤掉
    future = find_duplicates(walk.records, CancelToken(), min_size=1, modified_after=time.time() + 3600)
    assert future.groups == []

    # 最近 7 天 → 刚创建的文件保留
    recent = find_duplicates(walk.records, CancelToken(), min_size=1, modified_after=time.time() - 7 * 86400)
    assert len(recent.groups) == 1


# ---------------------------------------------------------------- 并行哈希
def test_parallel_and_sequential_produce_same_result(tmp_path) -> None:
    root = tmp_path / "data"
    for index in range(6):
        _write(root / f"dir{index}" / "copy.bin", (b"X" if index % 2 == 0 else b"Y") * 5000)
    walk = _walk(root)

    sequential = find_duplicates(walk.records, CancelToken(), min_size=1, workers=1)
    parallel = find_duplicates(walk.records, CancelToken(), min_size=1, workers=3)
    assert sequential.workers == 1
    assert parallel.workers == 3
    assert len(sequential.groups) == len(parallel.groups) == 2
    assert sorted(group.full_sha256 for group in sequential.groups) == sorted(
        group.full_sha256 for group in parallel.groups
    )
    assert sorted(group.reclaimable_bytes for group in sequential.groups) == sorted(
        group.reclaimable_bytes for group in parallel.groups
    )


def test_choose_hash_workers_policy() -> None:
    assert choose_hash_workers("hdd", 0, 8) == 1
    assert choose_hash_workers("ssd", 0, 8) == 4
    assert choose_hash_workers("ssd", 0, 2) == 2
    assert choose_hash_workers("unknown", 0, 8) == 2
    assert choose_hash_workers("hdd", 3, 8) == 3  # 用户显式配置优先


@pytest.mark.skipif(os.name != "nt", reason="Windows 专用介质探测")
def test_detect_storage_media_returns_known_value(tmp_path) -> None:
    assert detect_storage_media(str(tmp_path)) in ("ssd", "hdd", "unknown")
    assert detect_storage_media("") == "unknown"


# ---------------------------------------------------------------- 建议保留
def test_suggested_keep_prefers_shallow_path(tmp_path) -> None:
    root = tmp_path / "data"
    _write(root / "a" / "b" / "c" / "deep_copy.bin", b"S" * 5000)
    _write(root / "keep_copy.bin", b"S" * 5000)
    walk = _walk(root)
    outcome = find_duplicates(walk.records, CancelToken(), min_size=1)
    assert len(outcome.groups) == 1
    group = outcome.groups[0]
    assert group.suggested_keep_path.endswith("keep_copy.bin")
    assert group.files[0].path == group.suggested_keep_path


# ---------------------------------------------------------------- 哈希缓存
def test_hash_cache_reuse_and_invalidation(tmp_path) -> None:
    root = tmp_path / "data"
    _write(root / "a" / "one.bin", b"CACHE" * 2000)
    _write(root / "b" / "two.bin", b"CACHE" * 2000)
    cache = HashCache(tmp_path / "cache.sqlite3", ttl_days=7)

    walk = _walk(root)
    first = find_duplicates(walk.records, CancelToken(), min_size=1, cache=cache)
    cache.flush()
    assert first.cache_hits == 0
    assert len(first.groups) == 1
    digest = first.groups[0].full_sha256

    second = find_duplicates(walk.records, CancelToken(), min_size=1, cache=cache)
    assert second.cache_hits >= 2
    assert [group.full_sha256 for group in second.groups] == [digest]

    # 修改文件内容（大小不变、mtime 变化）→ 缓存失效，结果正确
    time.sleep(0.02)
    (root / "b" / "two.bin").write_bytes(b"OTHER" * 2000)
    walk2 = _walk(root)
    third = find_duplicates(walk2.records, CancelToken(), min_size=1, cache=cache)
    assert third.cache_hits == 0
    assert third.groups == []
    cache.close()


def test_hash_cache_survives_lookup_of_missing_file(tmp_path) -> None:
    cache = HashCache(tmp_path / "cache.sqlite3", ttl_days=7)
    from perf_purifier.core.models import FileRecord

    record = FileRecord(path=str(tmp_path / "nope.bin"), size=1, mtime=1.0)
    assert cache.lookup(record) is None
    cache.store(record, "d" * 64)
    cache.flush()
    assert cache.lookup(record) == "d" * 64
    cache.close()
