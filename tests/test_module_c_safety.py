"""模块 C 安全核心测试：路径边界、受保护路径、用户数据、身份重验、Defender 判定。"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import make_junction

from perf_purifier.module_c import safety
from perf_purifier.module_c.safety import (
    canonical_key,
    check_deletable,
    find_forbidden,
    is_admin,
    is_defender_platform_old_version,
    is_drive_root,
    is_reparse_point,
    is_under,
    known_user_data_roots,
    normalize_path,
    path_segments,
    to_long_path,
)


def test_normalize_and_segments() -> None:
    assert normalize_path("C:\\Windows\\Temp\\") == "c:\\windows\\temp"
    assert normalize_path("C:\\") == "c:"
    assert normalize_path("") == ""
    assert path_segments("C:\\A\\B") == ("c:", "a", "b")


@pytest.mark.parametrize(
    ("path", "root", "expected"),
    [
        ("C:\\a\\b", "C:\\a", True),
        ("C:\\a\\b\\c", "C:\\a", True),
        ("C:\\a", "C:\\a", True),
        ("C:\\ab", "C:\\a", False),
        ("C:\\Windows\\Temp", "C:\\", True),
        ("D:\\a\\b", "C:\\a", False),
    ],
)
def test_is_under_boundary(path: str, root: str, expected: bool) -> None:
    assert is_under(path, (root,)) is expected


@pytest.mark.parametrize(
    ("path", "blocked"),
    [
        ("C:\\Windows\\WinSxS\\x", True),
        ("C:\\Windows\\System32\\config\\SAM", True),
        ("C:\\Windows\\System32\\drivers\\etc\\hosts", True),
        ("C:\\Windows\\System32\\MRT.exe", False),
        ("C:\\Windows\\Temp\\a.tmp", False),
        ("C:\\Users\\me\\bootleg.txt", False),
        ("C:\\$Recycle.Bin\\x", True),
        ("C:\\System Volume Information\\x", True),
        ("C:\\Program Files\\WindowsApps\\x", True),
        ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\x", True),
    ],
)
def test_find_forbidden(path: str, blocked: bool) -> None:
    assert (find_forbidden(path) is not None) is blocked


def test_drive_root_detection() -> None:
    assert is_drive_root("C:\\") is True
    assert is_drive_root("c:") is True
    assert is_drive_root("C:\\Windows") is False


def test_canonical_key_and_long_path(tmp_path: Path) -> None:
    target = tmp_path / "a"
    target.mkdir()
    assert canonical_key(str(target)) == canonical_key(str(target))
    assert canonical_key("") == ""
    assert to_long_path("") == ""
    assert os.path.isdir(to_long_path(str(target)))


def test_check_deletable_ok_and_identity(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    target = root / "a.tmp"
    target.write_bytes(b"hello")
    stat_result = target.stat()

    ok = check_deletable(str(target), str(root), expected_size=5, expected_mtime=stat_result.st_mtime)
    assert ok.ok is True

    changed = check_deletable(str(target), str(root), expected_size=999)
    assert changed.ok is False
    assert changed.code == "identity_changed"

    root_check = check_deletable("C:\\", "C:\\")
    assert root_check.code == "drive_root"

    protected = check_deletable("C:\\Windows\\WinSxS", "C:\\Windows\\WinSxS")
    assert protected.code == "protected_path"


def test_check_deletable_outside_root_and_stale(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    root.mkdir()
    other = tmp_path / "other.bin"
    other.write_bytes(b"x")
    result = check_deletable(str(other), str(root))
    assert result.ok is False
    assert result.code == "outside_root"

    missing = check_deletable(str(root / "missing.bin"), str(root))
    assert missing.code == "stale"


def test_check_deletable_refuses_user_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "Docs"
    root.mkdir()
    target = root / "note.txt"
    target.write_bytes(b"data")
    monkeypatch.setattr(safety, "known_user_data_roots", lambda: (normalize_path(str(root)),))
    result = check_deletable(str(target), str(root))
    assert result.ok is False
    assert result.code == "user_data"


def test_check_deletable_refuses_reparse(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "f.txt").write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    if not make_junction(link, real):
        pytest.skip("当前环境无法创建 junction")
    try:
        assert is_reparse_point(str(link)) is True
        result = check_deletable(str(link), str(tmp_path))
        assert result.ok is False
        assert result.code == "reparse_point"
    finally:
        os.rmdir(link)


def test_admin_flag_is_bool() -> None:
    assert isinstance(is_admin(), bool)


def test_known_user_data_roots_no_drive_root() -> None:
    safety.known_user_data_roots.cache_clear()
    for root in known_user_data_roots():
        assert not is_drive_root(root), f"用户数据根不应该是卷根：{root}"


def test_defender_old_platform_detection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    platform = tmp_path / "Platform"
    platform.mkdir()
    old = platform / "4.18.100.1-0"
    new = platform / "4.18.200.2-0"
    current = platform / "CurrentVersion"
    for directory in (old, new, current):
        directory.mkdir()
    (platform / "readme.txt").write_text("x", encoding="utf-8")

    monkeypatch.setattr(safety, "defender_platform_dir", lambda: str(platform))
    assert is_defender_platform_old_version(str(old)) is True
    assert is_defender_platform_old_version(str(new)) is False
    assert is_defender_platform_old_version(str(current)) is False
    assert is_defender_platform_old_version(str(platform)) is False
    assert is_defender_platform_old_version(str(tmp_path / "elsewhere")) is False


def test_query_recycle_bin_returns_ints() -> None:
    from perf_purifier.module_c.safety import query_recycle_bin

    items, size = query_recycle_bin("C:\\")
    assert isinstance(items, int) and isinstance(size, int)
    assert items >= 0 and size >= 0
