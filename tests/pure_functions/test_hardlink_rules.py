"""任务 2 P0 补测：组内互为硬链接判定（纯函数，无 I/O、无管理员、无网络）。

覆盖清单（对应阶段 2 依赖）：
* 2D 硬链接去重闸门：``is_mutual_hardlink`` / ``is_fully_hardlinked``；
* 2C 删除可回收估算：``st_nlink > 1`` 但组内仅 1 条路径时必须为 False，
  否则会把"组外还有一份链接"误判为可回收 0；
* 审计日志：同一输入永远得到同一输出（纯函数，可复现）。
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from perf_purifier.core.judgements import FileMeta, is_fully_hardlinked, is_mutual_hardlink


def make_meta(
    path: str = r"C:\data\file.bin",
    *,
    dev: int = 1,
    ino: int = 100,
    nlink: int = 2,
    size: int | None = 5000,
) -> FileMeta:
    """构造测试用文件身份（默认：同一 inode、nlink=2）。"""

    return FileMeta(path=path, st_dev=dev, st_ino=ino, st_nlink=nlink, size=size)


# ---------------------------------------------------------------- 正例
def test_two_paths_same_inode_is_mutual() -> None:
    group = [make_meta(r"C:\data\a\one.bin"), make_meta(r"C:\data\b\two.bin")]
    assert is_mutual_hardlink(group) is True


def test_three_paths_same_inode_is_mutual() -> None:
    group = [
        make_meta(r"C:\data\a\one.bin", nlink=3),
        make_meta(r"C:\data\b\two.bin", nlink=3),
        make_meta(r"C:\data\c\three.bin", nlink=3),
    ]
    assert is_mutual_hardlink(group) is True
    assert is_fully_hardlinked(group) is True


def test_mixed_group_pair_plus_independent_is_mutual() -> None:
    group = [
        make_meta(r"C:\data\a\one.bin", ino=100),
        make_meta(r"C:\data\b\two.bin", ino=100),
        make_meta(r"C:\data\c\independent.bin", ino=200, nlink=1),
    ]
    assert is_mutual_hardlink(group) is True
    # 组内还有独立副本 → 不是"全部互为硬链接"，2D 仍可对独立副本做去重
    assert is_fully_hardlinked(group) is False


def test_identity_match_wins_even_if_nlink_is_one() -> None:
    """nlink 计数被外部工具重置时，仍以真实 identity 判定。"""

    group = [make_meta(r"C:\data\a.bin", nlink=1), make_meta(r"C:\data\b.bin", nlink=1)]
    assert is_mutual_hardlink(group) is True
    assert is_fully_hardlinked(group) is True


# ---------------------------------------------------------------- 反例
def test_nlink_gt1_but_single_path_in_group_is_not_mutual() -> None:
    """组外还有一份链接时，删除组内文件仍可释放空间 → 不算互为硬链接。"""

    group = [
        make_meta(r"C:\data\a\only_link_in_group.bin", ino=100, nlink=2),
        make_meta(r"C:\data\b\independent.bin", ino=200, nlink=1),
    ]
    assert is_mutual_hardlink(group) is False
    assert is_fully_hardlinked(group) is False


def test_same_inode_different_device_is_not_mutual() -> None:
    group = [make_meta(dev=1, ino=100), make_meta(dev=2, ino=100)]
    assert is_mutual_hardlink(group) is False
    assert is_fully_hardlinked(group) is False


def test_all_nlink_one_is_not_mutual() -> None:
    group = [
        make_meta(ino=100, nlink=1),
        make_meta(ino=200, nlink=1),
        make_meta(ino=300, nlink=1),
    ]
    assert is_mutual_hardlink(group) is False
    assert is_fully_hardlinked(group) is False


def test_unknown_identity_is_never_claimed_as_hardlink() -> None:
    """Windows ``DirEntry.stat()`` 的 dev/ino 恒为 0：无法判定时必须保守返回 False。"""

    group = [
        make_meta(r"C:\data\a.bin", dev=0, ino=0),
        make_meta(r"C:\data\b.bin", dev=0, ino=0),
    ]
    assert is_mutual_hardlink(group) is False
    assert is_fully_hardlinked(group) is False


def test_unknown_identity_does_not_mask_known_pair() -> None:
    group = [
        make_meta(r"C:\data\a.bin", dev=0, ino=0),
        make_meta(r"C:\data\b.bin", dev=1, ino=100),
        make_meta(r"C:\data\c.bin", dev=1, ino=100),
    ]
    assert is_mutual_hardlink(group) is True
    # 存在身份未知项 → 不能断言"全部同 inode"
    assert is_fully_hardlinked(group) is False


# ---------------------------------------------------------------- 边界
def test_empty_group() -> None:
    assert is_mutual_hardlink([]) is False
    assert is_fully_hardlinked([]) is False


def test_single_element_group() -> None:
    single = [make_meta()]
    assert is_mutual_hardlink(single) is False
    assert is_fully_hardlinked(single) is False


def test_fully_hardlinked_requires_all_same_identity() -> None:
    group = [
        make_meta(ino=100, nlink=3),
        make_meta(ino=100, nlink=3),
        make_meta(ino=100, nlink=3),
    ]
    assert is_fully_hardlinked(group) is True


def test_fully_hardlinked_false_when_any_identity_differs() -> None:
    group = [make_meta(ino=100), make_meta(ino=100), make_meta(ino=101)]
    assert is_fully_hardlinked(group) is False


@pytest.mark.parametrize("nlink", [0, 1, 2, 99])
def test_nlink_does_not_change_identity_verdict(nlink: int) -> None:
    """st_nlink 只是诊断字段，不参与判定（计数可能不可信）。"""

    group = [make_meta(nlink=nlink), make_meta(nlink=nlink)]
    assert is_mutual_hardlink(group) is True
    assert is_fully_hardlinked(group) is True


def test_input_sequence_is_not_mutated() -> None:
    group = [make_meta(ino=100), make_meta(ino=200, nlink=1)]
    snapshot = list(group)
    is_mutual_hardlink(group)
    is_fully_hardlinked(group)
    assert group == snapshot


def test_meta_is_immutable() -> None:
    meta = make_meta()
    with pytest.raises(FrozenInstanceError):
        meta.st_ino = 999  # type: ignore[misc]
