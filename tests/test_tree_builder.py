"""进程树构建测试（纯逻辑，不依赖 psutil）。"""

from __future__ import annotations

from perf_purifier.core.models import Completeness, ProcessInfo
from perf_purifier.module_a.tree_builder import build_tree


def _info(pid: int, ppid: int, name: str = "proc", create_time: float = 1000.0) -> ProcessInfo:
    return ProcessInfo(pid=pid, ppid=ppid, name=name, create_time=create_time)


def test_roots_and_depths() -> None:
    tree = build_tree([_info(4, 0, "System"), _info(100, 4, "services"), _info(200, 100, "svchost")])
    assert tree.roots == [4]
    assert tree.nodes[100].parent_pid == 4
    assert tree.nodes[100].depth == 1
    assert tree.nodes[200].depth == 2
    assert tree.nodes[4].children == [100]
    assert tree.orphans == []
    assert tree.cycles == []


def test_orphan_when_parent_missing() -> None:
    tree = build_tree([_info(4, 0, "System"), _info(900, 12345, "child")])
    assert 900 in tree.orphans
    assert tree.nodes[900].orphaned is True
    assert set(tree.roots) == {4, 900}
    assert any(warning.code == "orphans" for warning in tree.warnings)


def test_pid_reuse_detected() -> None:
    parent = _info(500, 4, "parent", create_time=2000.0)
    child = _info(600, 500, "child", create_time=1000.0)
    tree = build_tree([_info(4, 0, "System"), parent, child])
    node = tree.nodes[600]
    assert node.parent_pid_reused is True
    assert node.orphaned is True
    assert node.parent_pid is None
    assert 600 in tree.orphans


def test_cycle_is_broken_without_hang() -> None:
    tree = build_tree([_info(700, 701, "a"), _info(701, 700, "b")])
    assert set(tree.cycles) == {700, 701}
    assert set(tree.roots) == {700, 701}
    assert tree.nodes[700].parent_pid is None
    assert tree.nodes[701].parent_pid is None
    assert any(warning.code == "cycles" for warning in tree.warnings)


def test_unknown_ppid_is_root_not_orphan() -> None:
    tree = build_tree([_info(800, -1, "unknown-parent")])
    assert tree.roots == [800]
    assert tree.orphans == []
    assert tree.nodes[800].depth == 0


def test_self_parent_treated_as_root() -> None:
    tree = build_tree([_info(810, 810, "weird")])
    assert tree.roots == [810]
    assert tree.orphans == []


def test_children_sorted_by_display_name() -> None:
    tree = build_tree([_info(4, 0, "System"), _info(30, 4, "zeta"), _info(20, 4, "alpha")])
    assert tree.nodes[4].children == [20, 30]


def test_empty_input() -> None:
    tree = build_tree([])
    assert tree.nodes == {}
    assert tree.roots == []
    assert tree.total_processes == 0


def test_completeness_and_count_passthrough() -> None:
    tree = build_tree([_info(1, 0, "a")], completeness=Completeness.PARTIAL)
    assert tree.completeness is Completeness.PARTIAL
    assert tree.total_processes == 1


def test_iter_preorder_covers_all_nodes() -> None:
    tree = build_tree(
        [
            _info(4, 0, "System"),
            _info(100, 4, "services"),
            _info(200, 4, "explorer"),
            _info(300, 100, "svchost"),
        ]
    )
    order = [node.pid for node in tree.iter_preorder()]
    assert sorted(order) == [4, 100, 200, 300]
    assert order.index(4) == 0
    assert order.index(100) < order.index(300)
