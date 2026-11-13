"""进程树构建（纯函数，可脱离 psutil/GUI 单测）。

Windows 特有注意点：
* 父进程可能已退出，ppid 指向的 PID 可能已被系统复用 —— 用 create_time 判定；
* 受保护进程可能读不到 exe/username，但 pid/ppid 通常可读，仍参与建树；
* 损坏数据可能造成环，必须防御性断开，绝不允许死循环。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from ..core.models import Completeness, ProcessInfo, ProcessNode, ProcessTree, ScanWarning

PARENT_TIME_TOLERANCE_S = 0.5
"""父进程 create_time 晚于子进程超过该阈值，判定为 PID 复用（父已退出）。"""

SortKey = Callable[[int], tuple[str, int]]


def build_tree(
    processes: Sequence[ProcessInfo],
    *,
    completeness: Completeness = Completeness.FULL,
) -> ProcessTree:
    """由进程快照列表构建进程树。

    根节点判定：``ppid < 0``（不可读）或 ``ppid == pid``（自引用）或父 PID 不在快照。
    ``ppid != 0`` 且父不在快照的节点标记为 ``orphaned``（父进程已退出）。
    """

    nodes: dict[int, ProcessNode] = {info.pid: ProcessNode(info=info) for info in processes}
    tree = ProcessTree(nodes=nodes, total_processes=len(nodes), completeness=completeness)
    roots: list[int] = []

    for info in processes:
        node = nodes[info.pid]
        parent_pid = info.ppid
        if parent_pid < 0 or parent_pid == info.pid:
            roots.append(info.pid)
            continue
        parent = nodes.get(parent_pid)
        if parent is None:
            roots.append(info.pid)
            if parent_pid != 0:
                node.orphaned = True
                tree.orphans.append(info.pid)
            continue
        if (
            info.create_time > 0
            and parent.info.create_time > 0
            and parent.info.create_time > info.create_time + PARENT_TIME_TOLERANCE_S
        ):
            # 该 PID 在子进程启动后才出现 → 父进程已退出、PID 被复用
            roots.append(info.pid)
            node.orphaned = True
            node.parent_pid_reused = True
            tree.orphans.append(info.pid)
            continue
        node.parent_pid = parent_pid
        parent.children.append(info.pid)

    def sort_key(pid: int) -> tuple[str, int]:
        return (nodes[pid].info.display_name.casefold(), pid)

    for node in nodes.values():
        node.children.sort(key=sort_key)

    visited = _assign_depths(nodes, roots)
    residual = [pid for pid in nodes if pid not in visited]
    if residual:
        # 环或数据异常：断开并提升为根节点，宁可展示错层级也不能死循环
        for pid in residual:
            node = nodes[pid]
            previous_parent = node.parent_pid
            if previous_parent is not None and previous_parent in nodes:
                siblings = nodes[previous_parent].children
                if pid in siblings:
                    siblings.remove(pid)
            node.parent_pid = None
            node.orphaned = False
            roots.append(pid)
            tree.cycles.append(pid)
        _assign_depths(nodes, roots)

    roots.sort(key=sort_key)
    tree.roots = roots
    if tree.orphans:
        tree.warnings.append(
            ScanWarning(
                "orphans",
                f"{len(tree.orphans)} 个进程的父进程已退出或 PID 已被复用",
                phase="tree",
            )
        )
    if tree.cycles:
        tree.warnings.append(
            ScanWarning(
                "cycles",
                f"进程父子关系存在 {len(tree.cycles)} 处环，已断开为根节点（通常由 PID 复用或数据异常导致）",
                phase="tree",
            )
        )
    return tree


def _assign_depths(nodes: dict[int, ProcessNode], roots: Sequence[int]) -> set[int]:
    """从根节点做 DFS 计算层级，返回已访问集合。"""

    visited: set[int] = set()
    stack: list[tuple[int, int]] = [(pid, 0) for pid in reversed(roots)]
    while stack:
        pid, depth = stack.pop()
        if pid in visited:
            continue
        node = nodes.get(pid)
        if node is None:
            continue
        visited.add(pid)
        node.depth = depth
        for child_pid in reversed(node.children):
            if child_pid not in visited:
                stack.append((child_pid, depth + 1))
    return visited
