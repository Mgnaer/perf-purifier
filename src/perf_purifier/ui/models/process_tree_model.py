"""进程树 Qt 模型（``QAbstractItemModel``）。

为什么不用 QStandardItemModel：
* 树规模可能到几千节点，且需要"搜索命中节点时保留其祖先路径"的过滤语义；
* 用 ``dict[pid, ProcessNode]`` + 可见子节点索引即可 O(n) 重建视图，过滤逻辑清晰；
* 排序由建树阶段的子节点顺序决定（按进程名），不在视图层做二次排序。
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractItemModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor

from ...core.fmt import human_bytes, redact_cmdline
from ...core.models import (
    ProcessNode,
    ProcessTree,
    Severity,
    severity_color,
    severity_label,
    signature_label,
)


class ProcessTreeModel(QAbstractItemModel):
    COLUMNS: tuple[str, ...] = ("名称", "PID", "用户", "内存", "风险", "签名", "路径")

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._tree: ProcessTree | None = None
        self._nodes: dict[int, ProcessNode] = {}
        self._children: dict[int | None, list[int]] = {None: []}
        self._parent_of: dict[int, int | None] = {}
        self._row_of: dict[int, int] = {}
        self._search = ""
        self._min_severity = Severity.INFO

    # ------------------------------------------------------------ 数据入口
    def set_tree(self, tree: ProcessTree | None) -> None:
        self.beginResetModel()
        self._tree = tree
        self._nodes = dict(tree.nodes) if tree is not None else {}
        self._rebuild()
        self.endResetModel()

    def set_filters(self, search: str, min_severity: Severity) -> None:
        new_search = (search or "").strip().casefold()
        if new_search == self._search and min_severity == self._min_severity:
            return
        self.beginResetModel()
        self._search = new_search
        self._min_severity = min_severity
        self._rebuild()
        self.endResetModel()

    def node_for_index(self, index: QModelIndex) -> ProcessNode | None:
        if not index.isValid():
            return None
        return self._nodes.get(int(index.internalId()))

    def node_for_pid(self, pid: int) -> ProcessNode | None:
        return self._nodes.get(pid)

    # --------------------------------------------------------------- 重建
    def _matches(self, node: ProcessNode) -> bool:
        if node.flags and node.risk >= self._min_severity:
            severity_ok = True
        elif self._min_severity <= Severity.INFO:
            severity_ok = True
        else:
            severity_ok = False
        if not severity_ok:
            return False
        if not self._search:
            return True
        info = node.info
        haystack = " ".join(
            (
                info.name,
                info.exe or "",
                info.username or "",
                info.cmdline_text,
                str(info.pid),
            )
        ).casefold()
        return self._search in haystack

    def _sort_key(self, pid: int) -> tuple[str, int]:
        node = self._nodes.get(pid)
        if node is None:
            return ("", pid)
        return (node.info.display_name.casefold(), pid)

    def _rebuild(self) -> None:
        self._children = {None: []}
        self._parent_of.clear()
        self._row_of.clear()
        tree = self._tree
        if tree is None or not tree.nodes:
            return

        visible: dict[int, bool] = {}
        for pid in sorted(tree.nodes, key=lambda value: tree.nodes[value].depth, reverse=True):
            node = tree.nodes[pid]
            child_visible = any(visible.get(child, False) for child in node.children)
            visible[pid] = child_visible or self._matches(node)

        groups: dict[int | None, list[int]] = {}
        for pid, node in tree.nodes.items():
            if not visible.get(pid, False):
                continue
            parent_pid = node.parent_pid
            if parent_pid is None or parent_pid not in tree.nodes or not visible.get(parent_pid, False):
                groups.setdefault(None, []).append(pid)
            else:
                groups.setdefault(parent_pid, []).append(pid)

        for parent_pid, children in groups.items():
            children.sort(key=self._sort_key)
            self._children[parent_pid] = children
            for row, pid in enumerate(children):
                self._row_of[pid] = row
                self._parent_of[pid] = parent_pid

    # ------------------------------------------------------ QAbstractItemModel
    def index(self, row: int, column: int, parent: QModelIndex = QModelIndex()) -> QModelIndex:
        if column < 0 or column >= len(self.COLUMNS):
            return QModelIndex()
        parent_pid = int(parent.internalId()) if parent.isValid() else None
        children = self._children.get(parent_pid)
        if not children or row < 0 or row >= len(children):
            return QModelIndex()
        return self.createIndex(row, column, children[row])

    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()
        pid = int(index.internalId())
        parent_pid = self._parent_of.get(pid)
        if parent_pid is None:
            return QModelIndex()
        row = self._row_of.get(parent_pid)
        if row is None:
            return QModelIndex()
        return self.createIndex(row, 0, parent_pid)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid() and parent.column() != 0:
            return 0
        parent_pid = int(parent.internalId()) if parent.isValid() else None
        return len(self._children.get(parent_pid, ()))

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(self.COLUMNS):
                return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        node = self._nodes.get(int(index.internalId()))
        if node is None:
            return None
        info = node.info
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return info.display_name
            if column == 1:
                return str(info.pid)
            if column == 2:
                return info.username or "—"
            if column == 3:
                return human_bytes(info.rss)
            if column == 4:
                return severity_label(node.risk) if node.flags else "—"
            if column == 5:
                return signature_label(info.sig_status)
            if column == 6:
                return info.exe or "—"
            return None

        if role == Qt.ItemDataRole.TextAlignmentRole and column in (1, 3):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.ForegroundRole and column == 4 and node.flags:
            return QBrush(QColor(severity_color(node.risk)))

        if role == Qt.ItemDataRole.ToolTipRole:
            lines = [f"{info.display_name}（PID {info.pid}）"]
            if info.exe:
                lines.append(f"路径：{info.exe}")
            lines.append(f"签名：{signature_label(info.sig_status)}")
            if info.cmdline:
                lines.append("命令行：" + redact_cmdline(info.cmdline, enabled=True, max_chars=300))
            if node.flags:
                lines.append("风险：" + "；".join(f"[{flag.rule_id}] {flag.title}" for flag in node.flags))
            return "\n".join(lines)

        if role == Qt.ItemDataRole.UserRole:
            return info.pid
        return None
