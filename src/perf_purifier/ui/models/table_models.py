"""列表页 Qt 模型：网络连接 / 临时占用条目。"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor

from ...core.fmt import format_timestamp, human_bytes
from ...core.models import (
    ConnectionInfo,
    Occupancy,
    RemoteClass,
    TempEntry,
    occupancy_color,
    occupancy_label,
    remote_class_label,
    signature_label,
)
from ...module_a.temp_delete import entry_selectable


class ConnectionTableModel(QAbstractTableModel):
    COLUMNS: tuple[str, ...] = (
        "进程",
        "PID",
        "协议",
        "本地地址",
        "远端地址",
        "状态",
        "远端分类",
        "人工核实",
        "进程路径",
        "说明",
    )

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._rows: list[ConnectionInfo] = []

    def set_connections(self, connections: list[ConnectionInfo]) -> None:
        self.beginResetModel()
        self._rows = list(connections)
        self.endResetModel()

    def connection_at(self, index: QModelIndex) -> ConnectionInfo | None:
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        return self._rows[index.row()]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

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
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        connection = self._rows[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return connection.process_label
            if column == 1:
                return "—" if connection.pid is None else str(connection.pid)
            if column == 2:
                return f"{connection.protocol}({connection.family})"
            if column == 3:
                return connection.laddr.text if connection.laddr else "—"
            if column == 4:
                return connection.raddr.text if connection.raddr else "—"
            if column == 5:
                return connection.status or "—"
            if column == 6:
                return remote_class_label(connection.remote_class)
            if column == 7:
                return "⚠ 需核实" if connection.needs_review else ""
            if column == 8:
                return connection.process_exe or "—"
            if column == 9:
                return connection.explanation
            return None

        if role == Qt.ItemDataRole.TextAlignmentRole and column == 1:
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.ForegroundRole:
            if column == 7 and connection.needs_review:
                return QBrush(QColor("#b91c1c"))
            if column == 6 and connection.remote_class is RemoteClass.PUBLIC:
                return QBrush(QColor("#b45309"))

        if role == Qt.ItemDataRole.ToolTipRole:
            lines = [
                f"进程：{connection.process_label}"
                f"（PID {connection.pid if connection.pid is not None else '未知'}）",
                f"协议：{connection.protocol} / {connection.family}，状态：{connection.status or '未知'}",
                f"远端分类：{remote_class_label(connection.remote_class)}",
                f"进程签名：{signature_label(connection.process_sig)}",
            ]
            if connection.process_exe:
                lines.append(f"路径：{connection.process_exe}")
            if connection.explanation:
                lines.append(f"说明：{connection.explanation}")
            return "\n".join(lines)
        return None


class TempEntryTableModel(QAbstractTableModel):
    """临时占用条目表；第一列为可勾选列（阶段 2C 删除选择）。

    仅"非目录 + 占用状态 free/not_probed"的条目可勾选；locked/no_access 不可勾选。
    """

    COLUMNS: tuple[str, ...] = (
        "选择",
        "路径",
        "类型",
        "大小",
        "文件数",
        "最后修改",
        "占用状态",
        "探测说明",
    )

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._rows: list[TempEntry] = []
        self._checked: set[str] = set()

    def set_entries(self, entries: list[TempEntry]) -> None:
        self.beginResetModel()
        self._rows = list(entries)
        self._checked.clear()
        self.endResetModel()

    def entry_at(self, index: QModelIndex) -> TempEntry | None:
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        return self._rows[index.row()]

    def checked_entries(self) -> list[TempEntry]:
        return [entry for entry in self._rows if entry.path in self._checked]

    @property
    def checked_count(self) -> int:
        return len(self._checked)

    @property
    def checked_bytes(self) -> int:
        return sum(entry.size for entry in self._rows if entry.path in self._checked)

    def check_all_selectable(self) -> int:
        """勾选所有可删除条目（目录/locked/no_access 自动跳过）；返回新增数量。"""

        changed = 0
        for entry in self._rows:
            if entry_selectable(entry) and entry.path not in self._checked:
                self._checked.add(entry.path)
                changed += 1
        if changed and self._rows:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self._rows) - 1, 0),
                [Qt.ItemDataRole.CheckStateRole],
            )
        return changed

    def clear_checks(self) -> None:
        if not self._checked:
            return
        self._checked.clear()
        if self._rows:
            self.dataChanged.emit(
                self.index(0, 0), self.index(len(self._rows) - 1, 0), [Qt.ItemDataRole.CheckStateRole]
            )

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.COLUMNS)

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        flags = super().flags(index)
        if not index.isValid() or index.column() != 0:
            return flags
        entry = self.entry_at(index)
        if entry is None or not entry_selectable(entry):
            return flags & ~Qt.ItemFlag.ItemIsUserCheckable
        return flags | Qt.ItemFlag.ItemIsUserCheckable

    def setData(
        self,
        index: QModelIndex,
        value: Any,
        role: int = Qt.ItemDataRole.EditRole,
    ) -> bool:
        if role != Qt.ItemDataRole.CheckStateRole or not index.isValid() or index.column() != 0:
            return False
        entry = self.entry_at(index)
        if entry is None or not entry_selectable(entry):
            return False
        checked = Qt.CheckState(value) == Qt.CheckState.Checked
        if checked:
            self._checked.add(entry.path)
        else:
            self._checked.discard(entry.path)
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
        return True

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
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        entry = self._rows[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.CheckStateRole and column == 0:
            return Qt.CheckState.Checked if entry.path in self._checked else Qt.CheckState.Unchecked

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return ""
            if column == 1:
                return entry.path
            if column == 2:
                return "目录" if entry.is_dir else "文件"
            if column == 3:
                return human_bytes(entry.size)
            if column == 4:
                return str(entry.file_count)
            if column == 5:
                return format_timestamp(entry.mtime)
            if column == 6:
                return occupancy_label(entry.occupancy)
            if column == 7:
                return entry.occupancy_detail
            return None

        if role == Qt.ItemDataRole.TextAlignmentRole and column in (3, 4):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.ForegroundRole and column == 6:
            if entry.occupancy is not Occupancy.NOT_PROBED:
                return QBrush(QColor(occupancy_color(entry.occupancy)))

        if role == Qt.ItemDataRole.ToolTipRole:
            lines = [entry.path, f"扫描根：{entry.root}"]
            if not entry_selectable(entry):
                lines.append("该条目不可勾选（目录/被占用/无访问权限）")
            if entry.occupancy_detail:
                lines.append(entry.occupancy_detail)
            return "\n".join(lines)
        return None


