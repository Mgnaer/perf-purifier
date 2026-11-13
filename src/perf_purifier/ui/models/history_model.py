"""阶段 3B：动作历史只读表格模型。"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor

from ...core.action_history import HistoryRecord, action_label, result_label


class HistoryTableModel(QAbstractTableModel):
    COLUMNS: tuple[str, ...] = ("时间", "类型", "动作", "会话", "目标 / 身份", "结果", "错误码")

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._records: list[HistoryRecord] = []

    def set_records(self, records: list[HistoryRecord]) -> None:
        self.beginResetModel()
        self._records = list(records)
        self.endResetModel()

    def record_at(self, index: QModelIndex) -> HistoryRecord | None:
        if not index.isValid() or index.row() >= len(self._records):
            return None
        return self._records[index.row()]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._records)

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
        if not index.isValid() or index.row() >= len(self._records):
            return None
        record = self._records[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return record.ts
            if column == 1:
                return "会话头" if record.is_header else "执行项"
            if column == 2:
                return action_label(record.action)
            if column == 3:
                return record.session_id
            if column == 4:
                return record.target or "—"
            if column == 5:
                return result_label(record.result) if record.result else ("—" if record.is_header else "")
            if column == 6:
                return record.error_code
            return None

        if role == Qt.ItemDataRole.ForegroundRole:
            if record.result in ("failed", "refused"):
                return QBrush(QColor("#b91c1c"))
            if record.result == "success":
                return QBrush(QColor("#15803d"))
            if record.result == "dry_run":
                return QBrush(QColor("#6b7280"))
        if role == Qt.ItemDataRole.ToolTipRole:
            return (
                f"时间：{record.ts}\n会话：{record.session_id}\n动作：{action_label(record.action)}"
                f"\n结果：{result_label(record.result) if record.result else '会话头'}"
                f"\n来源：{record.source_file}"
            )
        return None
