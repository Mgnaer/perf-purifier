"""模块 B 表格模型：重复组 / 组内文件 / 大文件。"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor

from ...core.fmt import format_timestamp, human_bytes
from ...core.models import DuplicateGroup, FileRecord, LargeFile
from ...module_b.hardlink_action import group_selectable


def _hardlink_text(group: DuplicateGroup) -> str:
    if group.already_hardlinked:
        return "已互为硬链接（删除无收益）"
    if group.has_hardlinks:
        return f"含硬链接（{group.distinct_inodes}/{len(group.files)} 个独立文件）"
    return "无硬链接"


def _identity_counts(group: DuplicateGroup | None) -> dict[tuple[int, int], int]:
    counts: dict[tuple[int, int], int] = {}
    if group is None:
        return counts
    for record in group.files:
        counts[record.identity] = counts.get(record.identity, 0) + 1
    return counts


class DuplicateGroupTableModel(QAbstractTableModel):
    """重复组表；第一列可勾选（阶段 2D 硬链接去重选择）。

    已含硬链接的组不可勾选（策略层同样拒绝）。
    """

    COLUMNS: tuple[str, ...] = (
        "选择",
        "组号",
        "文件数",
        "单文件大小",
        "可回收(硬链接感知)",
        "硬链接情况",
        "建议保留",
        "SHA256 前缀",
    )

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._groups: list[DuplicateGroup] = []
        self._checked: set[int] = set()

    def set_groups(self, groups: list[DuplicateGroup]) -> None:
        self.beginResetModel()
        self._groups = list(groups)
        self._checked.clear()
        self.endResetModel()

    def group_at(self, index: QModelIndex) -> DuplicateGroup | None:
        if not index.isValid() or index.row() >= len(self._groups):
            return None
        return self._groups[index.row()]

    def checked_groups(self) -> list[DuplicateGroup]:
        return [
            group for row, group in enumerate(self._groups) if row in self._checked
        ]

    @property
    def checked_count(self) -> int:
        return len(self._checked)

    def check_all_selectable(self) -> int:
        """勾选所有可处理重复组（已含硬链接的组自动跳过）；返回新增数量。"""

        changed = 0
        for row, group in enumerate(self._groups):
            if group_selectable(group) and row not in self._checked:
                self._checked.add(row)
                changed += 1
        if changed and self._groups:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self._groups) - 1, 0),
                [Qt.ItemDataRole.CheckStateRole],
            )
        return changed

    def clear_checks(self) -> None:
        if not self._checked:
            return
        self._checked.clear()
        if self._groups:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self._groups) - 1, 0),
                [Qt.ItemDataRole.CheckStateRole],
            )

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._groups)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.COLUMNS)

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        flags = super().flags(index)
        if not index.isValid() or index.column() != 0:
            return flags
        group = self.group_at(index)
        if group is None or not group_selectable(group):
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
        group = self.group_at(index)
        if group is None or not group_selectable(group):
            return False
        if Qt.CheckState(value) == Qt.CheckState.Checked:
            self._checked.add(index.row())
        else:
            self._checked.discard(index.row())
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
        if not index.isValid() or index.row() >= len(self._groups):
            return None
        group = self._groups[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.CheckStateRole and column == 0:
            return Qt.CheckState.Checked if index.row() in self._checked else Qt.CheckState.Unchecked

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return ""
            if column == 1:
                return str(group.group_id)
            if column == 2:
                return str(len(group.files))
            if column == 3:
                return human_bytes(group.size)
            if column == 4:
                return human_bytes(group.reclaimable_bytes)
            if column == 5:
                return _hardlink_text(group)
            if column == 6:
                suggested = group.suggested_keep
                return suggested.path if suggested is not None else "—"
            if column == 7:
                return group.full_sha256[:16]
            return None

        if role == Qt.ItemDataRole.TextAlignmentRole and column in (1, 2, 3, 4):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role == Qt.ItemDataRole.ForegroundRole and column == 4 and group.already_hardlinked:
            return QBrush(QColor("#6b7280"))
        if role == Qt.ItemDataRole.ForegroundRole and column == 6 and group.suggested_keep_path:
            return QBrush(QColor("#15803d"))
        if role == Qt.ItemDataRole.ToolTipRole:
            return (
                f"组 {group.group_id}：{len(group.files)} 个文件，单文件 {human_bytes(group.size)}\n"
                f"独立 inode 数：{group.distinct_inodes}\n"
                f"SHA256：{group.full_sha256}\n"
                f"{_hardlink_text(group)}\n"
                f"建议保留：{group.suggested_keep_path or '—'}（仅建议，不会自动执行任何操作）"
            )
        return None


class DuplicateFileTableModel(QAbstractTableModel):
    COLUMNS: tuple[str, ...] = ("文件路径", "大小", "修改时间", "硬链接副本", "建议")

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._group: DuplicateGroup | None = None
        self._files: list[FileRecord] = []
        self._counts: dict[tuple[int, int], int] = {}

    def set_group(self, group: DuplicateGroup | None) -> None:
        self.beginResetModel()
        self._group = group
        self._files = list(group.files) if group is not None else []
        self._counts = _identity_counts(group)
        self.endResetModel()

    def file_at(self, index: QModelIndex) -> FileRecord | None:
        if not index.isValid() or index.row() >= len(self._files):
            return None
        return self._files[index.row()]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._files)

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
        if not index.isValid() or index.row() >= len(self._files):
            return None
        record = self._files[index.row()]
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return record.path
            if column == 1:
                return human_bytes(record.size)
            if column == 2:
                return format_timestamp(record.mtime)
            if column == 3:
                return "是" if self._counts.get(record.identity, 0) > 1 else ""
            if column == 4:
                if self._group is not None and record.path == self._group.suggested_keep_path:
                    return "建议保留"
                return ""
            return None
        if role == Qt.ItemDataRole.TextAlignmentRole and column == 1:
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role == Qt.ItemDataRole.ForegroundRole and column == 3:
            return QBrush(QColor("#b45309"))
        if role == Qt.ItemDataRole.ForegroundRole and column == 4:
            if self._group is not None and record.path == self._group.suggested_keep_path:
                return QBrush(QColor("#15803d"))
        if role == Qt.ItemDataRole.ToolTipRole:
            return (
                f"{record.path}\n设备号/inode：{record.dev} / {record.ino}\n"
                f"修改时间：{format_timestamp(record.mtime)}"
            )
        return None


class LargeFileTableModel(QAbstractTableModel):
    COLUMNS: tuple[str, ...] = ("排名", "文件路径", "大小", "修改时间")

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._files: list[LargeFile] = []

    def set_files(self, files: list[LargeFile]) -> None:
        self.beginResetModel()
        self._files = list(files)
        self.endResetModel()

    def file_at(self, index: QModelIndex) -> LargeFile | None:
        if not index.isValid() or index.row() >= len(self._files):
            return None
        return self._files[index.row()]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._files)

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
        if not index.isValid() or index.row() >= len(self._files):
            return None
        item = self._files[index.row()]
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return str(index.row() + 1)
            if column == 1:
                return item.path
            if column == 2:
                return human_bytes(item.size)
            if column == 3:
                return format_timestamp(item.mtime)
            return None
        if role == Qt.ItemDataRole.TextAlignmentRole and column in (0, 2):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        return None
