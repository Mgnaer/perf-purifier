"""模块 C（磁盘空间页）表格模型：概览 / 垃圾规则（可勾选）/ 大文件。"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from ...core.fmt import human_bytes, percent_text
from ...module_c.models import RISK_ORDER, JunkRuleResult, LargeFileHit, OverviewEntry


class OverviewTableModel(QAbstractTableModel):
    """卷根顶层占用表。"""

    HEADERS = ("名称", "类型", "占用", "占已用", "文件数")

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._entries: list[OverviewEntry] = []
        self._used = 0

    def set_entries(self, entries: list[OverviewEntry], *, used_bytes: int = 0) -> None:
        self.beginResetModel()
        self._entries = list(entries)
        self._used = max(0, int(used_bytes))
        self.endResetModel()

    def entry_at(self, index: QModelIndex) -> OverviewEntry | None:
        if not index.isValid() or not (0 <= index.row() < len(self._entries)):
            return None
        return self._entries[index.row()]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(  # noqa: N802 - Qt API
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        if 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if not index.isValid() or not (0 <= index.row() < len(self._entries)):
            return None
        entry = self._entries[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            column = index.column()
            if column == 0:
                return entry.name
            if column == 1:
                return "目录" if entry.is_dir else "文件"
            if column == 2:
                return human_bytes(entry.size)
            if column == 3:
                return percent_text(entry.size, self._used)
            if column == 4:
                return f"{entry.file_count:,}"
        elif role == Qt.ItemDataRole.TextAlignmentRole and index.column() >= 2:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        elif role == Qt.ItemDataRole.ToolTipRole:
            return entry.path
        return None


class JunkRuleTableModel(QAbstractTableModel):
    """垃圾规则聚合表（第一列可勾选，默认勾选安全级）。"""

    HEADERS = ("选择", "类别", "规则", "等级", "项数", "大小", "说明")
    COLUMN_CHECK = 0

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._results: list[JunkRuleResult] = []
        self._checked: set[str] = set()

    # ------------------------------------------------------------------ 数据
    def set_results(
        self,
        results: list[JunkRuleResult],
        *,
        default_checked_risks: set[str] | None = None,
    ) -> None:
        self.beginResetModel()
        self._results = [result for result in results if result.items or result.error]
        self._results.sort(
            key=lambda result: (RISK_ORDER.get(result.rule.risk, 9), -result.total_size, result.rule.id)
        )
        checked_risks = default_checked_risks or set()
        self._checked = {
            result.rule.id
            for result in self._results
            if result.rule.risk in checked_risks and result.items
        }
        self.endResetModel()

    def rule_result_at(self, index: QModelIndex) -> JunkRuleResult | None:
        if not index.isValid() or not (0 <= index.row() < len(self._results)):
            return None
        return self._results[index.row()]

    def checked_rule_ids(self) -> list[str]:
        return [rule_id for rule_id in self._checked]

    def checked_results(self) -> list[JunkRuleResult]:
        return [result for result in self._results if result.rule.id in self._checked]

    def checked_count(self) -> int:
        return sum(len(result.items) for result in self.checked_results())

    def checked_bytes(self) -> int:
        return sum(result.total_size for result in self.checked_results())

    def check_all_of_risks(self, risks: set[str]) -> None:
        self.beginResetModel()
        self._checked = {
            result.rule.id
            for result in self._results
            if result.rule.risk in risks and result.items
        }
        self.endResetModel()

    def clear_checks(self) -> None:
        if not self._checked:
            return
        self.beginResetModel()
        self._checked.clear()
        self.endResetModel()

    # ------------------------------------------------------------------ Qt
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self._results)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self.HEADERS)

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:  # noqa: N802 - Qt API
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        if index.column() == self.COLUMN_CHECK:
            result = self.rule_result_at(index)
            if result is None or not result.items:
                return base
            return base | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def setData(  # noqa: N802 - Qt API
        self, index: QModelIndex, value: Any, role: int = Qt.ItemDataRole.EditRole
    ) -> bool:
        if role != Qt.ItemDataRole.CheckStateRole or index.column() != self.COLUMN_CHECK:
            return False
        result = self.rule_result_at(index)
        if result is None or not result.items:
            return False
        if int(value) == int(Qt.CheckState.Checked):
            self._checked.add(result.rule.id)
        else:
            self._checked.discard(result.rule.id)
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
        return True

    def headerData(  # noqa: N802 - Qt API
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        if 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        result = self.rule_result_at(index)
        if result is None:
            return None
        rule = result.rule
        column = index.column()
        if role == Qt.ItemDataRole.CheckStateRole and column == self.COLUMN_CHECK:
            if not result.items:
                return Qt.CheckState.Unchecked
            return Qt.CheckState.Checked if rule.id in self._checked else Qt.CheckState.Unchecked
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 1:
                return rule.category
            if column == 2:
                return rule.name
            if column == 3:
                return rule.risk_label
            if column == 4:
                return f"{len(result.items):,}"
            if column == 5:
                return human_bytes(result.total_size)
            if column == 6:
                return result.error or rule.note or ("需管理员权限" if rule.requires_admin else "")
        elif role == Qt.ItemDataRole.TextAlignmentRole and column in (4, 5):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        elif role == Qt.ItemDataRole.ToolTipRole:
            lines = [f"规则：{rule.id}", f"删除方式：{rule.mode_label}"]
            if rule.requires_admin:
                lines.append("需要管理员权限")
            if rule.note:
                lines.append(rule.note)
            if result.error:
                lines.append(f"错误：{result.error}")
            return "\n".join(lines)
        return None


class SpaceLargeFileTableModel(QAbstractTableModel):
    """最大文件排行表。"""

    HEADERS = ("大小", "修改时间", "路径")

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._files: list[LargeFileHit] = []

    def set_files(self, files: list[LargeFileHit]) -> None:
        self.beginResetModel()
        self._files = list(files)
        self.endResetModel()

    def file_at(self, index: QModelIndex) -> LargeFileHit | None:
        if not index.isValid() or not (0 <= index.row() < len(self._files)):
            return None
        return self._files[index.row()]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self._files)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(  # noqa: N802 - Qt API
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        if 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if not index.isValid() or not (0 <= index.row() < len(self._files)):
            return None
        hit = self._files[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            column = index.column()
            if column == 0:
                return human_bytes(hit.size)
            if column == 1:
                import time  # noqa: PLC0415 - 展示用

                try:
                    return time.strftime("%Y-%m-%d %H:%M", time.localtime(hit.mtime))
                except (OSError, OverflowError, ValueError):
                    return "—"
            return hit.path
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() == 0:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ToolTipRole:
            return hit.path
        return None


__all__ = ["JunkRuleTableModel", "OverviewTableModel", "SpaceLargeFileTableModel"]
