"""双栏对比面板：在同一个重复组内选择两个文件对比。

只展示信息，不提供删除/硬链接按钮；硬链接说明会明确提示"修改一个会影响另一个"。
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...core.fmt import format_timestamp, human_bytes
from ...core.models import DuplicateGroup, FileRecord


class _FilePane(QGroupBox):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(title, parent)
        layout = QVBoxLayout(self)
        self.combo = QComboBox()
        self.combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.combo.setMinimumContentsLength(24)
        self.details = QLabel("—")
        self.details.setWordWrap(True)
        self.details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.combo)
        layout.addWidget(self.details, 1)


class ComparePanel(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._group: DuplicateGroup | None = None
        self._counts: dict[tuple[int, int], int] = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        box = QGroupBox("双栏对比（同一重复组）")
        outer.addWidget(box)
        layout = QVBoxLayout(box)

        columns = QHBoxLayout()
        self._left = _FilePane("文件 A")
        self._right = _FilePane("文件 B")
        columns.addWidget(self._left, 1)
        columns.addWidget(self._right, 1)
        layout.addLayout(columns)

        self._swap_button = QPushButton("交换 A / B")
        self._swap_button.clicked.connect(self._swap)
        self._swap_button.setEnabled(False)
        layout.addWidget(self._swap_button)

        self._left.combo.currentIndexChanged.connect(self._update)
        self._right.combo.currentIndexChanged.connect(self._update)
        self.clear()

    # ------------------------------------------------------------- 对外 API
    def set_group(self, group: DuplicateGroup | None) -> None:
        self._group = group
        counts: dict[tuple[int, int], int] = {}
        if group is not None:
            for record in group.files:
                counts[record.identity] = counts.get(record.identity, 0) + 1
        self._counts = counts
        files = group.files if group is not None else ()
        for pane in (self._left, self._right):
            pane.combo.blockSignals(True)
            pane.combo.clear()
            for record in files:
                pane.combo.addItem(record.path, record.path)
            pane.combo.blockSignals(False)
        if len(files) >= 2:
            self._left.combo.setCurrentIndex(0)
            self._right.combo.setCurrentIndex(1)
        self._swap_button.setEnabled(len(files) >= 2)
        self._update()

    def clear(self) -> None:
        self.set_group(None)

    # ------------------------------------------------------------- 内部
    def _record(self, pane: _FilePane) -> FileRecord | None:
        if self._group is None:
            return None
        index = pane.combo.currentIndex()
        if 0 <= index < len(self._group.files):
            return self._group.files[index]
        return None

    def _update(self) -> None:
        for pane in (self._left, self._right):
            record = self._record(pane)
            if record is None:
                pane.details.setText("—")
                continue
            shared = self._counts.get(record.identity, 0) > 1
            hardlink_text = (
                "是（与组内其它路径指向同一份数据，修改一个会影响另一个）"
                if shared
                else "否（独立文件）"
            )
            sha = self._group.full_sha256 if self._group is not None else ""
            pane.details.setText(
                f"大小：{human_bytes(record.size)}\n"
                f"修改时间：{format_timestamp(record.mtime)}\n"
                f"路径：{record.path}\n"
                f"设备号 / inode：{record.dev} / {record.ino}\n"
                f"硬链接：{hardlink_text}\n"
                f"全文件 SHA256：{sha}"
            )

    def _swap(self) -> None:
        left_index = self._left.combo.currentIndex()
        right_index = self._right.combo.currentIndex()
        self._left.combo.blockSignals(True)
        self._right.combo.blockSignals(True)
        self._left.combo.setCurrentIndex(right_index)
        self._right.combo.setCurrentIndex(left_index)
        self._left.combo.blockSignals(False)
        self._right.combo.blockSignals(False)
        self._update()
