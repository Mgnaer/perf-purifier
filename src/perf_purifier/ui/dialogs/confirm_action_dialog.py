"""阶段 2 通用二次确认对话框（只负责 UI 与输入约束，不执行任何动作）。

安全约定：
* 默认「确认执行」按钮**不可点击**，必须勾选"我已了解后果"；
* 高风险动作（如结束进程）可要求输入确认词（``require_typed_phrase``）；
* 目标清单只读展示；取消按钮默认聚焦；对话框关闭不产生任何副作用。
"""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)


class ConfirmActionDialog(QDialog):
    def __init__(
        self,
        *,
        title: str,
        action_summary: str,
        consequence: str,
        items: Sequence[str],
        require_typed_phrase: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.accepted = False
        self.setWindowTitle(title)
        self.setMinimumSize(640, 480)

        layout = QVBoxLayout(self)
        summary = QLabel(action_summary)
        summary.setWordWrap(True)
        summary_font = summary.font()
        summary_font.setPointSize(max(11, summary_font.pointSize() + 2))
        summary_font.setBold(True)
        summary.setFont(summary_font)
        layout.addWidget(summary)

        warning = QLabel(consequence)
        warning.setWordWrap(True)
        warning.setStyleSheet("color: #b91c1c;")
        layout.addWidget(warning)

        items_view = QPlainTextEdit()
        items_view.setReadOnly(True)
        items_view.setPlainText("\n".join(items))
        items_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(items_view, 1)

        self._checkbox = QCheckBox("我已了解后果，并确认执行")
        layout.addWidget(self._checkbox)

        self._phrase_edit: QLineEdit | None = None
        if require_typed_phrase:
            phrase_row = QVBoxLayout()
            phrase_label = QLabel(f'高风险操作：请输入「{require_typed_phrase}」以继续')
            phrase_label.setWordWrap(True)
            self._phrase_edit = QLineEdit()
            self._phrase_edit.setPlaceholderText(require_typed_phrase)
            phrase_row.addWidget(phrase_label)
            phrase_row.addWidget(self._phrase_edit)
            layout.addLayout(phrase_row)
            self._phrase_edit.textChanged.connect(self._update_confirm_state)

        buttons = QDialogButtonBox()
        cancel_button = buttons.addButton("取消", QDialogButtonBox.ButtonRole.RejectRole)
        self._confirm_button = buttons.addButton("确认执行", QDialogButtonBox.ButtonRole.AcceptRole)
        self._confirm_button.setEnabled(False)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self._on_accept)
        cancel_button.setDefault(True)
        layout.addWidget(buttons)

        self._checkbox.toggled.connect(self._update_confirm_state)

    @property
    def confirm_button(self) -> QWidget:
        return self._confirm_button

    def _update_confirm_state(self) -> None:
        enabled = self._checkbox.isChecked()
        if enabled and self._phrase_edit is not None:
            enabled = self._phrase_edit.text().strip() == self._phrase_edit.placeholderText().strip()
        self._confirm_button.setEnabled(enabled)

    def _on_accept(self) -> None:
        self.accepted = True
        self.accept()
