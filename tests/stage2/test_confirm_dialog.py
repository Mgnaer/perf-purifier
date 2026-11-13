"""2A 二次确认对话框测试：默认不可确认、勾选约束、输入确认词、取消无副作用。"""

from __future__ import annotations

from PySide6.QtWidgets import QDialog

from perf_purifier.ui.dialogs.confirm_action_dialog import ConfirmActionDialog


def make_dialog(**overrides) -> ConfirmActionDialog:
    values = dict(
        title="确认删除",
        action_summary="将把 2 个文件移动到回收站",
        consequence="回收站不可用的文件会失败，不会改为永久删除。",
        items=[r"C:\Temp\a.tmp", r"C:\Temp\b.tmp"],
    )
    values.update(overrides)
    return ConfirmActionDialog(**values)


def test_confirm_disabled_until_checkbox(qapp) -> None:
    dialog = make_dialog()
    assert dialog.confirm_button.isEnabled() is False
    dialog._checkbox.setChecked(True)
    assert dialog.confirm_button.isEnabled() is True
    dialog.reject()
    assert dialog.accepted is False


def test_confirm_click_sets_accepted(qapp) -> None:
    dialog = make_dialog()
    dialog._checkbox.setChecked(True)
    dialog.confirm_button.click()
    assert dialog.accepted is True
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_typed_phrase_required(qapp) -> None:
    dialog = make_dialog(
        title="确认结束进程",
        require_typed_phrase="结束进程",
    )
    dialog._checkbox.setChecked(True)
    assert dialog.confirm_button.isEnabled() is False
    dialog._phrase_edit.setText("错误内容")
    assert dialog.confirm_button.isEnabled() is False
    dialog._phrase_edit.setText(" 结束进程 ")
    assert dialog.confirm_button.isEnabled() is True
    dialog.reject()
    assert dialog.accepted is False


def test_cancel_never_accepts(qapp) -> None:
    dialog = make_dialog()
    dialog._checkbox.setChecked(True)
    dialog.reject()
    assert dialog.accepted is False
    assert dialog.result() == QDialog.DialogCode.Rejected
