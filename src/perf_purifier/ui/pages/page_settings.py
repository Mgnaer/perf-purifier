"""阶段 3A：设置页（运行信息 / 执行层开关只读展示 / 一键关闭全部动作 / 完整配置只读）。

安全约定（S3-3）：
* 本页**只能关闭**执行层开关，不提供开启入口（开启必须手工编辑 config.json 后重启，保留安全摩擦）；
* 关闭操作立即写盘并对当前运行实例生效（无需重启）；
* 任何配置损坏都按"全部关闭"处理（``AppConfig.load`` 的默认值即全关）。
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.config import (
    APP_NAME,
    AppConfig,
    app_data_dir,
    log_dir,
)
from ...core.config import (
    config_path as default_config_path,
)
from ...core.shell import open_containing_folder
from ..dialogs.about_dialog import AboutDialog

_ACTION_SWITCHES: tuple[tuple[str, str, str], ...] = (
    ("stage2_enabled", "执行层总开关", "关闭后所有动作按钮不可用（默认关闭）"),
    ("allow_delete_temp", "删除 Temp 到回收站", "开启后仍需勾选 + 二次确认"),
    ("allow_hardlink_dedupe", "硬链接去重", "仅同卷 NTFS，执行前重算哈希"),
    ("allow_kill_process", "结束进程", "需输入确认词；受保护进程拒绝"),
    ("allow_clean_space", "清理磁盘垃圾（磁盘空间页）", "需首次预演 + 勾选 + 二次确认；只进回收站"),
)


logger = logging.getLogger(__name__)

MAX_WHITELIST_ITEMS = 100
MAX_EXCLUDE_ITEMS = 100


class SettingsPage(QWidget):
    actions_disabled = Signal()

    def __init__(
        self,
        config: AppConfig,
        *,
        is_admin: bool,
        app_version: str = "",
        config_path: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._is_admin = is_admin
        self._app_version = app_version
        self._config_path = Path(config_path) if config_path is not None else default_config_path()
        self._build_ui()
        self.refresh()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)

        title = QLabel("运行信息")
        title_font = title.font()
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        self._info_labels: dict[str, QLabel] = {
            "admin": QLabel(),
            "version": QLabel(),
            "config": QLabel(),
            "logs": QLabel(),
            "data": QLabel(),
        }
        info_form = QFormLayout()
        info_form.addRow("当前权限：", self._info_labels["admin"])
        info_form.addRow("程序版本：", self._info_labels["version"])
        info_form.addRow("配置文件：", self._info_labels["config"])
        info_form.addRow("日志目录：", self._info_labels["logs"])
        info_form.addRow("数据目录：", self._info_labels["data"])
        for label in self._info_labels.values():
            label.setTextInteractionFlags(label.textInteractionFlags() | label.textInteractionFlags().TextSelectableByMouse)
            label.setWordWrap(True)
        layout.addLayout(info_form)

        open_row = QHBoxLayout()
        self._btn_open_config = QPushButton("打开配置目录")
        self._btn_open_config.clicked.connect(self._on_open_config_dir)
        open_row.addWidget(self._btn_open_config)
        self._btn_about = QPushButton("关于 / 安全说明")
        self._btn_about.clicked.connect(self._show_about)
        open_row.addWidget(self._btn_about)
        open_row.addStretch(1)
        layout.addLayout(open_row)

        switch_title = QLabel("执行层开关（只读）")
        switch_title_font = switch_title.font()
        switch_title_font.setBold(True)
        switch_title.setFont(switch_title_font)
        layout.addWidget(switch_title)

        self._switch_table = QTableWidget(len(_ACTION_SWITCHES), 3)
        self._switch_table.setHorizontalHeaderLabels(["开关", "当前状态", "说明"])
        self._switch_table.verticalHeader().setVisible(False)
        self._switch_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._switch_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._switch_table.horizontalHeader().setStretchLastSection(True)
        self._switch_table.setColumnWidth(0, 200)
        self._switch_table.setColumnWidth(1, 110)
        layout.addWidget(self._switch_table)

        self._hint = QLabel()
        self._hint.setWordWrap(True)
        self._hint.setStyleSheet("color: palette(dark);")
        layout.addWidget(self._hint)

        action_row = QHBoxLayout()
        self._btn_disable = QPushButton("一键关闭所有执行层开关")
        self._btn_disable.clicked.connect(self._on_disable_actions)
        action_row.addWidget(self._btn_disable)
        self._btn_reset_preview = QPushButton("重置首次预演标记")
        self._btn_reset_preview.clicked.connect(self._on_reset_preview_flags)
        action_row.addWidget(self._btn_reset_preview)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        rules_title = QLabel("分析白名单与扫描排除（只影响评分与文件扫描范围，不改变动作授权）")
        rules_title_font = rules_title.font()
        rules_title_font.setBold(True)
        rules_title.setFont(rules_title_font)
        layout.addWidget(rules_title)

        self._rule_edits: dict[str, QLineEdit] = {}
        self._rule_lists: dict[str, QListWidget] = {}
        for caption_text, attr, placeholder in (
            ("分析白名单-路径", "analysis_whitelist_paths", r"例如 C:\Tools\my_tool.exe"),
            ("分析白名单-进程名", "analysis_whitelist_names", "例如 my_tool.exe"),
            ("文件扫描排除规则", "file_scan_exclude_patterns", r"例如 C:\$Recycle.Bin 或 *.iso"),
        ):
            rule_row = QHBoxLayout()
            caption = QLabel(caption_text)
            caption.setMinimumWidth(140)
            edit = QLineEdit()
            edit.setPlaceholderText(placeholder)
            add_button = QPushButton("添加")
            remove_button = QPushButton("移除选中")
            rule_list = QListWidget()
            rule_list.setMaximumHeight(64)
            add_button.clicked.connect(
                lambda _checked=False, a=attr, e=edit: self._add_rule(a, e)
            )
            remove_button.clicked.connect(lambda _checked=False, a=attr: self._remove_rule(a))
            rule_row.addWidget(caption)
            rule_row.addWidget(edit, 1)
            rule_row.addWidget(add_button)
            rule_row.addWidget(remove_button)
            layout.addLayout(rule_row)
            layout.addWidget(rule_list)
            self._rule_edits[attr] = edit
            self._rule_lists[attr] = rule_list

        config_title = QLabel("完整配置（只读；开启动作开关请手工编辑配置文件后重启）")
        config_title_font = config_title.font()
        config_title_font.setBold(True)
        config_title.setFont(config_title_font)
        layout.addWidget(config_title)
        layout.addWidget(config_title)

        self._config_table = QTableWidget(0, 3)
        self._config_table.setHorizontalHeaderLabels(["配置项", "当前值", "说明"])
        self._config_table.verticalHeader().setVisible(False)
        self._config_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._config_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._config_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self._config_table, 1)

    # ------------------------------------------------------------- 刷新
    def refresh(self) -> None:
        self._info_labels["admin"].setText("管理员（提升权限）" if self._is_admin else "普通用户（建议以管理员重启以获得完整数据）")
        self._info_labels["version"].setText(f"{APP_NAME} {self._app_version or '—'}")
        self._info_labels["config"].setText(str(self._config_path))
        self._info_labels["logs"].setText(str(log_dir()))
        self._info_labels["data"].setText(str(app_data_dir()))

        for row, (field, label, explanation) in enumerate(_ACTION_SWITCHES):
            enabled = bool(getattr(self._config, field, False))
            self._switch_table.setItem(row, 0, QTableWidgetItem(label))
            status = QTableWidgetItem("开启" if enabled else "关闭")
            self._switch_table.setItem(row, 1, status)
            self._switch_table.setItem(row, 2, QTableWidgetItem(explanation))
        any_enabled = any(bool(getattr(self._config, field, False)) for field, _label, _exp in _ACTION_SWITCHES)
        self._btn_disable.setEnabled(any_enabled)
        self._hint.setText(
            "关闭会立即写盘并生效；开启必须手工编辑 config.json 后重启程序（本页不提供开启入口）。"
            if any_enabled
            else "当前执行层已全部关闭（安全默认状态）。开启需手工编辑 config.json 后重启。"
        )

        values = asdict(self._config)
        self._config_table.setRowCount(len(values))
        for row, (key, value) in enumerate(values.items()):
            self._config_table.setItem(row, 0, QTableWidgetItem(key))
            self._config_table.setItem(row, 1, QTableWidgetItem(str(value)))
        for attr, widget in self._rule_lists.items():
            widget.clear()
            for entry in getattr(self._config, attr, []):
                widget.addItem(entry)

    # ------------------------------------------------------------- 动作
    def _on_disable_actions(self) -> None:
        changed = False
        for field, _label, _explanation in _ACTION_SWITCHES:
            if bool(getattr(self._config, field, False)):
                setattr(self._config, field, False)
                changed = True
        if not changed:
            self.refresh()
            self.actions_disabled.emit()
            return
        saved, message = self._config.save(self._config_path)
        if not saved:
            QMessageBox.critical(self, "保存失败", message)
            return
        self.refresh()
        self.actions_disabled.emit()
        QMessageBox.information(
            self,
            "已关闭全部执行层开关",
            "已将 stage2_enabled / allow_delete_temp / allow_hardlink_dedupe / "
            "allow_kill_process / allow_clean_space 全部置为 false 并保存。\n\n"
            "关闭操作已当场生效；如需重新开启，请手工编辑配置文件后重启程序。",
        )

    def _on_reset_preview_flags(self) -> None:
        from ...core.first_run import reset_preview_flags

        if not reset_preview_flags(self._config):
            QMessageBox.information(self, "无需重置", "三个动作的首次预演标记均未设置。")
            self.refresh()
            return
        saved, message = self._config.save(self._config_path)
        if not saved:
            QMessageBox.critical(self, "保存失败", message)
            return
        self.refresh()
        QMessageBox.information(
            self,
            "已重置",
            "首次预演标记已重置：下次真正执行某动作前需重新完成一次预演（先点击“预演选中项”）。",
        )
    def _show_about(self) -> None:
        dialog = AboutDialog(
            is_admin=self._is_admin,
            app_version=self._app_version,
            config_file=self._config_path,
            parent=self,
        )
        dialog.exec()

    def _on_open_config_dir(self) -> None:
        ok, error = open_containing_folder(str(self._config_path))
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    # ------------------------------------------------- 分析白名单 / 扫描排除（4C）
    def _add_rule(self, attr: str, edit: QLineEdit) -> None:
        value = edit.text().strip()
        if not value:
            QMessageBox.information(self, "内容为空", "请输入要添加的内容。")
            return
        current = list(getattr(self._config, attr, []))
        if value in current:
            QMessageBox.information(self, "已存在", "该条目已存在，未重复添加。")
            return
        limit = MAX_WHITELIST_ITEMS
        if len(current) >= limit:
            QMessageBox.warning(self, "数量上限", f"最多 {limit} 条，请先移除部分条目。")
            return
        current.append(value)
        setattr(self._config, attr, current)
        self._save_rules()
        edit.clear()
        self.refresh()
        logger.info("用户修改分析白名单/排除规则：+ %s（%s）", value, attr)

    def _remove_rule(self, attr: str) -> None:
        widget = self._rule_lists[attr]
        item = widget.currentItem()
        if item is None:
            QMessageBox.information(self, "未选择条目", "请先在列表中选择要移除的条目。")
            return
        value = item.text()
        current = [entry for entry in getattr(self._config, attr, []) if entry != value]
        setattr(self._config, attr, current)
        self._save_rules()
        self.refresh()
        logger.info("用户修改分析白名单/排除规则：- %s（%s）", value, attr)

    def _save_rules(self) -> None:
        saved, message = self._config.save(self._config_path)
        if not saved:
            QMessageBox.critical(self, "保存失败", message)
