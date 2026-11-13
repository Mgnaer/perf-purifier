"""临时占用页（模块 A · 阶段 1B 只读扫描 + 阶段 2C 删除到回收站）。

安全边界（S3/S4/S5/S8）：
* 删除功能受 ``stage2_enabled`` + ``allow_delete_temp`` 双开关控制，默认关闭；
* 必须勾选目标 + 策略判定 + 二次确认对话框；默认不勾选任何项；
* 只调用注入的回收站后端（send2trash），失败仅报告，绝不永久删除；
* 执行前重验文件身份（存在/大小/修改时间/reparse），变化则拒绝该项；
* 审计日志由 ActionJob 写入 ``operations.jsonl``。
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.action_policy import ActionKind, ActionPolicy
from ...core.audit import ActionAuditWriter, rotate_audit_log
from ...core.config import AppConfig, config_path, default_export_dir, log_dir
from ...core.fmt import human_bytes, now_text
from ...core.judgements import CompletenessVerdict
from ...core.models import (
    Completeness,
    Occupancy,
    ProcessScanResult,
    TempEntry,
    completeness_label,
    occupancy_label,
)
from ...core.shell import open_containing_folder
from ...core.trash import Send2TrashBackend
from ...jobs.action_job import ActionJob, ActionSessionResult
from ...jobs.base_job import JobRunner
from ...module_a.report import export_temp_csv
from ...module_a.temp_delete import (
    DeleteTempExecutor,
    build_delete_preview,
    preview_refusal_text,
    temp_scan_verdict,
)
from ..action_preview import ensure_first_preview, preview_result_text, run_preview_job
from ..dialogs.confirm_action_dialog import ConfirmActionDialog
from ..models.table_models import TempEntryTableModel
from ..widgets.kpi_bar import KpiBar

logger = logging.getLogger(__name__)


class TempPage(QWidget):
    refresh_requested = Signal(str)
    status_message = Signal(str)

    def __init__(
        self,
        config: AppConfig,
        *,
        is_admin: bool = False,
        app_version: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._is_admin = is_admin
        self._app_version = app_version
        self._audit_dir: Path = log_dir()
        self._config_save_path: Path | None = None
        self._result: ProcessScanResult | None = None
        self._entries: list[TempEntry] = []
        self._busy = False
        self._action_running = False
        self._action_runner = JobRunner(self)
        self._action_runner.finished.connect(self._on_action_runner_finished)
        self._build_ui()
        self._refresh_export_state()
        self._update_selection_state()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self._btn_refresh = QPushButton("重新扫描")
        self._btn_refresh.clicked.connect(lambda: self.refresh_requested.emit("temp"))
        self._root_combo = QComboBox()
        self._root_combo.addItem("全部扫描根", "")
        self._root_combo.currentIndexChanged.connect(self._apply_filter)
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("搜索：路径 / 占用状态")
        self._search_edit.setClearButtonEnabled(True)
        self._search_edit.textChanged.connect(self._apply_filter)
        self._btn_open = QPushButton("打开临时目录")
        self._btn_open.clicked.connect(self._open_selected)
        self._btn_export = QPushButton("导出 CSV")
        self._btn_export.clicked.connect(self.export_csv)

        toolbar.addWidget(self._btn_refresh)
        toolbar.addSpacing(8)
        toolbar.addWidget(QLabel("扫描根："))
        toolbar.addWidget(self._root_combo)
        toolbar.addWidget(self._search_edit, 1)
        toolbar.addWidget(self._btn_open)
        toolbar.addWidget(self._btn_export)
        layout.addLayout(toolbar)

        self._hint = QLabel("尚未扫描：点击“重新扫描”生成一次完整只读检查（进程 + 网络 + 临时占用）。")
        self._hint.setWordWrap(True)
        self._hint.setStyleSheet("color: palette(dark); font-size: 11px;")
        layout.addWidget(self._hint)

        action_row = QHBoxLayout()
        action_row.setSpacing(6)
        self._selection_label = QLabel("未选择目标")
        self._selection_label.setStyleSheet("color: palette(dark);")
        self._btn_clear_selection = QPushButton("清空选择")
        self._btn_clear_selection.clicked.connect(self._on_clear_selection)
        self._btn_select_all = QPushButton("全选可删除项")
        self._btn_select_all.clicked.connect(self._on_select_all)
        self._btn_preview = QPushButton("预演选中项（不执行）")
        self._btn_preview.clicked.connect(self._start_preview)
        self._btn_delete = QPushButton("删除选中项（回收站）")
        self._btn_delete.clicked.connect(self._start_delete)
        action_row.addWidget(self._selection_label, 1)
        action_row.addWidget(self._btn_select_all)
        action_row.addWidget(self._btn_clear_selection)
        action_row.addWidget(self._btn_preview)
        action_row.addWidget(self._btn_delete)
        layout.addLayout(action_row)

        self._kpi = KpiBar(
            [
                ("total", "估算总量"),
                ("files", "文件数"),
                ("locked", "疑似被占用"),
                ("roots", "扫描根"),
                ("completeness", "数据完整度"),
            ]
        )
        layout.addWidget(self._kpi)

        self._root_table = QTableWidget(0, 5)
        self._root_table.setHorizontalHeaderLabels(["临时目录", "类型", "状态", "大小", "文件数"])
        self._root_table.verticalHeader().setVisible(False)
        self._root_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._root_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._root_table.setMaximumHeight(150)
        root_header = self._root_table.horizontalHeader()
        root_header.setStretchLastSection(False)
        root_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 3, 4):
            root_header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self._root_table)

        self._model = TempEntryTableModel(self)
        self._model.dataChanged.connect(self._update_selection_state)
        self._view = QTableView()
        self._view.setModel(self._model)
        self._view.setAlternatingRowColors(True)
        self._view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._view.setWordWrap(False)
        self._view.doubleClicked.connect(self._open_selected)
        header = self._view.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._view.setColumnWidth(0, 40)
        self._view.setColumnWidth(1, 400)
        self._view.setColumnWidth(2, 56)
        self._view.setColumnWidth(3, 88)
        self._view.setColumnWidth(4, 62)
        self._view.setColumnWidth(5, 145)
        self._view.setColumnWidth(6, 92)
        self._view.setColumnWidth(7, 220)
        layout.addWidget(self._view, 1)

        self._probe_note = QLabel("占用探测尚未运行。")
        self._probe_note.setWordWrap(True)
        self._probe_note.setStyleSheet("color: palette(dark); font-size: 11px;")
        layout.addWidget(self._probe_note)

    # ------------------------------------------------------------- 对外 API
    def set_result(self, result: ProcessScanResult | None) -> None:
        self._result = result
        if result is None or result.temp is None:
            self._entries = []
            self._root_combo.blockSignals(True)
            self._root_combo.clear()
            self._root_combo.addItem("全部扫描根", "")
            self._root_combo.blockSignals(False)
            self._root_table.setRowCount(0)
            self._model.set_entries([])
            self._kpi.reset()
            self._hint.setText(
                "尚未扫描：点击“重新扫描”生成一次完整只读检查（进程 + 网络 + 临时占用）。"
            )
            self._probe_note.setText("占用探测尚未运行。")
            self._refresh_export_state()
            self._update_selection_state()
            return
        temp = result.temp
        self._entries = list(temp.entries)
        self._root_combo.blockSignals(True)
        self._root_combo.clear()
        self._root_combo.addItem("全部扫描根", "")
        for root in temp.roots:
            if root.exists:
                self._root_combo.addItem(root.path, root.path)
        self._root_combo.blockSignals(False)

        self._root_table.setRowCount(len(temp.roots))
        for row, root in enumerate(temp.roots):
            values = [
                root.path,
                "临时" if root.kind == "temp" else "缓存",
                "存在" if root.exists else "不存在",
                human_bytes(temp.size_for_root(root.path)),
                str(temp.files_for_root(root.path)),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column >= 3:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self._root_table.setItem(row, column, item)

        locked = sum(1 for entry in self._entries if entry.occupancy is Occupancy.LOCKED)
        self._kpi.set_value("total", human_bytes(temp.total_size))
        self._kpi.set_value("files", str(temp.total_files))
        self._kpi.set_value("locked", str(locked), "danger" if locked else "good")
        self._kpi.set_value("roots", str(sum(1 for root in temp.roots if root.exists)))
        self._kpi.set_value(
            "completeness",
            completeness_label(temp.completeness),
            "good" if temp.completeness is Completeness.FULL else "warn",
        )
        self._hint.setText(
            "口径：目录大小 = 文件逻辑大小之和（与资源管理器“占用空间”可能不同）。"
            "勾选文件后可“删除选中项（回收站）”：需二次确认，失败不会改为永久删除。"
        )
        self._probe_note.setText(temp.probe_note)
        self._apply_filter()
        self._refresh_export_state()
        self._update_selection_state()

    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._btn_refresh.setEnabled(not busy and not self._action_running)
        self._btn_open.setEnabled(not busy and not self._action_running)
        self._refresh_export_state()
        self._update_selection_state()

    def clear(self) -> None:
        self.set_result(None)

    def is_action_running(self) -> bool:
        return self._action_running

    def cancel_action(self) -> None:
        if self._action_running:
            self._action_runner.cancel()

    def wait_action(self, msecs: int = 3000) -> bool:
        return self._action_runner.wait(msecs)

    # ------------------------------------------------------------- 选择状态
    def _stage2_policy(self) -> ActionPolicy:
        return ActionPolicy.from_config(self._config)

    def _delete_enabled(self) -> bool:
        policy = self._stage2_policy()
        return policy.stage2_enabled and policy.allow_delete_temp

    def _update_selection_state(self) -> None:
        count = self._model.checked_count
        size = self._model.checked_bytes
        if count:
            self._selection_label.setText(f"已选 {count} 项，共 {human_bytes(size)}")
        else:
            self._selection_label.setText("未选择目标（勾选“选择”列后可删除到回收站）")
        enabled = (
            count > 0
            and self._result is not None
            and not self._busy
            and not self._action_running
            and self._delete_enabled()
        )
        self._btn_delete.setEnabled(enabled)
        self._btn_clear_selection.setEnabled(count > 0 and not self._action_running)
        self._btn_preview.setEnabled(
            count > 0
            and self._result is not None
            and not self._busy
            and not self._action_running
        )
        self._btn_preview.setToolTip(
            "预演：只做策略校验并列出将会处理的目标，不修改任何文件、不写回收站（不执行任何真实动作）"
        )
        if not self._delete_enabled():
            self._btn_delete.setToolTip(
                "删除功能默认关闭：请在 config.json 中设置 stage2_enabled=true 与 allow_delete_temp=true 后重启程序"
            )
        elif count == 0:
            self._btn_delete.setToolTip("请先勾选要删除的文件")
        else:
            self._btn_delete.setToolTip("删除到回收站（需要二次确认；不会永久删除）")

    def _on_select_all(self) -> None:
        self._model.check_all_selectable()
        self._update_selection_state()

    def _on_clear_selection(self) -> None:
        self._model.clear_checks()
        self._update_selection_state()

    def refresh_action_switches(self) -> None:
        """设置页一键关闭执行层开关后刷新按钮状态。"""

        self._update_selection_state()

    def _start_preview(self) -> None:
        """阶段 3A 预演：只做策略校验，不执行任何真实动作（不写回收站）。"""

        if self._action_running or self._result is None or self._result.temp is None:
            return
        entries = self._model.checked_entries()
        if not entries:
            QMessageBox.information(self, "未选择目标", "请先勾选要预演的文件。")
            return
        temp = self._result.temp
        verdict = temp_scan_verdict(temp, is_admin=self._is_admin)
        preview_policy = replace(
            ActionPolicy.from_config(self._config),
            stage2_enabled=True,
            allow_delete_temp=True,
        )
        targets, decision, token = build_delete_preview(
            entries,
            temp.roots,
            policy=preview_policy,
            verdict=verdict,
            now=time.time(),
            token_id=uuid.uuid4().hex,
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "预演被拒绝", preview_refusal_text(decision))
            return
        session, error = run_preview_job(
            kind=ActionKind.DELETE_TEMP,
            token=token,
            targets=targets,
            allowed_indices=decision.allowed_indices,
            verdict=verdict,
            is_admin=self._is_admin,
            app_version=self._app_version,
            audit_directory=self._audit_dir,
            config=self._config,
            config_path=self._config_save_path,
        )
        if session is None:
            QMessageBox.critical(self, "预演失败", error)
            return
        QMessageBox.information(self, "预演完成", preview_result_text(session, ActionKind.DELETE_TEMP))
        self._hint.setText("预演完成：未修改任何内容；可继续执行真实删除（需开关开启 + 二次确认）。")
        self._update_selection_state()

    # ------------------------------------------------------------- 执行删除
    def _start_delete(self) -> None:
        if self._action_running or self._result is None or self._result.temp is None:
            return
        if not self._delete_enabled():
            QMessageBox.warning(
                self,
                "删除功能未开启",
                "执行层默认关闭。请先修改配置后重启程序：\n"
                f"{config_path()}\n\n"
                '设置 "stage2_enabled": true 与 "allow_delete_temp": true。',
            )
            return
        entries = self._model.checked_entries()
        if not entries:
            QMessageBox.information(self, "未选择目标", "请先勾选要删除的文件。")
            return
        if not ensure_first_preview(self, ActionKind.DELETE_TEMP, self._config):
            return
        temp = self._result.temp
        policy = self._stage2_policy()
        verdict: CompletenessVerdict = temp_scan_verdict(temp, is_admin=self._is_admin)
        now = time.time()
        targets, decision, token = build_delete_preview(
            entries,
            temp.roots,
            policy=policy,
            verdict=verdict,
            now=now,
            token_id=uuid.uuid4().hex,
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "策略拒绝", preview_refusal_text(decision))
            return

        allowed_targets = [targets[index] for index in decision.allowed_indices]
        total_bytes = sum(target.size for target in allowed_targets)
        preview_items = [
            f"{target.path}（{human_bytes(target.size)}）" for target in allowed_targets[:100]
        ]
        if len(allowed_targets) > 100:
            preview_items.append(f"... 其余 {len(allowed_targets) - 100} 项略")
        dialog = ConfirmActionDialog(
            title="确认删除到回收站",
            action_summary=f"将把 {len(allowed_targets)} 个文件（{human_bytes(total_bytes)}）移动到回收站",
            consequence=(
                "删除后可在回收站手动还原；回收站不可用的文件会失败，"
                "程序不会改为永久删除。执行前会再次校验文件身份。"
            ),
            items=preview_items,
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        job = ActionJob(
            action=ActionKind.DELETE_TEMP,
            token=token,
            targets=targets,
            allowed_indices=decision.allowed_indices,
            executor=DeleteTempExecutor(Send2TrashBackend()),
            audit=ActionAuditWriter(self._audit_dir),
            verdict=verdict,
            is_admin=self._is_admin,
            app_version=self._app_version,
            dry_run=False,
            clock=time.time,
        )
        job.progress.connect(self._on_action_progress)
        job.finished.connect(self._on_action_finished)
        job.failed.connect(self._on_action_failed)
        job.cancelled.connect(self._on_action_cancelled)
        self._action_running = True
        self._hint.setText(f"正在执行删除：0 / {len(allowed_targets)} …")
        self._update_selection_state()
        if not self._action_runner.start(job):
            self._action_running = False
            self._hint.setText("已有动作任务在运行")
            self._update_selection_state()

    def _on_action_progress(self, percent: int, text: str) -> None:
        self._hint.setText(f"正在执行删除：{text}")

    def _on_action_finished(self, session: ActionSessionResult) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._model.clear_checks()
        self._hint.setText(
            f"删除完成：成功 {session.success_count} 项，失败 {session.failed_count} 项；"
            "列表为扫描时快照，建议重新扫描刷新。"
        )
        self._update_selection_state()
        detail_lines = [
            f"{item.result}: {item.target}"
            + (f"（{item.error_code}）" if item.error_code else "")
            for item in session.results
        ]
        QMessageBox.information(
            self,
            "删除完成",
            f"成功 {session.success_count} 项，失败 {session.failed_count} 项。\n\n"
            "失败项未做任何永久删除；详情已写入审计日志。\n\n" + "\n".join(detail_lines[:50]),
        )
        self.status_message.emit(
            f"删除完成：成功 {session.success_count} 项，失败 {session.failed_count} 项"
        )

    def _on_action_failed(self, message: str) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._hint.setText(f"删除失败：{message}")
        self._update_selection_state()
        self.status_message.emit("删除失败，详见日志")
        QMessageBox.critical(self, "删除失败", f"{message}\n\n审计日志目录：{log_dir()}")

    def _on_action_cancelled(self) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._hint.setText("删除已取消（已执行的项目见审计日志）")
        self._update_selection_state()
        self.status_message.emit("删除已取消")

    def _on_action_runner_finished(self) -> None:
        if not self._action_running:
            self._update_selection_state()

    # ------------------------------------------------------------- 过滤/动作
    def _refresh_export_state(self) -> None:
        self._btn_export.setEnabled(not self._busy and not self._action_running and self._result is not None)

    def _apply_filter(self) -> None:
        root = str(self._root_combo.currentData() or "")
        search = self._search_edit.text().strip().casefold()
        filtered: list[TempEntry] = []
        for entry in self._entries:
            if root and entry.root != root:
                continue
            if search:
                haystack = f"{entry.path} {entry.root} {occupancy_label(entry.occupancy)}".casefold()
                if search not in haystack:
                    continue
            filtered.append(entry)
        self._model.set_entries(filtered)
        self._update_selection_state()

    def _open_selected(self) -> None:
        entry = self._model.entry_at(self._view.currentIndex())
        target = entry.path if entry is not None else None
        if target is None and self._result is not None and self._result.temp is not None:
            for root in self._result.temp.roots:
                if root.exists:
                    target = root.path
                    break
        if not target:
            QMessageBox.information(self, "无临时目录", "未找到可打开的临时目录。")
            return
        if entry is not None and entry.is_dir:
            path = target
        else:
            path = os.path.dirname(target)
        ok, error = open_containing_folder(path)
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    def export_csv(self) -> None:
        if self._result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次扫描再导出。")
            return
        try:
            export_dir = default_export_dir()
            export_dir.mkdir(parents=True, exist_ok=True)
            suggested = str(export_dir / f"临时文件占用_{now_text()}.csv")
        except OSError:
            suggested = f"临时文件占用_{now_text()}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "导出临时占用 CSV", suggested, "CSV 文件 (*.csv)")
        if not path:
            return
        if not path.casefold().endswith(".csv"):
            path += ".csv"
        ok, message = export_temp_csv(path, self._result)
        if ok:
            self.status_message.emit(f"已导出临时占用：{path}")
            QMessageBox.information(self, "导出成功", f"{message}\n\n文件：{path}")
        else:
            QMessageBox.critical(self, "导出失败", message)
