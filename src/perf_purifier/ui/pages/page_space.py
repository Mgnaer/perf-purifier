"""磁盘空间页（模块 C）：空间盘点 + 垃圾规则清理。

安全边界（与临时占用页/重复文件页一致）：
* 默认只读：进入页面只显示提示，扫描需用户点击；
* 清理受 ``stage2_enabled`` + ``allow_clean_space`` 双开关控制，默认关闭；
* 必须勾选规则 + 策略判定 + 首次预演 + 二次确认对话框；默认不勾选谨慎/系统级；
* 只调用注入的回收站后端（send2trash），失败仅报告，绝不永久删除；
* 执行前重验目标身份（存在/大小/修改时间/reparse/受保护路径/用户数据目录）；
* 审计日志由 ActionJob 写入 ``operations.jsonl``。
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ...core.action_policy import ActionKind, ActionPolicy
from ...core.audit import ActionAuditWriter, rotate_audit_log
from ...core.config import AppConfig, config_path, default_export_dir, log_dir
from ...core.fmt import human_bytes, human_duration_ms, now_text, percent_text
from ...core.models import completeness_label
from ...core.shell import open_containing_folder
from ...core.trash import Send2TrashBackend
from ...jobs.action_job import ActionJob, ActionSessionResult
from ...jobs.base_job import JobRunner
from ...jobs.space_job import SpaceScanJob
from ...module_c.executor import SlimDeleteExecutor
from ...module_c.models import RISK_CAUTION, RISK_SAFE, RISK_SYSTEM, SpaceScanResult
from ...module_c.policy import build_slim_preview, refusal_text
from ...module_c.report import export_junk_csv, export_space_json
from ...module_c.scanner import list_drives, resolve_drive_root, system_drive
from ..action_preview import ensure_first_preview, preview_result_text, run_preview_job
from ..dialogs.confirm_action_dialog import ConfirmActionDialog
from ..models.space_models import JunkRuleTableModel, OverviewTableModel, SpaceLargeFileTableModel

logger = logging.getLogger(__name__)

_MIN_SIZE_CHOICES: tuple[tuple[str, int], ...] = (
    ("50 MB", 50 * 1024**2),
    ("100 MB", 100 * 1024**2),
    ("500 MB", 500 * 1024**2),
    ("1 GB", 1024**3),
)


class SpacePage(QWidget):
    """模块 C 页面：磁盘占用概览 + 垃圾规则清理。"""

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
        self._result: SpaceScanResult | None = None
        self._busy = False
        self._action_running = False
        self._scan_runner = JobRunner(self)
        self._scan_runner.finished.connect(self._on_scan_runner_finished)
        self._action_runner = JobRunner(self)
        self._action_runner.finished.connect(self._on_action_runner_finished)
        self._build_ui()
        self._update_action_state()
        self._update_export_state()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self._drive_combo = QComboBox()
        self._drive_combo.setMinimumWidth(250)
        self._btn_scan = QPushButton("开始扫描")
        self._btn_scan.clicked.connect(self.start_scan)
        self._chk_caution = QCheckBox("包含谨慎级")
        self._chk_caution.setToolTip(
            "谨慎级：游戏着色器缓存、缩略图缓存、厂商驱动安装包备份等"
            "（会重新生成或需人工判断，默认不勾选）"
        )
        self._chk_caution.setChecked(bool(getattr(self._config, "slim_include_caution", False)))
        self._chk_system = QCheckBox("包含系统级")
        self._chk_system.setToolTip(
            "系统级：Windows 更新缓存、旧 LCU、MRT、系统日志、内存转储、Defender 旧平台。"
            "需要管理员权限，普通用户运行时会自动跳过。"
        )
        self._chk_system.setChecked(
            bool(getattr(self._config, "slim_include_system", False)) and is_admin_ok(self._is_admin)
        )
        self._chk_system.setEnabled(is_admin_ok(self._is_admin))
        if not is_admin_ok(self._is_admin):
            self._chk_system.setCheckable(True)
            self._chk_system.setText("包含系统级（需管理员）")
        self._size_combo = QComboBox()
        for label, value in _MIN_SIZE_CHOICES:
            self._size_combo.addItem(f"大文件 ≥ {label}", value)
        self._size_combo.setCurrentIndex(1)
        self._btn_export_csv = QPushButton("导出垃圾 CSV")
        self._btn_export_csv.clicked.connect(self.export_junk_csv)
        self._btn_export_json = QPushButton("导出完整 JSON")
        self._btn_export_json.clicked.connect(self.export_json)

        toolbar.addWidget(QLabel("磁盘："))
        toolbar.addWidget(self._drive_combo)
        toolbar.addWidget(self._btn_scan)
        toolbar.addSpacing(8)
        toolbar.addWidget(self._chk_caution)
        toolbar.addWidget(self._chk_system)
        toolbar.addSpacing(8)
        toolbar.addWidget(self._size_combo)
        toolbar.addStretch(1)
        toolbar.addWidget(self._btn_export_csv)
        toolbar.addWidget(self._btn_export_json)
        layout.addLayout(toolbar)

        status_row = QHBoxLayout()
        status_row.setSpacing(6)
        self._hint = QLabel(
            "尚未扫描：点击「开始扫描」生成一次只读检查（空间概览 + 垃圾规则 + 大文件排行）。"
            "本页不会自动删除任何内容。"
        )
        self._hint.setWordWrap(True)
        self._hint.setStyleSheet("color: palette(dark); font-size: 11px;")
        self._scan_progress = QProgressBar()
        self._scan_progress.setRange(0, 100)
        self._scan_progress.setValue(0)
        self._scan_progress.setTextVisible(False)
        self._scan_progress.setFixedWidth(160)
        self._scan_progress.setFixedHeight(10)
        self._scan_progress.setVisible(False)
        status_row.addWidget(self._hint, 1)
        status_row.addWidget(self._scan_progress)
        layout.addLayout(status_row)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter, 1)

        # ---------------------------------------------------------- 概览
        overview_box = QWidget()
        overview_layout = QVBoxLayout(overview_box)
        overview_layout.setContentsMargins(0, 0, 0, 0)
        overview_layout.setSpacing(4)
        usage_row = QHBoxLayout()
        self._usage_label = QLabel("磁盘占用：—")
        usage_font = self._usage_label.font()
        usage_font.setBold(True)
        self._usage_label.setFont(usage_font)
        self._usage_bar = QProgressBar()
        self._usage_bar.setRange(0, 1000)
        self._usage_bar.setValue(0)
        self._usage_bar.setTextVisible(False)
        self._usage_bar.setFixedHeight(12)
        usage_row.addWidget(self._usage_label)
        usage_row.addWidget(self._usage_bar, 1)
        overview_layout.addLayout(usage_row)
        self._overview_model = OverviewTableModel(self)
        self._overview_view = QTableView()
        self._overview_view.setModel(self._overview_model)
        self._overview_view.setAlternatingRowColors(True)
        self._overview_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._overview_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._overview_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._overview_view.setWordWrap(False)
        self._overview_view.doubleClicked.connect(self._open_overview_selected)
        overview_header = self._overview_view.horizontalHeader()
        overview_header.setStretchLastSection(False)
        overview_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, 5):
            overview_header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        overview_layout.addWidget(self._overview_view, 1)
        splitter.addWidget(overview_box)

        # ---------------------------------------------------------- 垃圾规则
        junk_box = QWidget()
        junk_layout = QVBoxLayout(junk_box)
        junk_layout.setContentsMargins(0, 0, 0, 0)
        junk_layout.setSpacing(4)
        junk_row = QHBoxLayout()
        self._junk_label = QLabel("可清理垃圾：尚未扫描")
        junk_font = self._junk_label.font()
        junk_font.setBold(True)
        self._junk_label.setFont(junk_font)
        self._btn_select_safe = QPushButton("全选安全级")
        self._btn_select_safe.clicked.connect(lambda: self._select_by_risk({RISK_SAFE}))
        self._btn_select_all = QPushButton("全选可清理")
        self._btn_select_all.clicked.connect(self._select_all)
        self._btn_clear = QPushButton("清空选择")
        self._btn_clear.clicked.connect(self._clear_selection)
        self._selection_label = QLabel("未选择目标")
        self._selection_label.setStyleSheet("color: palette(dark);")
        junk_row.addWidget(self._junk_label)
        junk_row.addStretch(1)
        junk_row.addWidget(self._selection_label)
        junk_row.addWidget(self._btn_select_safe)
        junk_row.addWidget(self._btn_select_all)
        junk_row.addWidget(self._btn_clear)
        junk_layout.addLayout(junk_row)

        self._junk_model = JunkRuleTableModel(self)
        self._junk_model.dataChanged.connect(lambda *_args: self._update_action_state())
        self._junk_view = QTableView()
        self._junk_view.setModel(self._junk_model)
        self._junk_view.setAlternatingRowColors(True)
        self._junk_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._junk_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._junk_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._junk_view.setWordWrap(False)
        junk_header = self._junk_view.horizontalHeader()
        junk_header.setStretchLastSection(True)
        junk_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._junk_view.setColumnWidth(0, 48)
        self._junk_view.setColumnWidth(1, 130)
        self._junk_view.setColumnWidth(2, 220)
        self._junk_view.setColumnWidth(3, 56)
        self._junk_view.setColumnWidth(4, 62)
        self._junk_view.setColumnWidth(5, 90)
        junk_layout.addWidget(self._junk_view, 1)

        action_row = QHBoxLayout()
        action_row.setSpacing(6)
        self._btn_preview = QPushButton("预演选中项（不执行）")
        self._btn_preview.clicked.connect(self._start_preview)
        self._btn_clean = QPushButton("清理选中项（回收站）")
        self._btn_clean.clicked.connect(self._start_clean)
        self._btn_empty_trash = QPushButton("清空回收站…")
        self._btn_empty_trash.clicked.connect(self._start_empty_recycle_bin)
        self._action_hint = QLabel("")
        self._action_hint.setWordWrap(True)
        self._action_hint.setStyleSheet("color: palette(dark); font-size: 11px;")
        action_row.addWidget(self._btn_empty_trash)
        action_row.addStretch(1)
        action_row.addWidget(self._btn_preview)
        action_row.addWidget(self._btn_clean)
        junk_layout.addLayout(action_row)
        junk_layout.addWidget(self._action_hint)
        splitter.addWidget(junk_box)

        # ---------------------------------------------------------- 大文件
        large_box = QWidget()
        large_layout = QVBoxLayout(large_box)
        large_layout.setContentsMargins(0, 0, 0, 0)
        large_layout.setSpacing(4)
        large_row = QHBoxLayout()
        self._large_label = QLabel("最大文件排行：尚未扫描")
        self._btn_open_large = QPushButton("打开所在目录")
        self._btn_open_large.clicked.connect(self._open_large_selected)
        large_row.addWidget(self._large_label)
        large_row.addStretch(1)
        large_row.addWidget(self._btn_open_large)
        large_layout.addLayout(large_row)
        self._large_model = SpaceLargeFileTableModel(self)
        self._large_view = QTableView()
        self._large_view.setModel(self._large_model)
        self._large_view.setAlternatingRowColors(True)
        self._large_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._large_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._large_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._large_view.setWordWrap(False)
        self._large_view.doubleClicked.connect(lambda _index: self._open_large_selected())
        large_header = self._large_view.horizontalHeader()
        large_header.setStretchLastSection(True)
        large_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._large_view.setColumnWidth(0, 90)
        self._large_view.setColumnWidth(1, 130)
        large_layout.addWidget(self._large_view, 1)
        splitter.addWidget(large_box)

        splitter.setSizes([260, 300, 220])
        self._reload_drives()

    # ------------------------------------------------------------------ 盘符
    def _reload_drives(self) -> None:
        current = self._drive_combo.currentData()
        self._drive_combo.blockSignals(True)
        self._drive_combo.clear()
        drives = list_drives(fixed_only=True)
        if not drives:
            self._drive_combo.addItem(f"{system_drive()}（默认）", system_drive())
        for info in drives:
            self._drive_combo.addItem(
                f"{info.letter} {info.type_label} · 可用 {human_bytes(info.free_bytes)}"
                f" / 共 {human_bytes(info.total_bytes)}",
                info.root,
            )
        target = str(current) if current else system_drive()
        index = self._drive_combo.findData(target)
        if index >= 0:
            self._drive_combo.setCurrentIndex(index)
        self._drive_combo.blockSignals(False)

    # ------------------------------------------------------------------ 扫描
    def selected_drive(self) -> str:
        return str(self._drive_combo.currentData() or system_drive())

    def start_scan(self) -> None:
        if self._busy or self._action_running or self._scan_runner.is_running():
            return
        drive = resolve_drive_root(self.selected_drive()) or system_drive()
        include_caution = self._chk_caution.isChecked()
        include_system = self._chk_system.isChecked() and self._is_admin
        if include_system and not self._is_admin:
            include_system = False
        # 记住扫描范围偏好（失败不影响扫描）
        self._config.slim_include_caution = bool(include_caution)
        self._config.slim_include_system = bool(include_system)
        saved, _message = self._config.save()
        if not saved:
            logger.debug("磁盘空间页：扫描偏好保存失败（忽略）")

        job = SpaceScanJob(
            config=self._config,
            is_admin=self._is_admin,
            drive=drive,
            include_caution=include_caution,
            include_system=include_system,
            top_files=int(getattr(self._config, "slim_large_file_limit", 20)),
            min_file_size=int(self._size_combo.currentData() or 0),
        )
        job.progress.connect(self._on_scan_progress)
        job.stage_changed.connect(lambda text: self._hint.setText(text))
        job.warning.connect(self._on_scan_warning)
        job.finished.connect(self._on_scan_finished)
        job.failed.connect(self._on_scan_failed)
        job.cancelled.connect(self._on_scan_cancelled)
        self._set_busy(True)
        self._hint.setText("正在扫描：空间盘点 + 垃圾规则（只读，不会修改任何文件）…")
        if not self._scan_runner.start(job):
            self._set_busy(False)
            self._hint.setText("已有扫描任务在运行")

    def is_scanning(self) -> bool:
        return self._scan_runner.is_running()

    def cancel_scan(self) -> None:
        if self._scan_runner.is_running():
            self._scan_runner.cancel()

    def wait_scan(self, msecs: int = 3000) -> bool:
        return self._scan_runner.wait(msecs)

    def _on_scan_progress(self, percent: int, text: str) -> None:
        self._scan_progress.setVisible(True)
        self._scan_progress.setValue(max(0, min(100, percent)))
        if text:
            self._hint.setText(f"正在扫描（{percent}%）：{text}")

    def _on_scan_warning(self, warning: object) -> None:
        message = getattr(warning, "message", str(warning))
        logger.info("磁盘空间扫描提示：%s", message)
        self.status_message.emit(f"扫描提示：{message}")

    def _on_scan_finished(self, result: SpaceScanResult) -> None:
        self._scan_progress.setVisible(False)
        self._set_busy(False)
        self.set_result(result)
        self.status_message.emit(
            f"磁盘空间扫描完成：垃圾 {human_bytes(result.junk_total_size)}，"
            f"用时 {human_duration_ms(result.elapsed_ms)}"
        )

    def _on_scan_failed(self, message: str) -> None:
        self._scan_progress.setVisible(False)
        self._set_busy(False)
        self._hint.setText(f"扫描失败：{message}")
        QMessageBox.critical(self, "扫描失败", f"{message}\n\n日志目录：{log_dir()}")

    def _on_scan_cancelled(self) -> None:
        self._scan_progress.setVisible(False)
        self._set_busy(False)
        self._hint.setText("扫描已取消（未修改任何文件）")
        self.status_message.emit("磁盘空间扫描已取消")

    def _on_scan_runner_finished(self) -> None:
        if not self._busy:
            self._update_action_state()

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._btn_scan.setEnabled(not busy and not self._action_running)
        self._drive_combo.setEnabled(not busy and not self._action_running)
        self._chk_caution.setEnabled(not busy and not self._action_running)
        self._chk_system.setEnabled(
            is_admin_ok(self._is_admin) and not busy and not self._action_running
        )
        self._size_combo.setEnabled(not busy and not self._action_running)
        self._update_export_state()
        self._update_action_state()

    # ------------------------------------------------------------------ 结果
    def set_result(self, result: SpaceScanResult | None) -> None:
        """把扫描结果灌入界面（测试可直接注入合成结果）。"""

        self._result = result
        if result is None:
            self._usage_label.setText("磁盘占用：—")
            self._usage_bar.setValue(0)
            self._overview_model.set_entries([])
            self._junk_model.set_results([])
            self._large_model.set_files([])
            self._junk_label.setText("可清理垃圾：尚未扫描")
            self._large_label.setText("最大文件排行：尚未扫描")
            self._hint.setText(
                "尚未扫描：点击「开始扫描」生成一次只读检查（空间概览 + 垃圾规则 + 大文件排行）。"
                "本页不会自动删除任何内容。"
            )
            self._update_export_state()
            self._update_action_state()
            return

        used = result.used_bytes
        self._usage_label.setText(
            f"{result.drive}  已用 {human_bytes(used)} / 共 {human_bytes(result.total_bytes)}"
            f"（可用 {human_bytes(result.free_bytes)}，已用率 {percent_text(used, result.total_bytes)}）"
        )
        ratio = (used / result.total_bytes) if result.total_bytes > 0 else 0.0
        self._usage_bar.setValue(int(round(ratio * 1000)))
        self._overview_model.set_entries(result.overview_entries, used_bytes=used)
        self._large_model.set_files(result.top_files)

        checked_risks = {RISK_SAFE}
        if result.include_caution:
            checked_risks.add(RISK_CAUTION)
        if result.include_system and self._is_admin:
            checked_risks.add(RISK_SYSTEM)
        self._junk_model.set_results(result.junk_results, default_checked_risks=checked_risks)

        sizes = result.sizes_by_risk()
        self._junk_label.setText(
            f"可清理垃圾：{human_bytes(result.junk_total_size)}"
            f"（安全 {human_bytes(sizes[RISK_SAFE])} · 谨慎 {human_bytes(sizes[RISK_CAUTION])}"
            f" · 系统 {human_bytes(sizes[RISK_SYSTEM])}）"
        )
        self._large_label.setText(f"最大文件排行（Top {len(result.top_files)}）")
        warnings = "；".join(warning.message for warning in result.warnings[:2])
        self._hint.setText(
            f"扫描完成：{result.drive} 共 {result.files_scanned:,} 个文件，"
            f"垃圾可清理 {human_bytes(result.junk_total_size)}，"
            f"数据完整度 {completeness_label(result.completeness)}，"
            f"用时 {human_duration_ms(result.elapsed_ms)}。"
            + (f"　提示：{warnings}" if warnings else "")
        )
        self._update_export_state()
        self._update_action_state()

    # ------------------------------------------------------------------ 选择
    def _select_by_risk(self, risks: set[str]) -> None:
        self._junk_model.check_all_of_risks(risks)
        self._update_action_state()

    def _select_all(self) -> None:
        allowed = {RISK_SAFE}
        if self._chk_caution.isChecked():
            allowed.add(RISK_CAUTION)
        if self._chk_system.isChecked() and self._is_admin:
            allowed.add(RISK_SYSTEM)
        self._junk_model.check_all_of_risks(allowed)
        self._update_action_state()

    def _clear_selection(self) -> None:
        self._junk_model.clear_checks()
        self._update_action_state()

    def checked_items(self) -> list:
        items = []
        for result in self._junk_model.checked_results():
            items.extend(result.items)
        return items

    # ------------------------------------------------------------------ 动作
    def _policy(self) -> ActionPolicy:
        return ActionPolicy.from_config(self._config)

    def _clean_enabled(self) -> bool:
        policy = self._policy()
        return policy.stage2_enabled and policy.allow_clean_space

    def _update_export_state(self) -> None:
        ready = self._result is not None and not self._busy and not self._action_running
        self._btn_export_csv.setEnabled(ready)
        self._btn_export_json.setEnabled(ready)

    def _update_action_state(self) -> None:
        count = self._junk_model.checked_count()
        size = self._junk_model.checked_bytes()
        if count:
            self._selection_label.setText(f"已选 {count} 项，共 {human_bytes(size)}")
        else:
            self._selection_label.setText("未选择目标（在「选择」列勾选规则）")

        base_ready = (
            self._result is not None
            and not self._busy
            and not self._action_running
        )
        self._btn_select_safe.setEnabled(base_ready)
        self._btn_select_all.setEnabled(base_ready)
        self._btn_clear.setEnabled(base_ready and count > 0)
        self._btn_preview.setEnabled(base_ready and count > 0)
        self._btn_preview.setToolTip(
            "预演：只做策略校验并列出将会处理的目标，不修改任何文件、不写回收站（不执行任何真实动作）"
        )
        self._btn_clean.setEnabled(base_ready and count > 0 and self._clean_enabled())
        if not self._clean_enabled():
            self._btn_clean.setToolTip(
                "清理功能默认关闭：请在 config.json 中设置 stage2_enabled=true 与 "
                "allow_clean_space=true 后重启程序"
            )
        elif count == 0:
            self._btn_clean.setToolTip("请先在「选择」列勾选要清理的规则")
        else:
            self._btn_clean.setToolTip("移动到回收站（需要二次确认；不会永久删除）")

        recycle_item = self._recycle_bin_item()
        self._btn_empty_trash.setEnabled(
            base_ready and recycle_item is not None and self._clean_enabled()
        )
        if recycle_item is None:
            self._btn_empty_trash.setToolTip("当前回收站为空")
        elif not self._clean_enabled():
            self._btn_empty_trash.setToolTip("清空回收站属于执行层动作，需先开启开关")
        else:
            self._btn_empty_trash.setToolTip("清空 C 盘回收站（含此前删除的其他文件，需输入确认词）")

        if base_ready and not self._clean_enabled():
            self._action_hint.setText(
                "执行层默认关闭（安全默认）：如需清理，请手工编辑配置文件后重启程序："
                f"{config_path()}"
            )
        elif self._action_running:
            self._action_hint.setText("动作执行中…")
        else:
            self._action_hint.setText(
                "清理只把文件移动到回收站（可在回收站还原），失败不会改为永久删除；"
                "执行前会再次校验目标身份。"
            )

    def refresh_action_switches(self) -> None:
        """设置页一键关闭执行层开关后刷新按钮状态。"""

        self._update_action_state()

    def _recycle_bin_item(self):
        if self._result is None:
            return None
        for result in self._result.junk_results:
            if result.rule.id == "recycle_bin" and result.items:
                return result.items[0]
        return None

    # ------------------------------------------------------------------ 预演
    def _start_preview(self) -> None:
        if self._result is None or self._action_running:
            return
        items = self.checked_items()
        if not items:
            QMessageBox.information(self, "未选择目标", "请先在「选择」列勾选要预演的规则。")
            return
        verdict = self._result.verdict
        preview_policy = replace(
            self._policy(), stage2_enabled=True, allow_clean_space=True
        )
        targets, decision, token = build_slim_preview(
            items,
            policy=preview_policy,
            verdict=verdict,
            is_admin=self._is_admin,
            now=time.time(),
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "预演被拒绝", refusal_text(decision))
            return
        session, error = run_preview_job(
            kind=ActionKind.CLEAN_SPACE,
            token=token,
            targets=items,
            allowed_indices=decision.allowed_indices,
            verdict=verdict,
            is_admin=self._is_admin,
            app_version=self._app_version,
            audit_directory=self._audit_dir,
            config=self._config,
        )
        if session is None:
            QMessageBox.critical(self, "预演失败", error)
            return
        QMessageBox.information(self, "预演完成", preview_result_text(session, ActionKind.CLEAN_SPACE))
        self._hint.setText("预演完成：未修改任何内容；可继续执行真实清理（需开关开启 + 二次确认）。")
        self._update_action_state()

    # ------------------------------------------------------------------ 清理
    def _start_clean(self) -> None:
        if self._action_running or self._result is None:
            return
        if not self._clean_enabled():
            QMessageBox.warning(
                self,
                "清理功能未开启",
                "执行层默认关闭。请先修改配置后重启程序：\n"
                f"{config_path()}\n\n"
                '设置 "stage2_enabled": true 与 "allow_clean_space": true。',
            )
            return
        items = self.checked_items()
        if not items:
            QMessageBox.information(self, "未选择目标", "请先在「选择」列勾选要清理的规则。")
            return
        if not ensure_first_preview(self, ActionKind.CLEAN_SPACE, self._config):
            return
        policy = self._policy()
        verdict = self._result.verdict
        targets, decision, token = build_slim_preview(
            items,
            policy=policy,
            verdict=verdict,
            is_admin=self._is_admin,
            now=time.time(),
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "策略拒绝", refusal_text(decision))
            return
        allowed_items = [items[index] for index in decision.allowed_indices]
        total_bytes = sum(item.size_bytes for item in allowed_items)
        preview_lines = [
            f"{item.path}（{human_bytes(item.size_bytes)}）" for item in allowed_items[:100]
        ]
        if len(allowed_items) > 100:
            preview_lines.append(f"... 其余 {len(allowed_items) - 100} 项略")
        dialog = ConfirmActionDialog(
            title="确认清理磁盘垃圾",
            action_summary=(
                f"将把 {len(allowed_items)} 项（{human_bytes(total_bytes)}）移动到回收站"
            ),
            consequence=(
                "清理后可在回收站手动还原；回收站不可用的文件会失败，"
                "程序不会改为永久删除。执行前会再次校验每一项身份。"
            ),
            items=preview_lines,
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        job = ActionJob(
            action=ActionKind.CLEAN_SPACE,
            token=token,
            targets=items,
            allowed_indices=decision.allowed_indices,
            executor=SlimDeleteExecutor(
                Send2TrashBackend(),
                is_admin=self._is_admin,
                drive=self._result.drive or system_drive(),
            ),
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
        self._hint.setText(f"正在清理：0 / {len(allowed_items)} …")
        self._update_action_state()
        if not self._action_runner.start(job):
            self._action_running = False
            self._hint.setText("已有动作任务在运行")
            self._update_action_state()

    # ------------------------------------------------------------------ 清空回收站
    def _start_empty_recycle_bin(self) -> None:
        if self._action_running or self._result is None:
            return
        item = self._recycle_bin_item()
        if item is None:
            QMessageBox.information(self, "回收站为空", "当前 C 盘回收站没有可清空的内容。")
            return
        if not self._clean_enabled():
            QMessageBox.warning(
                self,
                "清理功能未开启",
                "执行层默认关闭。请先修改配置后重启程序：\n"
                f"{config_path()}\n\n"
                '设置 "stage2_enabled": true 与 "allow_clean_space": true。',
            )
            return
        if not ensure_first_preview(self, ActionKind.CLEAN_SPACE, self._config):
            return
        policy = self._policy()
        verdict = self._result.verdict
        targets, decision, token = build_slim_preview(
            [item], policy=policy, verdict=verdict, is_admin=self._is_admin, now=time.time()
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "策略拒绝", refusal_text(decision))
            return
        dialog = ConfirmActionDialog(
            title="确认清空回收站",
            action_summary=f"将清空 C 盘回收站（{item.file_count:,} 项，{human_bytes(item.size_bytes)}）",
            consequence=(
                "清空后文件不可恢复；回收站中此前删除的**其他文件**也会一并清空。"
                "请确认没有需要找回的内容。"
            ),
            items=[f"回收站：{item.file_count:,} 项 / {human_bytes(item.size_bytes)}"],
            require_typed_phrase="清空回收站",
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        job = ActionJob(
            action=ActionKind.CLEAN_SPACE,
            token=token,
            targets=[item],
            allowed_indices=decision.allowed_indices,
            executor=SlimDeleteExecutor(
                Send2TrashBackend(),
                is_admin=self._is_admin,
                drive=self._result.drive or system_drive(),
            ),
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
        self._hint.setText("正在清空回收站…")
        self._update_action_state()
        if not self._action_runner.start(job):
            self._action_running = False
            self._hint.setText("已有动作任务在运行")
            self._update_action_state()

    # ------------------------------------------------------------------ 动作回调
    def is_action_running(self) -> bool:
        return self._action_running

    def cancel_action(self) -> None:
        if self._action_running:
            self._action_runner.cancel()

    def wait_action(self, msecs: int = 3000) -> bool:
        return self._action_runner.wait(msecs)

    def _on_action_progress(self, percent: int, text: str) -> None:
        self._hint.setText(f"正在执行：{text}")

    def _on_action_finished(self, session: ActionSessionResult) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._junk_model.clear_checks()
        self._hint.setText(
            f"清理完成：成功 {session.success_count} 项，失败 {session.failed_count} 项；"
            "请重新扫描刷新数据。"
        )
        self._update_action_state()
        detail_lines = [
            f"{item.result}: {item.target}" + (f"（{item.error_code}）" if item.error_code else "")
            for item in session.results
        ]
        QMessageBox.information(
            self,
            "清理完成",
            f"成功 {session.success_count} 项，失败 {session.failed_count} 项。\n\n"
            "失败项未做任何永久删除；详情已写入审计日志。\n\n" + "\n".join(detail_lines[:50]),
        )
        self.status_message.emit(
            f"磁盘清理完成：成功 {session.success_count} 项，失败 {session.failed_count} 项"
        )

    def _on_action_failed(self, message: str) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._hint.setText(f"清理失败：{message}")
        self._update_action_state()
        self.status_message.emit("磁盘清理失败，详见日志")
        QMessageBox.critical(self, "清理失败", f"{message}\n\n审计日志目录：{log_dir()}")

    def _on_action_cancelled(self) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._hint.setText("清理已取消（已执行的项目见审计日志）")
        self._update_action_state()
        self.status_message.emit("磁盘清理已取消")

    def _on_action_runner_finished(self) -> None:
        if not self._action_running:
            self._update_action_state()

    # ------------------------------------------------------------------ 打开目录
    def _open_overview_selected(self) -> None:
        entry = self._overview_model.entry_at(self._overview_view.currentIndex())
        if entry is None:
            return
        target = entry.path if entry.is_dir else os.path.dirname(entry.path)
        ok, error = open_containing_folder(target)
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    def _open_large_selected(self) -> None:
        hit = self._large_model.file_at(self._large_view.currentIndex())
        if hit is None:
            QMessageBox.information(self, "未选择", "请先在表格中选择一个文件。")
            return
        ok, error = open_containing_folder(os.path.dirname(hit.path))
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    # ------------------------------------------------------------------ 导出
    def _suggest_path(self, prefix: str, suffix: str) -> str:
        try:
            export_dir = default_export_dir()
            export_dir.mkdir(parents=True, exist_ok=True)
            return str(export_dir / f"{prefix}_{now_text()}{suffix}")
        except OSError:
            return f"{prefix}_{now_text()}{suffix}"

    def export_junk_csv(self) -> None:
        if self._result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次扫描再导出。")
            return
        path, _filter = QFileDialog.getSaveFileName(
            self, "导出垃圾明细 CSV", self._suggest_path("磁盘垃圾", ".csv"), "CSV 文件 (*.csv)"
        )
        if not path:
            return
        if not path.casefold().endswith(".csv"):
            path += ".csv"
        ok, message = export_junk_csv(path, self._result)
        if ok:
            self.status_message.emit(f"已导出垃圾明细 CSV：{path}")
            QMessageBox.information(self, "导出成功", f"{message}\n\n文件：{path}")
        else:
            QMessageBox.critical(self, "导出失败", message)

    def export_json(self) -> None:
        if self._result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次扫描再导出。")
            return
        path, _filter = QFileDialog.getSaveFileName(
            self, "导出完整 JSON", self._suggest_path("磁盘空间", ".json"), "JSON 文件 (*.json)"
        )
        if not path:
            return
        if not path.casefold().endswith(".json"):
            path += ".json"
        ok, message = export_space_json(path, self._result)
        if ok:
            self.status_message.emit(f"已导出完整 JSON：{path}")
            QMessageBox.information(self, "导出成功", f"{message}\n\n文件：{path}")
        else:
            QMessageBox.critical(self, "导出失败", message)


def is_admin_ok(value: bool) -> bool:
    """单独提出来便于测试打桩。"""

    return bool(value)


__all__ = ["SpacePage"]
