"""重复文件页（模块 B · 阶段 1C，只读）。

交互：选择目录 → 开始扫描（后台线程，可取消）→ 重复组/组内文件/双栏对比 → 导出。
**本页没有删除按钮**：删除与硬链接能力属于后续阶段，会配合预览、二次确认与日志。
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
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
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ...core.action_policy import ActionKind, ActionPolicy, policy_refusal_text
from ...core.audit import ActionAuditWriter, rotate_audit_log
from ...core.cancel import CancelToken
from ...core.config import AppConfig, config_path, default_export_dir, log_dir
from ...core.fmt import human_bytes, human_duration_ms, now_text
from ...core.models import (
    Completeness,
    FileScanOptions,
    FileScanResult,
    completeness_label,
)
from ...core.shell import open_containing_folder
from ...jobs.action_job import ActionJob, ActionSessionResult
from ...jobs.base_job import JobRunner
from ...jobs.file_scan_job import FileScanJob
from ...module_b.hardlink_action import (
    HardlinkDetachExecutor,
    HardlinkExecutor,
    build_detach_preview,
    build_hardlink_preview,
    file_scan_verdict,
)
from ...module_b.report import (
    export_duplicate_files_csv,
    export_duplicates_csv,
    export_file_report_html,
    export_file_scan_json,
)
from ...module_b.walker import parse_exclude_patterns
from ..action_preview import ensure_first_preview, preview_result_text, run_preview_job
from ..dialogs.confirm_action_dialog import ConfirmActionDialog
from ..models.file_models import DuplicateFileTableModel, DuplicateGroupTableModel
from ..widgets.busy_overlay import ScanProgressBar
from ..widgets.compare_panel import ComparePanel
from ..widgets.kpi_bar import KpiBar

logger = logging.getLogger(__name__)

_TYPE_FILTERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("全部类型", ()),
    (
        "图片",
        (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".heic", ".raw"),
    ),
    ("视频", (".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v")),
    (
        "文档",
        (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".rtf", ".csv"),
    ),
    ("音频", (".mp3", ".flac", ".wav", ".aac", ".m4a", ".ogg", ".wma")),
    ("压缩包", (".zip", ".7z", ".rar", ".tar", ".gz", ".iso")),
)
_MTIME_FILTERS: tuple[tuple[str, int], ...] = (
    ("修改时间：不限", 0),
    ("最近 7 天", 7),
    ("最近 30 天", 30),
    ("最近 90 天", 90),
    ("最近 1 年", 365),
)


class DuplicatesPage(QWidget):
    status_message = Signal(str)
    result_ready = Signal(bool)
    scan_finished = Signal(object)

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
        self._result: FileScanResult | None = None
        self._warning_count = 0
        self._action_running = False
        self._runner = JobRunner(self)
        self._runner.finished.connect(self._on_runner_finished)
        self._action_runner = JobRunner(self)
        self._action_runner.finished.connect(self._on_action_runner_finished)
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _make_table(self) -> QTableView:
        view = QTableView()
        view.setAlternatingRowColors(True)
        view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        view.setWordWrap(False)
        header = view.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        return view

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        row1 = QHBoxLayout()
        row1.setSpacing(6)
        self._btn_browse = QPushButton("选择目录…")
        self._btn_browse.clicked.connect(self._browse)
        self._root_edit = QLineEdit()
        self._root_edit.setReadOnly(True)
        self._root_edit.setPlaceholderText(r"请选择要扫描的目录（例如 D:\Downloads）")
        self._min_size = QSpinBox()
        self._min_size.setRange(1, 1024 * 1024)
        self._min_size.setValue(1)
        self._min_size.setSuffix(" KB")
        self._min_size.setToolTip("小于该大小的文件不参与重复检测（0 字节文件默认被排除）")
        self._btn_start = QPushButton("开始扫描")
        self._btn_start.setDefault(True)
        self._btn_start.clicked.connect(self.start_scan)
        self._btn_cancel = QPushButton("取消")
        self._btn_cancel.setEnabled(False)
        self._btn_cancel.clicked.connect(self.cancel_scan)

        row1.addWidget(QLabel("目录："))
        row1.addWidget(self._btn_browse)
        row1.addWidget(self._root_edit, 1)
        row1.addSpacing(6)
        row1.addWidget(QLabel("最小文件："))
        row1.addWidget(self._min_size)
        row1.addWidget(self._btn_start)
        row1.addWidget(self._btn_cancel)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(6)
        self._type_combo = QComboBox()
        for label, extensions in _TYPE_FILTERS:
            self._type_combo.addItem(label, extensions)
        self._mtime_combo = QComboBox()
        for label, days in _MTIME_FILTERS:
            self._mtime_combo.addItem(label, days)
        self._exclude_edit = QLineEdit()
        self._exclude_edit.setPlaceholderText(r"排除名称/通配符，逗号分隔（如 node_modules, .git, *.tmp）")
        self._exclude_edit.setText(", ".join(self._config.file_scan_exclude_patterns))
        self._cache_checkbox = QCheckBox("使用哈希缓存（加速再次扫描）")
        self._cache_checkbox.setChecked(bool(self._config.file_scan_cache_enabled))
        self._cache_checkbox.setToolTip(
            "缓存按 (路径, 大小, 修改时间) 复用 SHA256 结果；\n"
            "修改过的文件会自动重新哈希，缓存仅存于本机。"
        )
        row2.addWidget(QLabel("类型："))
        row2.addWidget(self._type_combo)
        row2.addWidget(self._mtime_combo)
        row2.addWidget(QLabel("排除："))
        row2.addWidget(self._exclude_edit, 1)
        row2.addWidget(self._cache_checkbox)
        layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.setSpacing(6)
        hint = QLabel(
            "只读：仅扫描与导出，不删除文件、不建立硬链接；跳过 junction/符号链接、"
            "$Recycle.Bin、System Volume Information 与云占位文件。"
            "“建议保留”只是启发式建议（路径更浅/修改更早），不会自动执行任何操作。"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(dark); font-size: 11px;")
        row3.addWidget(hint, 1)
        self._btn_groups_csv = QPushButton("导出组 CSV")
        self._btn_files_csv = QPushButton("导出明细 CSV")
        self._btn_json = QPushButton("导出 JSON")
        self._btn_html = QPushButton("导出 HTML 报告")
        self._btn_groups_csv.clicked.connect(self.export_groups_csv)
        self._btn_files_csv.clicked.connect(self.export_files_csv)
        self._btn_json.clicked.connect(self.export_json)
        self._btn_html.clicked.connect(self.export_html)
        for button in (self._btn_groups_csv, self._btn_files_csv, self._btn_json, self._btn_html):
            row3.addWidget(button)
            button.setEnabled(False)
        layout.addLayout(row3)

        action_row = QHBoxLayout()
        action_row.setSpacing(6)
        self._group_selection_label = QLabel("未选择重复组")
        self._group_selection_label.setStyleSheet("color: palette(dark);")
        self._btn_clear_groups = QPushButton("清空选择")
        self._btn_clear_groups.clicked.connect(self._on_clear_group_selection)
        self._btn_select_all_groups = QPushButton("全选可处理组")
        self._btn_select_all_groups.clicked.connect(self._on_select_all_groups)
        self._btn_preview = QPushButton("预演选中项（不执行）")
        self._btn_preview.clicked.connect(self._start_preview)
        self._btn_hardlink = QPushButton("硬链接去重（默认关闭）")
        self._btn_hardlink.clicked.connect(self._start_hardlink)
        self._btn_detach_preview = QPushButton("预演独立化（不执行）")
        self._btn_detach_preview.clicked.connect(self._start_detach_preview)
        self._btn_detach = QPushButton("独立化选中文件（默认关闭）")
        self._btn_detach.clicked.connect(self._start_detach)
        action_row.addWidget(self._group_selection_label, 1)
        action_row.addWidget(self._btn_select_all_groups)
        action_row.addWidget(self._btn_clear_groups)
        action_row.addWidget(self._btn_preview)
        action_row.addWidget(self._btn_hardlink)
        action_row.addWidget(self._btn_detach_preview)
        action_row.addWidget(self._btn_detach)
        layout.addLayout(action_row)

        self._progress = ScanProgressBar()
        self._progress.set_idle("就绪：选择目录后点击“开始扫描”（只读）")
        layout.addWidget(self._progress)

        self._kpi = KpiBar(
            [
                ("files", "扫描文件数"),
                ("groups", "重复组"),
                ("dup_files", "重复文件数"),
                ("reclaimable", "可回收估算"),
                ("completeness", "数据完整度"),
            ]
        )
        layout.addWidget(self._kpi)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self._group_model = DuplicateGroupTableModel(self)
        self._group_model.dataChanged.connect(self._update_group_selection_state)
        self._group_view = self._make_table()
        self._group_view.setModel(self._group_model)
        self._group_view.setColumnWidth(0, 40)
        self._group_view.setColumnWidth(1, 52)
        self._group_view.setColumnWidth(2, 56)
        self._group_view.setColumnWidth(3, 88)
        self._group_view.setColumnWidth(4, 124)
        self._group_view.setColumnWidth(5, 150)
        self._group_view.setColumnWidth(6, 240)
        self._group_view.selectionModel().currentChanged.connect(self._on_group_changed)
        splitter.addWidget(self._group_view)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)
        self._file_model = DuplicateFileTableModel(self)
        self._file_view = self._make_table()
        self._file_view.setModel(self._file_model)
        self._file_view.setColumnWidth(0, 460)
        self._file_view.setColumnWidth(1, 96)
        self._file_view.setColumnWidth(2, 150)
        self._file_view.doubleClicked.connect(self._on_file_activated)
        right_layout.addWidget(self._file_view, 1)
        self._compare = ComparePanel()
        right_layout.addWidget(self._compare, 1)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([560, 760])
        layout.addWidget(splitter, 1)

        self._set_busy(False)

    # ------------------------------------------------------------- 对外 API
    def is_scanning(self) -> bool:
        return self._runner.is_running()

    def wait_for_stop(self, msecs: int = 3000) -> bool:
        return self._runner.wait(msecs)

    def current_result(self) -> FileScanResult | None:
        return self._result

    def set_result(self, result: FileScanResult | None) -> None:
        """外部注入结果（测试/后续阶段复用）。"""

        self._apply_result(result)
        if result is not None:
            self._root_edit.setText(result.root)

    def start_scan(self) -> None:
        if self._runner.is_running():
            self.status_message.emit("文件扫描正在进行中，请等待完成或先取消")
            return
        root = self._root_edit.text().strip()
        if not root or not Path(root).is_dir():
            QMessageBox.warning(self, "目录无效", "请先选择一个存在的目录。")
            return
        self._result = None
        self._warning_count = 0
        self._group_model.set_groups([])
        self._file_model.set_group(None)
        self._compare.clear()
        self._kpi.reset()
        self._set_exports_enabled(False)
        self._progress.set_running("正在准备扫描…")
        self._set_busy(True)

        options = FileScanOptions(
            root=root,
            min_size=max(1, int(self._min_size.value())) * 1024,
            max_files=self._config.file_scan_max_files,
            walk_budget_s=self._config.file_scan_walk_budget_s,
            large_limit=self._config.file_scan_large_limit,
            exclude_patterns=parse_exclude_patterns(self._exclude_edit.text()),
            extensions=self._current_extensions(),
            modified_after=self._current_modified_after(),
            hash_workers=self._config.file_scan_hash_workers,
            use_cache=self._cache_checkbox.isChecked(),
            cache_ttl_days=self._config.file_scan_cache_ttl_days,
        )
        try:
            self._config.file_scan_exclude_patterns = list(options.exclude_patterns)
            self._config.file_scan_cache_enabled = options.use_cache
            self._config.save()
        except Exception:  # noqa: BLE001 - 配置保存失败不影响扫描
            logger.debug("保存扫描过滤配置失败", exc_info=True)
        job = FileScanJob(options, token=CancelToken())
        job.stage_changed.connect(self._on_stage)
        job.progress.connect(self._on_progress)
        job.warning.connect(self._on_warning)
        job.finished.connect(self._on_finished)
        job.failed.connect(self._on_failed)
        job.cancelled.connect(self._on_cancelled)
        self.result_ready.emit(False)
        if not self._runner.start(job):
            self._set_busy(False)
            self._progress.set_idle("已有扫描任务在运行")

    def cancel_scan(self) -> None:
        if not self._runner.is_running():
            return
        self._runner.cancel()
        self._btn_cancel.setEnabled(False)
        self._progress.set_progress(self._progress.value(), "正在停止…（等待当前步骤结束）")

    # ------------------------------------------------------------- 内部 UI
    def _browse(self) -> None:
        start = self._root_edit.text().strip() or str(Path.home())
        directory = QFileDialog.getExistingDirectory(self, "选择要扫描的目录", start)
        if directory:
            self._root_edit.setText(directory)
            self._btn_start.setEnabled(True)

    def _set_busy(self, busy: bool) -> None:
        self._btn_start.setEnabled(not busy and bool(self._root_edit.text().strip()))
        self._btn_cancel.setEnabled(busy)
        self._btn_browse.setEnabled(not busy)
        self._min_size.setEnabled(not busy)
        for widget in (
            self._type_combo,
            self._mtime_combo,
            self._exclude_edit,
            self._cache_checkbox,
        ):
            widget.setEnabled(not busy)
        self._update_group_selection_state()

    def _current_extensions(self) -> tuple[str, ...]:
        value = self._type_combo.currentData()
        return tuple(value) if value else ()

    def _current_modified_after(self) -> float:
        days = int(self._mtime_combo.currentData() or 0)
        return time.time() - days * 86400 if days > 0 else 0.0

    def _set_exports_enabled(self, enabled: bool) -> None:
        for button in (self._btn_groups_csv, self._btn_files_csv, self._btn_json, self._btn_html):
            button.setEnabled(enabled)

    def _on_stage(self, text: str) -> None:
        self._progress.set_progress(self._progress.value(), text)

    def _on_progress(self, percent: int, text: str) -> None:
        self._progress.set_progress(percent, text)

    def _on_warning(self, warning) -> None:
        self._warning_count += 1
        logger.warning("文件扫描提示 [%s] %s", warning.code, warning.message)

    def _on_finished(self, result: FileScanResult) -> None:
        self._apply_result(result)
        self.result_ready.emit(True)
        self.scan_finished.emit(result)

    def _apply_result(self, result: FileScanResult | None) -> None:
        self._result = result
        if result is None:
            self._group_model.set_groups([])
            self._file_model.set_group(None)
            self._compare.clear()
            self._kpi.reset()
            self._set_exports_enabled(False)
            self._progress.set_idle("就绪：选择目录后点击“开始扫描”（只读）")
            self._update_group_selection_state()
            self._set_busy(False)
            return
        self._group_model.set_groups(result.duplicate_groups)
        self._kpi.set_value("files", str(result.files_scanned))
        self._kpi.set_value(
            "groups", str(len(result.duplicate_groups)), "warn" if result.duplicate_groups else "good"
        )
        self._kpi.set_value(
            "dup_files", str(result.duplicate_file_count), "warn" if result.duplicate_file_count else "normal"
        )
        self._kpi.set_value(
            "reclaimable",
            human_bytes(result.reclaimable_bytes),
            "warn" if result.reclaimable_bytes else "good",
        )
        self._kpi.set_value(
            "completeness",
            completeness_label(result.completeness),
            "good" if result.completeness is Completeness.FULL else "warn",
        )
        summary = (
            f"完成：{result.files_scanned} 个文件，{len(result.duplicate_groups)} 组重复"
            f"（可回收估算 {human_bytes(result.reclaimable_bytes)}），"
            f"用时 {human_duration_ms(result.duration_ms)}"
            f"；哈希并发 {result.hash_workers}（介质 {result.media_type}）"
        )
        if result.cache_hits:
            summary += f"；缓存命中 {result.cache_hits}"
        if result.skipped_excluded:
            summary += f"；排除 {result.skipped_excluded}"
        if self._warning_count:
            summary += f"；{self._warning_count} 条提示"
        self._progress.set_finished(summary)
        self._set_busy(False)
        self._set_exports_enabled(True)
        self._file_model.set_group(None)
        self._compare.clear()
        if result.duplicate_groups:
            first = self._group_model.index(0, 0)
            self._group_view.setCurrentIndex(first)
        self._update_group_selection_state()
        self.status_message.emit(
            f"文件扫描完成：{result.root}，{result.files_scanned} 个文件，"
            f"{len(result.duplicate_groups)} 组重复"
        )

    def _on_failed(self, message: str) -> None:
        self._progress.set_idle(f"扫描失败：{message}")
        self._set_busy(False)
        self.status_message.emit("文件扫描失败，详见日志")
        QMessageBox.critical(self, "扫描失败", message)

    def _on_cancelled(self) -> None:
        self._progress.set_idle("已取消（本次不产生部分结果）")
        self._set_busy(False)
        self.status_message.emit("文件扫描已取消")

    def _on_runner_finished(self) -> None:
        self._btn_cancel.setEnabled(False)
        if self._result is None:
            self._btn_start.setEnabled(bool(self._root_edit.text().strip()))
        self._update_group_selection_state()

    def _on_group_changed(self, current, previous) -> None:
        group = self._group_model.group_at(current)
        self._file_model.set_group(group)
        self._compare.set_group(group)

    def _on_file_activated(self, index) -> None:
        record = self._file_model.file_at(index)
        if record is None:
            return
        ok, error = open_containing_folder(record.path)
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    # ------------------------------------------------------------- 2D 硬链接去重
    def _hardlink_policy(self) -> ActionPolicy:
        return ActionPolicy.from_config(self._config)

    def _hardlink_enabled(self) -> bool:
        policy = self._hardlink_policy()
        return policy.stage2_enabled and policy.allow_hardlink_dedupe

    def _update_group_selection_state(self) -> None:
        count = self._group_model.checked_count
        if count:
            self._group_selection_label.setText(f"已选 {count} 个重复组")
        else:
            self._group_selection_label.setText("未选择重复组（勾选“选择”列后可硬链接去重）")
        enabled = (
            count > 0
            and self._result is not None
            and not self._runner.is_running()
            and not self._action_running
            and self._hardlink_enabled()
        )
        self._btn_hardlink.setEnabled(enabled)
        self._btn_clear_groups.setEnabled(count > 0 and not self._action_running)
        self._btn_preview.setEnabled(
            count > 0
            and self._result is not None
            and not self._runner.is_running()
            and not self._action_running
        )
        self._btn_preview.setToolTip(
            "预演：只做策略校验并列出将会处理的目标，不修改任何文件（不执行任何真实动作）"
        )
        has_file = self._file_model.rowCount() > 0
        detach_enabled = has_file and not self._action_running and not self._runner.is_running()
        self._btn_detach_preview.setEnabled(detach_enabled)
        self._btn_detach_preview.setToolTip("预演独立化：不复制、不修改任何文件")
        self._btn_detach.setEnabled(
            detach_enabled
            and self._hardlink_policy().stage2_enabled
            and self._hardlink_policy().allow_hardlink_detach
        )
        self._btn_detach.setToolTip(
            "将硬链接文件复制为独立文件（复制→校验→原子替换；需同卷空间；失败不改原文件）"
        )
        if not self._hardlink_enabled():
            self._btn_hardlink.setToolTip(
                "硬链接去重默认关闭：请在 config.json 中设置 stage2_enabled=true 与 allow_hardlink_dedupe=true 后重启程序"
            )
        elif count == 0:
            self._btn_hardlink.setToolTip("请先勾选重复组")
        else:
            self._btn_hardlink.setToolTip("将冗余文件替换为指向保留文件的硬链接（需二次确认）")

    def _on_select_all_groups(self) -> None:
        self._group_model.check_all_selectable()
        self._update_group_selection_state()

    def _on_clear_group_selection(self) -> None:
        self._group_model.clear_checks()
        self._update_group_selection_state()

    def _start_hardlink(self) -> None:
        if self._action_running or self._result is None:
            return
        if not self._hardlink_enabled():
            QMessageBox.warning(
                self,
                "硬链接去重未开启",
                "执行层默认关闭。请先修改配置后重启程序：\n"
                f"{config_path()}\n\n"
                '设置 "stage2_enabled": true 与 "allow_hardlink_dedupe": true。',
            )
            return
        groups = self._group_model.checked_groups()
        if not groups:
            QMessageBox.information(self, "未选择重复组", "请先勾选要处理的重复组。")
            return
        if not ensure_first_preview(self, ActionKind.HARDLINK_DEDUPE, self._config):
            return
        policy = self._hardlink_policy()
        verdict = file_scan_verdict(self._result, is_admin=self._is_admin)
        targets, decision, token = build_hardlink_preview(
            groups,
            policy=policy,
            verdict=verdict,
            now=time.time(),
            token_id=uuid.uuid4().hex,
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "策略拒绝", policy_refusal_text(decision))
            return
        allowed = [targets[index] for index in decision.allowed_indices]
        items = [
            f"保留：{target.canonical.path}\n  → 冗余：{target.redundant.path}"
            for target in allowed[:50]
        ]
        if len(allowed) > 50:
            items.append(f"... 其余 {len(allowed) - 50} 项略")
        dialog = ConfirmActionDialog(
            title="确认硬链接去重",
            action_summary=f"将把 {len(allowed)} 个冗余文件替换为硬链接（保留 {len(groups)} 个文件路径）",
            consequence=(
                "替换后两个路径指向同一份数据，修改一个会影响另一个；"
                "冗余路径的修改时间/ACL 会变为保留文件的；"
                "本操作不做自动回滚，需要恢复为独立文件时请手动复制。"
            ),
            items=items,
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        cancel_token = CancelToken()
        job = ActionJob(
            action=ActionKind.HARDLINK_DEDUPE,
            token=token,
            targets=targets,
            allowed_indices=decision.allowed_indices,
            executor=HardlinkExecutor(token=cancel_token),
            audit=ActionAuditWriter(self._audit_dir),
            verdict=verdict,
            is_admin=self._is_admin,
            app_version=self._app_version,
            dry_run=False,
            clock=time.time,
            cancel_token=cancel_token,
        )
        job.progress.connect(self._on_action_progress)
        job.finished.connect(self._on_action_finished)
        job.failed.connect(self._on_action_failed)
        job.cancelled.connect(self._on_action_cancelled)
        self._action_running = True
        self._progress.set_running(f"正在执行硬链接去重：0 / {len(allowed)} …")
        self._update_group_selection_state()
        if not self._action_runner.start(job):
            self._action_running = False
            self._progress.set_idle("已有动作任务在运行")
            self._update_group_selection_state()

    def is_action_running(self) -> bool:
        return self._action_running

    def cancel_action(self) -> None:
        if self._action_running:
            self._action_runner.cancel()

    def wait_action(self, msecs: int = 3000) -> bool:
        return self._action_runner.wait(msecs)

    def _on_action_progress(self, percent: int, text: str) -> None:
        self._progress.set_progress(percent, f"硬链接去重：{text}")

    def _on_action_finished(self, session: ActionSessionResult) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._group_model.clear_checks()
        self._progress.set_finished(
            f"硬链接去重完成：成功 {session.success_count} 项，失败 {session.failed_count} 项"
        )
        self._update_group_selection_state()
        lines = [
            f"{item.result}: {item.target}" + (f"（{item.error_code}）" if item.error_code else "")
            for item in session.results
        ]
        QMessageBox.information(
            self,
            "硬链接去重完成",
            f"成功 {session.success_count} 项，失败 {session.failed_count} 项。\n\n"
            "失败项未做任何替换；详情已写入审计日志。\n\n" + "\n".join(lines[:50]),
        )
        self.status_message.emit(
            f"硬链接去重完成：成功 {session.success_count} 项，失败 {session.failed_count} 项"
        )

    def _on_action_failed(self, message: str) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._progress.set_idle(f"硬链接去重失败：{message}")
        self._update_group_selection_state()
        self.status_message.emit("硬链接去重失败，详见日志")
        QMessageBox.critical(self, "硬链接去重失败", f"{message}\n\n审计日志目录：{log_dir()}")

    def _on_action_cancelled(self) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._progress.set_idle("硬链接去重已取消（已执行项目见审计日志）")
        self._update_group_selection_state()
        self.status_message.emit("硬链接去重已取消")

    def _on_action_runner_finished(self) -> None:
        if not self._action_running:
            self._update_group_selection_state()

    def refresh_action_switches(self) -> None:
        """设置页一键关闭执行层开关后刷新按钮状态。"""

        self._update_group_selection_state()

    def _start_preview(self) -> None:
        """阶段 3A 预演：只做策略校验，不建立任何硬链接（不修改文件）。"""

        if self._action_running or self._result is None:
            return
        groups = self._group_model.checked_groups()
        if not groups:
            QMessageBox.information(self, "未选择重复组", "请先勾选要预演的重复组。")
            return
        verdict = file_scan_verdict(self._result, is_admin=self._is_admin)
        preview_policy = replace(
            self._hardlink_policy(),
            stage2_enabled=True,
            allow_hardlink_dedupe=True,
        )
        targets, decision, token = build_hardlink_preview(
            groups,
            policy=preview_policy,
            verdict=verdict,
            now=time.time(),
            token_id=uuid.uuid4().hex,
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "预演被拒绝", policy_refusal_text(decision))
            return
        session, error = run_preview_job(
            kind=ActionKind.HARDLINK_DEDUPE,
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
        QMessageBox.information(
            self, "预演完成", preview_result_text(session, ActionKind.HARDLINK_DEDUPE)
        )
        self.status_message.emit("预演完成：未修改任何文件")
        self._update_group_selection_state()



    # ------------------------------------------------------------- 4B 硬链接独立化
    def _current_file_record(self):
        index = self._file_view.currentIndex()
        record = self._file_model.file_at(index)
        if record is None:
            record = self._file_model.file_at(self._file_model.index(0, 0))
        return record

    def _detach_policy(self) -> ActionPolicy:
        return ActionPolicy.from_config(self._config)

    def _start_detach_preview(self) -> None:
        if self._action_running or self._result is None:
            return
        record = self._current_file_record()
        if record is None:
            QMessageBox.information(self, "未选择文件", "请先在组内文件表中选择一个文件。")
            return
        verdict = file_scan_verdict(self._result, is_admin=self._is_admin)
        preview_policy = replace(
            self._detach_policy(), stage2_enabled=True, allow_hardlink_detach=True
        )
        targets, decision, token = build_detach_preview(
            [record],
            policy=preview_policy,
            verdict=verdict,
            now=time.time(),
            token_id=uuid.uuid4().hex,
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "预演被拒绝", policy_refusal_text(decision))
            return
        session, error = run_preview_job(
            kind=ActionKind.HARDLINK_DETACH,
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
        QMessageBox.information(
            self, "预演完成", preview_result_text(session, ActionKind.HARDLINK_DETACH)
        )
        self._update_group_selection_state()

    def _start_detach(self) -> None:
        if self._action_running or self._result is None:
            return
        policy = self._detach_policy()
        if not (policy.stage2_enabled and policy.allow_hardlink_detach):
            QMessageBox.warning(
                self,
                "独立化未开启",
                "执行层默认关闭。请修改配置后重启：\n"
                f"{config_path()}\n\n"
                '设置 "stage2_enabled": true 与 "allow_hardlink_detach": true。',
            )
            return
        record = self._current_file_record()
        if record is None:
            QMessageBox.information(self, "未选择文件", "请先在组内文件表中选择一个文件。")
            return
        if not ensure_first_preview(self, ActionKind.HARDLINK_DETACH, self._config):
            return
        verdict = file_scan_verdict(self._result, is_admin=self._is_admin)
        targets, decision, token = build_detach_preview(
            [record], policy=policy, verdict=verdict, now=time.time(), token_id=uuid.uuid4().hex
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "策略拒绝", policy_refusal_text(decision))
            return
        allowed = [targets[index] for index in decision.allowed_indices]
        dialog = ConfirmActionDialog(
            title="确认硬链接独立化",
            action_summary=f"将把 {len(allowed)} 个硬链接文件复制为独立文件",
            consequence=(
                "过程：复制到同目录临时文件 → 哈希校验 → 原子替换；需要同卷剩余空间 "
                "≥ 文件大小 + 1MB。失败时原文件保持不变，不会删除任何数据。"
            ),
            items=[f"{target.path}（{human_bytes(target.size)}，nlink={target.nlink}）" for target in allowed],
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        cancel_token = CancelToken()
        job = ActionJob(
            action=ActionKind.HARDLINK_DETACH,
            token=token,
            targets=targets,
            allowed_indices=decision.allowed_indices,
            executor=HardlinkDetachExecutor(token=cancel_token),
            audit=ActionAuditWriter(self._audit_dir),
            verdict=verdict,
            is_admin=self._is_admin,
            app_version=self._app_version,
            dry_run=False,
            clock=time.time,
            cancel_token=cancel_token,
        )
        job.finished.connect(self._on_detach_finished)
        job.failed.connect(self._on_action_failed)
        job.cancelled.connect(self._on_action_cancelled)
        self._action_running = True
        self._progress.set_running("正在独立化硬链接文件…")
        self._update_group_selection_state()
        if not self._action_runner.start(job):
            self._action_running = False
            self._progress.set_idle("已有动作任务在运行")
            self._update_group_selection_state()

    def _on_detach_finished(self, session: ActionSessionResult) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._progress.set_finished(
            f"独立化完成：成功 {session.success_count} 项，失败 {session.failed_count} 项"
        )
        self._update_group_selection_state()
        lines = [
            f"{item.result}: {item.target}" + (f"（{item.error_code}）" if item.error_code else "")
            for item in session.results
        ]
        self.status_message.emit(
            f"独立化完成：成功 {session.success_count} 项，失败 {session.failed_count} 项"
        )
        QMessageBox.information(
            self,
            "独立化完成",
            f"成功 {session.success_count} 项，失败 {session.failed_count} 项。\n\n" + "\n".join(lines[:20]),
        )

    # ------------------------------------------------------------- 导出
    def _export(
        self,
        label: str,
        prefix: str,
        suffix: str,
        exporter: Callable[[str, FileScanResult], tuple[bool, str]],
    ) -> None:
        if self._result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次文件扫描再导出。")
            return
        try:
            export_dir = default_export_dir()
            export_dir.mkdir(parents=True, exist_ok=True)
            suggested = str(export_dir / f"{prefix}_{now_text()}{suffix}")
        except OSError:
            suggested = f"{prefix}_{now_text()}{suffix}"
        path, _ = QFileDialog.getSaveFileName(self, f"导出{label}", suggested, f"{label} 文件 (*{suffix})")
        if not path:
            return
        if not path.casefold().endswith(suffix):
            path += suffix
        ok, message = exporter(path, self._result)
        if ok:
            self.status_message.emit(f"已导出{label}：{path}")
            QMessageBox.information(self, "导出成功", f"{message}\n\n文件：{path}")
        else:
            QMessageBox.critical(self, "导出失败", message)

    def export_groups_csv(self) -> None:
        self._export("重复组 CSV", "重复文件组", ".csv", export_duplicates_csv)

    def export_files_csv(self) -> None:
        self._export("重复明细 CSV", "重复文件明细", ".csv", export_duplicate_files_csv)

    def export_json(self) -> None:
        self._export("JSON", "重复文件扫描", ".json", export_file_scan_json)

    def export_html(self) -> None:
        self._export("HTML 报告", "重复文件报告", ".html", export_file_report_html)
