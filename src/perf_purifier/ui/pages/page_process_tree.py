"""进程血缘页（模块 A · 阶段 1A）。

交互：开始扫描 / 取消 / 搜索 / 风险筛选 / 导出 CSV、JSON / 选中查看详情。
所有扫描在独立 QThread 执行，UI 线程只处理信号。
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

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
    QScrollArea,
    QSplitter,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from ...core.action_policy import ActionKind, ActionPolicy, policy_refusal_text
from ...core.audit import ActionAuditWriter, rotate_audit_log
from ...core.cancel import CancelToken
from ...core.config import AppConfig, config_path, default_export_dir, log_dir
from ...core.fmt import human_duration_ms, now_text
from ...core.models import (
    Completeness,
    ProcessScanResult,
    ProcessTree,
    ScanWarning,
    Severity,
    completeness_label,
)
from ...core.snapshots import (
    build_snapshot,
    compare_snapshot,
    delete_snapshot,
    diff_summary,
    load_snapshot,
    save_snapshot,
    snapshot_path,
    snapshot_summary,
)
from ...core.whitelist import Whitelist
from ...jobs.action_job import ActionJob, ActionSessionResult
from ...jobs.base_job import JobRunner
from ...jobs.process_job import ProcessScanJob
from ...module_a.kill_action import (
    KillExecutor,
    build_kill_preview,
    process_scan_verdict,
)
from ...module_a.report import export_process_csv, export_process_json
from ..action_preview import ensure_first_preview, preview_result_text, run_preview_job
from ..dialogs.confirm_action_dialog import ConfirmActionDialog
from ..models.process_tree_model import ProcessTreeModel
from ..widgets.busy_overlay import ScanProgressBar
from ..widgets.detail_panel import DetailPanel
from ..widgets.kpi_bar import KpiBar

logger = logging.getLogger(__name__)

_RISK_FILTERS: tuple[tuple[str, Severity], ...] = (
    ("全部", Severity.INFO),
    ("关注及以上", Severity.NOTICE),
    ("可疑及以上", Severity.SUSPICIOUS),
    ("高风险", Severity.HIGH),
)


class ProcessTreePage(QWidget):
    scan_started = Signal()
    scan_finished = Signal(object)
    scan_progress = Signal(int, str)
    scan_stopped = Signal()
    result_ready = Signal(bool)
    status_message = Signal(str)

    def __init__(
        self,
        config: AppConfig,
        whitelist: Whitelist,
        *,
        is_admin: bool,
        app_version: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._whitelist = whitelist
        self._is_admin = is_admin
        self._app_version = app_version
        self._audit_dir: Path = log_dir()
        self._config_save_path: Path | None = None
        self._snapshot_path: Path | None = None
        self._result: ProcessScanResult | None = None
        self._warnings: list[ScanWarning] = []
        self._action_running = False
        self._runner = JobRunner(self)
        self._runner.finished.connect(self._on_runner_finished)
        self._action_runner = JobRunner(self)
        self._action_runner.finished.connect(self._on_action_runner_finished)
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self._btn_start = QPushButton("开始扫描")
        self._btn_start.setDefault(True)
        self._btn_start.clicked.connect(self.refresh)
        self._btn_cancel = QPushButton("取消")
        self._btn_cancel.setEnabled(False)
        self._btn_cancel.clicked.connect(self.cancel_scan)

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("搜索：进程名 / PID / 路径 / 命令行")
        self._search_edit.setClearButtonEnabled(True)
        self._search_edit.setMinimumWidth(240)
        self._search_edit.textChanged.connect(self._apply_filters)

        self._risk_combo = QComboBox()
        for text, severity in _RISK_FILTERS:
            self._risk_combo.addItem(text, int(severity))
        self._risk_combo.currentIndexChanged.connect(self._apply_filters)

        self._btn_csv = QPushButton("导出 CSV")
        self._btn_csv.setEnabled(False)
        self._btn_csv.clicked.connect(self.export_csv)
        self._btn_json = QPushButton("导出 JSON")
        self._btn_json.setEnabled(False)
        self._btn_json.clicked.connect(self.export_json)
        self._btn_snapshot_save = QPushButton("保存基线")
        self._btn_snapshot_save.clicked.connect(self.save_baseline)
        self._btn_snapshot_compare = QPushButton("对比基线")
        self._btn_snapshot_compare.clicked.connect(self.compare_baseline)
        self._btn_snapshot_delete = QPushButton("删除基线")
        self._btn_snapshot_delete.clicked.connect(self.delete_baseline)

        toolbar.addWidget(self._btn_start)
        toolbar.addWidget(self._btn_cancel)
        toolbar.addSpacing(8)
        toolbar.addWidget(QLabel("搜索："))
        toolbar.addWidget(self._search_edit, 1)
        toolbar.addWidget(QLabel("风险："))
        toolbar.addWidget(self._risk_combo)
        toolbar.addSpacing(8)
        toolbar.addWidget(self._btn_csv)
        toolbar.addWidget(self._btn_json)
        toolbar.addSpacing(8)
        toolbar.addWidget(self._btn_snapshot_save)
        toolbar.addWidget(self._btn_snapshot_compare)
        toolbar.addWidget(self._btn_snapshot_delete)
        layout.addLayout(toolbar)

        action_row = QHBoxLayout()
        action_row.setSpacing(6)
        self._kill_selection_label = QLabel("未选择进程（可按住 Ctrl/Shift 多选，最多 20 个）")
        self._kill_selection_label.setStyleSheet("color: palette(dark);")
        self._btn_preview = QPushButton("预演选中项（不执行）")
        self._btn_preview.clicked.connect(self._start_preview)
        self._btn_kill = QPushButton("结束选中进程（默认关闭）")
        self._btn_kill.clicked.connect(self._start_kill)
        action_row.addWidget(self._kill_selection_label, 1)
        action_row.addWidget(self._btn_preview)
        action_row.addWidget(self._btn_kill)
        layout.addLayout(action_row)

        self._progress = ScanProgressBar()
        layout.addWidget(self._progress)

        self._kpi = KpiBar(
            [
                ("total", "进程数"),
                ("notice", "关注及以上"),
                ("suspect", "可疑及以上"),
                ("high", "高风险"),
                ("orphan", "孤儿进程"),
                ("completeness", "数据完整度"),
            ]
        )
        layout.addWidget(self._kpi)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._model = ProcessTreeModel(self)
        self._view = QTreeView()
        self._view.setModel(self._model)
        self._view.setAlternatingRowColors(True)
        self._view.setUniformRowHeights(True)
        self._view.setSortingEnabled(False)
        self._view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._view.setExpandsOnDoubleClick(True)
        header = self._view.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._view.setColumnWidth(0, 240)
        self._view.setColumnWidth(1, 68)
        self._view.setColumnWidth(2, 140)
        self._view.setColumnWidth(3, 88)
        self._view.setColumnWidth(4, 80)
        self._view.setColumnWidth(5, 150)
        self._view.selectionModel().currentChanged.connect(self._on_current_changed)
        self._view.selectionModel().selectionChanged.connect(
            lambda selected, deselected: self._update_kill_selection_state()
        )

        self._detail = DetailPanel(self._config)
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setWidget(self._detail)
        detail_scroll.setMinimumWidth(360)

        splitter.addWidget(self._view)
        splitter.addWidget(detail_scroll)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([720, 460])
        layout.addWidget(splitter, 1)

    # ------------------------------------------------------------- 对外 API
    def is_scanning(self) -> bool:
        return self._runner.is_running()

    def wait_for_stop(self, msecs: int = 3000) -> bool:
        return self._runner.wait(msecs)

    def current_result(self) -> ProcessScanResult | None:
        return self._result

    def refresh(self) -> None:
        if self._runner.is_running():
            self.status_message.emit("扫描正在进行中，请等待完成或先取消")
            return
        self._result = None
        self._warnings = []
        self._model.set_tree(None)
        self._detail.show_node(None)
        self._kpi.reset()
        self._btn_csv.setEnabled(False)
        self._btn_json.setEnabled(False)
        self._set_busy(True)
        self._progress.set_running("正在准备扫描…")
        self.scan_progress.emit(0, "正在准备扫描…")

        job = ProcessScanJob(
            self._config,
            self._whitelist,
            is_admin=self._is_admin,
            token=CancelToken(),
        )
        job.stage_changed.connect(self._on_stage)
        job.progress.connect(self._on_progress)
        job.warning.connect(self._on_warning)
        job.finished.connect(self._on_finished)
        job.failed.connect(self._on_failed)
        job.cancelled.connect(self._on_cancelled)

        self.scan_started.emit()
        self.result_ready.emit(False)
        if not self._runner.start(job):
            self._set_busy(False)
            self._progress.set_idle("已有扫描任务在运行，请稍后再试")

    def cancel_scan(self) -> None:
        if not self._runner.is_running():
            return
        self._runner.cancel()
        self._btn_cancel.setEnabled(False)
        self._progress.set_progress(self._progress.value(), "正在停止…（等待当前步骤结束）")

    # ------------------------------------------------------------- 槽函数
    def _set_busy(self, busy: bool) -> None:
        self._btn_start.setEnabled(not busy)
        self._btn_cancel.setEnabled(busy)
        self._btn_csv.setEnabled(not busy and self._result is not None)
        self._btn_json.setEnabled(not busy and self._result is not None)
        self._update_kill_selection_state()
        self._update_snapshot_buttons()

    def _on_stage(self, text: str) -> None:
        self._progress.set_progress(self._progress.value(), text)
        self.scan_progress.emit(self._progress.value(), text)

    def _on_progress(self, percent: int, text: str) -> None:
        self._progress.set_progress(percent, text)
        self.scan_progress.emit(percent, text)

    def _on_warning(self, warning: ScanWarning) -> None:
        self._warnings.append(warning)
        logger.warning("扫描提示 [%s] %s", warning.code, warning.message)

    def _on_finished(self, result: ProcessScanResult) -> None:
        self._result = result
        tree = result.tree
        self._model.set_tree(tree)
        self._apply_filters()
        if not self._search_edit.text().strip() and self._current_severity() is Severity.INFO:
            self._view.expandToDepth(0)
        self._update_kpi(tree)
        summary = f"完成：{tree.total_processes} 个进程，用时 {human_duration_ms(result.duration_ms)}"
        if self._warnings:
            summary += f"；{len(self._warnings)} 条提示"
        self._progress.set_finished(summary)
        self.scan_progress.emit(100, summary)
        self._set_busy(False)
        self._btn_csv.setEnabled(True)
        self._btn_json.setEnabled(True)
        self._detail.show_node(None)
        self.result_ready.emit(True)
        self._update_kill_selection_state()
        self._update_snapshot_buttons()
        self.scan_finished.emit(result)
        noticed = tree.count_at_least(Severity.NOTICE)
        self.status_message.emit(
            f"扫描完成：{tree.total_processes} 个进程，{noticed} 个命中关注及以上规则"
        )
        if tree.total_processes == 0:
            QMessageBox.warning(
                self,
                "未读取到进程",
                "未能读取任何进程信息。\n请查看日志，或尝试以管理员身份重新运行。",
            )

    def _on_failed(self, message: str) -> None:
        self._progress.set_idle(f"扫描失败：{message}")
        self._set_busy(False)
        self.status_message.emit("扫描失败，详见日志")
        self.scan_stopped.emit()
        QMessageBox.critical(
            self,
            "扫描失败",
            f"{message}\n\n详细信息见日志目录：\n{log_dir()}",
        )

    def _on_cancelled(self) -> None:
        self._progress.set_idle("已取消（本次不产生部分结果）")
        self._set_busy(False)
        self.status_message.emit("扫描已取消")
        self.scan_stopped.emit()

    def _on_runner_finished(self) -> None:
        self._btn_cancel.setEnabled(False)
        if self._result is None:
            self._btn_start.setEnabled(True)

    def _on_current_changed(self, current: Any, previous: Any) -> None:
        node = self._model.node_for_index(current)
        parent_node = None
        if node is not None and node.parent_pid is not None:
            parent_node = self._model.node_for_pid(node.parent_pid)
        self._detail.show_node(node, parent_node)

    def _update_kpi(self, tree: ProcessTree) -> None:
        notice = tree.count_at_least(Severity.NOTICE)
        suspicious = tree.count_at_least(Severity.SUSPICIOUS)
        high = tree.count_at_least(Severity.HIGH)
        orphans = len(tree.orphans)
        self._kpi.set_value("total", str(tree.total_processes))
        self._kpi.set_value("notice", str(notice), "warn" if notice else "normal")
        self._kpi.set_value("suspect", str(suspicious), "warn" if suspicious else "normal")
        self._kpi.set_value("high", str(high), "danger" if high else "normal")
        self._kpi.set_value("orphan", str(orphans), "warn" if orphans else "normal")
        self._kpi.set_value(
            "completeness",
            completeness_label(tree.completeness),
            "good" if tree.completeness is Completeness.FULL else "warn",
        )

    # ------------------------------------------------------------- 2B 结束进程
    def set_result(self, result: ProcessScanResult | None) -> None:
        """供测试/复用：应用一个扫描结果（与扫描完成后的界面状态一致，不发信号）。"""

        self._result = result
        if result is None:
            self._warnings = []
            self._model.set_tree(None)
            self._detail.show_node(None)
            self._kpi.reset()
            self._btn_csv.setEnabled(False)
            self._btn_json.setEnabled(False)
            self._update_kill_selection_state()
            return
        self._model.set_tree(result.tree)
        self._apply_filters()
        self._update_kpi(result.tree)
        self._btn_csv.setEnabled(True)
        self._btn_json.setEnabled(True)
        self._detail.show_node(None)
        self._update_kill_selection_state()
        self._update_snapshot_buttons()

    def _kill_policy(self) -> ActionPolicy:
        return ActionPolicy.from_config(self._config)

    def _kill_enabled(self) -> bool:
        policy = self._kill_policy()
        return policy.stage2_enabled and policy.allow_kill_process

    def _selected_pids(self) -> list[int]:
        pids: list[int] = []
        for index in self._view.selectionModel().selectedRows(0):
            node = self._model.node_for_index(index)
            if node is not None and node.info.pid not in pids:
                pids.append(node.info.pid)
        return pids

    def _update_kill_selection_state(self) -> None:
        pids = self._selected_pids()
        if pids:
            self._kill_selection_label.setText(f"已选 {len(pids)} 个进程")
        else:
            self._kill_selection_label.setText(
                "未选择进程（可按住 Ctrl/Shift 多选，最多 20 个）"
            )
        enabled = (
            len(pids) > 0
            and self._result is not None
            and not self._runner.is_running()
            and not self._action_running
            and self._kill_enabled()
        )
        self._btn_kill.setEnabled(enabled)
        self._btn_preview.setEnabled(
            len(pids) > 0
            and self._result is not None
            and not self._runner.is_running()
            and not self._action_running
        )
        self._btn_preview.setToolTip(
            "预演：只做策略校验并列出将会结束的目标，不结束任何进程（不执行任何真实动作）"
        )
        if not self._kill_enabled():
            self._btn_kill.setToolTip(
                "结束进程默认关闭：请在 config.json 中设置 stage2_enabled=true 与 allow_kill_process=true 后重启程序"
            )
        elif not pids:
            self._btn_kill.setToolTip("请先选择要结束的进程（可多选）")
        else:
            self._btn_kill.setToolTip("结束选中进程（需输入确认词；Windows 强制终止）")

    def _start_kill(self) -> None:
        if self._action_running or self._result is None:
            return
        if not self._kill_enabled():
            QMessageBox.warning(
                self,
                "结束进程未开启",
                "执行层默认关闭。请先修改配置后重启程序：\n"
                f"{config_path()}\n\n"
                '设置 "stage2_enabled": true 与 "allow_kill_process": true。',
            )
            return
        pids = self._selected_pids()
        if not pids:
            QMessageBox.information(self, "未选择进程", "请先在进程树中选择要结束的进程。")
            return
        if not ensure_first_preview(self, ActionKind.KILL_PROCESS, self._config):
            return
        policy = self._kill_policy()
        verdict = process_scan_verdict(self._result, is_admin=self._is_admin)
        targets, decision, token = build_kill_preview(
            self._result,
            pids,
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
            f"PID {target.pid}  {target.name}（{target.exe or '路径未知'}）"
            for target in allowed
        ]
        items.extend(f"提示：{warning}" for warning in decision.warnings)
        dialog = ConfirmActionDialog(
            title="确认结束进程",
            action_summary=f"将结束 {len(allowed)} 个进程",
            consequence=(
                "Windows 上为强制终止（无优雅退出），未保存的数据会丢失；"
                "系统关键进程、本程序自身/祖先进程、PID 复用或受保护进程会被拒绝；"
                "本操作不提供强制结束升级，且无法撤销。"
            ),
            items=items,
            require_typed_phrase="结束进程",
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        cancel_token = CancelToken()
        job = ActionJob(
            action=ActionKind.KILL_PROCESS,
            token=token,
            targets=targets,
            allowed_indices=decision.allowed_indices,
            executor=KillExecutor(),
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
        self._progress.set_running(f"正在结束进程：0 / {len(allowed)} …")
        self._update_kill_selection_state()
        if not self._action_runner.start(job):
            self._action_running = False
            self._progress.set_idle("已有动作任务在运行")
            self._update_kill_selection_state()

    def is_action_running(self) -> bool:
        return self._action_running

    def cancel_action(self) -> None:
        if self._action_running:
            self._action_runner.cancel()

    def wait_action(self, msecs: int = 3000) -> bool:
        return self._action_runner.wait(msecs)

    def _on_action_progress(self, percent: int, text: str) -> None:
        self._progress.set_progress(percent, f"结束进程：{text}")

    def _on_action_finished(self, session: ActionSessionResult) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._progress.set_finished(
            f"结束进程完成：成功 {session.success_count} 项，失败 {session.failed_count} 项"
        )
        self._update_kill_selection_state()
        lines = [
            f"{item.result}: {item.target}" + (f"（{item.error_code}）" if item.error_code else "")
            for item in session.results
        ]
        QMessageBox.information(
            self,
            "结束进程完成",
            f"成功 {session.success_count} 项，失败 {session.failed_count} 项。\n\n"
            "失败项未再尝试其它手段；详情已写入审计日志。\n\n" + "\n".join(lines[:50]),
        )
        self.status_message.emit(
            f"结束进程完成：成功 {session.success_count} 项，失败 {session.failed_count} 项"
        )

    def _on_action_failed(self, message: str) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._progress.set_idle(f"结束进程失败：{message}")
        self._update_kill_selection_state()
        self.status_message.emit("结束进程失败，详见日志")
        QMessageBox.critical(self, "结束进程失败", f"{message}\n\n审计日志目录：{log_dir()}")

    def _on_action_cancelled(self) -> None:
        self._action_running = False
        rotate_audit_log(self._audit_dir)
        self._progress.set_idle("结束进程已取消（已执行项目见审计日志）")
        self._update_kill_selection_state()
        self.status_message.emit("结束进程已取消")

    def _on_action_runner_finished(self) -> None:
        if not self._action_running:
            self._update_kill_selection_state()
            self._update_snapshot_buttons()

    def refresh_action_switches(self) -> None:
        """设置页一键关闭执行层开关后刷新按钮状态。"""

        self._update_kill_selection_state()

    def _start_preview(self) -> None:
        """阶段 3A 预演：只做策略校验，不结束任何进程（不执行任何真实动作）。"""

        if self._action_running or self._result is None:
            return
        pids = self._selected_pids()
        if not pids:
            QMessageBox.information(self, "未选择进程", "请先在进程树中选择要预演的进程。")
            return
        verdict = process_scan_verdict(self._result, is_admin=self._is_admin)
        preview_policy = replace(
            self._kill_policy(),
            stage2_enabled=True,
            allow_kill_process=True,
        )
        targets, decision, token = build_kill_preview(
            self._result,
            pids,
            policy=preview_policy,
            verdict=verdict,
            now=time.time(),
            token_id=uuid.uuid4().hex,
        )
        if token is None or not decision.allowed:
            QMessageBox.warning(self, "预演被拒绝", policy_refusal_text(decision))
            return
        session, error = run_preview_job(
            kind=ActionKind.KILL_PROCESS,
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
        QMessageBox.information(self, "预演完成", preview_result_text(session, ActionKind.KILL_PROCESS))
        self.status_message.emit("预演完成：未结束任何进程")
        self._update_kill_selection_state()

    # ------------------------------------------------------------- 快照对比（4A 只读）
    def _snapshot_target(self) -> Path:
        return self._snapshot_path or snapshot_path()

    def _update_snapshot_buttons(self) -> None:
        busy = self._runner.is_running() or self._action_running
        try:
            exists = self._snapshot_target().exists()
        except OSError:
            exists = False
        self._btn_snapshot_save.setEnabled(self._result is not None and not busy)
        self._btn_snapshot_compare.setEnabled(self._result is not None and exists and not busy)
        self._btn_snapshot_delete.setEnabled(exists and not busy)
        target = self._snapshot_target()
        self._btn_snapshot_save.setToolTip(f"保存只读基线到：{target}（仅本机，不会自动更新）")
        self._btn_snapshot_compare.setToolTip("与已保存基线对比（只读，不修改任何内容）")
        self._btn_snapshot_delete.setToolTip("删除已保存的基线文件")

    def save_baseline(self) -> None:
        if self._result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次扫描再保存基线。")
            return
        snapshot = build_snapshot(self._result)
        ok, message = save_snapshot(snapshot, self._snapshot_target())
        if not ok:
            QMessageBox.critical(self, "保存基线失败", message)
            return
        self._update_snapshot_buttons()
        self.status_message.emit("已保存只读基线（仅本机）")
        QMessageBox.information(self, "已保存基线", snapshot_summary(snapshot))

    def compare_baseline(self) -> None:
        snapshot, error = load_snapshot(self._snapshot_target())
        if snapshot is None:
            QMessageBox.information(self, "无法对比", error)
            self._update_snapshot_buttons()
            return
        if self._result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次扫描再对比基线。")
            return
        diff = compare_snapshot(snapshot, self._result)
        self.status_message.emit(
            f"基线对比完成：新增进程 {len(diff.new_processes)}，"
            f"新增远端端点 {len(diff.new_remote_endpoints)}"
        )
        QMessageBox.information(self, "基线对比结果", diff_summary(diff))

    def delete_baseline(self) -> None:
        answer = QMessageBox.question(
            self,
            "删除基线？",
            "将删除本机保存的只读基线文件；不影响任何扫描结果或系统设置。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        ok, message = delete_snapshot(self._snapshot_target())
        self._update_snapshot_buttons()
        if ok:
            self.status_message.emit("已删除基线")
        else:
            QMessageBox.critical(self, "删除失败", message)

    # ------------------------------------------------------------- 过滤
    def _current_severity(self) -> Severity:
        value = self._risk_combo.currentData()
        try:
            return Severity(int(value))
        except (TypeError, ValueError):
            return Severity.INFO

    def _apply_filters(self) -> None:
        severity = self._current_severity()
        self._model.set_filters(self._search_edit.text(), severity)
        if self._search_edit.text().strip() or severity is not Severity.INFO:
            self._view.expandAll()
        elif self._model.rowCount() > 0:
            self._view.expandToDepth(0)

    # ------------------------------------------------------------- 导出
    def export_csv(self) -> None:
        self._export("CSV", "进程血缘", ".csv", export_process_csv)

    def export_json(self) -> None:
        self._export("JSON", "进程血缘", ".json", export_process_json)

    def _export(
        self,
        label: str,
        prefix: str,
        suffix: str,
        exporter: Callable[[str, ProcessScanResult, AppConfig], tuple[bool, str]],
    ) -> None:
        if self._result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次扫描再导出。")
            return
        try:
            export_dir = default_export_dir()
            export_dir.mkdir(parents=True, exist_ok=True)
            suggested = str(export_dir / f"{prefix}_{now_text()}{suffix}")
        except OSError:
            suggested = f"{prefix}_{now_text()}{suffix}"
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"导出{label}",
            suggested,
            f"{label} 文件 (*{suffix})",
        )
        if not path:
            return
        if not path.casefold().endswith(suffix):
            path += suffix
        ok, message = exporter(path, self._result, self._config)
        if ok:
            self.status_message.emit(f"已导出{label}：{path}")
            QMessageBox.information(self, "导出成功", f"{message}\n\n文件：{path}")
        else:
            QMessageBox.critical(self, "导出失败", message)
