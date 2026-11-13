"""阶段 3B：动作历史页（只读查看 ``operations.jsonl`` 与轮转文件）。

安全约束（docs/05 S3-5）：
* 只读：只解析日志文本，不执行日志中的任何内容，不改写日志；
* 不提供导出 / 重做 / 撤销 / 打开目标等可能导致二次操作的功能；
* 有字节上限与坏行计数，超大日志只展示最新部分并明确提示。
"""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ...core.action_history import (
    ACTION_LABELS,
    DEFAULT_MAX_BYTES,
    RESULT_LABELS,
    HistoryLoadResult,
    filter_records,
    incomplete_sessions,
    load_history,
)
from ...core.config import log_dir
from ...core.shell import open_containing_folder
from ..models.history_model import HistoryTableModel

PAGE_SIZE = 200


class HistoryPage(QWidget):
    def __init__(self, *, log_directory: Path | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._log_directory = Path(log_directory) if log_directory is not None else log_dir()
        self._loaded: HistoryLoadResult | None = None
        self._filtered: tuple = ()
        self._limit = PAGE_SIZE
        self._build_ui()
        self.refresh()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self._btn_refresh = QPushButton("刷新")
        self._btn_refresh.clicked.connect(self.refresh)
        self._action_combo = QComboBox()
        self._action_combo.addItem("全部动作", "")
        for key, label in ACTION_LABELS.items():
            self._action_combo.addItem(label, key)
        self._result_combo = QComboBox()
        self._result_combo.addItem("全部结果", "")
        for key, label in RESULT_LABELS.items():
            self._result_combo.addItem(label, key)
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("搜索：时间 / 会话 / 目标 / 错误码")
        self._search_edit.setClearButtonEnabled(True)
        self._btn_load_more = QPushButton("加载更多")
        self._btn_load_more.clicked.connect(self._load_more)
        self._btn_open_dir = QPushButton("打开日志目录")
        self._btn_open_dir.clicked.connect(self._open_log_directory)

        toolbar.addWidget(self._btn_refresh)
        toolbar.addSpacing(8)
        toolbar.addWidget(QLabel("动作："))
        toolbar.addWidget(self._action_combo)
        toolbar.addWidget(QLabel("结果："))
        toolbar.addWidget(self._result_combo)
        toolbar.addWidget(self._search_edit, 1)
        toolbar.addWidget(self._btn_load_more)
        toolbar.addWidget(self._btn_open_dir)
        layout.addLayout(toolbar)

        self._summary = QLabel("正在读取动作历史…")
        self._summary.setWordWrap(True)
        self._summary.setStyleSheet("color: palette(dark); font-size: 11px;")
        layout.addWidget(self._summary)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self._model = HistoryTableModel(self)
        self._view = QTableView()
        self._view.setModel(self._model)
        self._view.setAlternatingRowColors(True)
        self._view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._view.setWordWrap(False)
        header = self._view.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, header.ResizeMode.Interactive)
        self._view.setColumnWidth(0, 150)
        self._view.setColumnWidth(1, 64)
        self._view.setColumnWidth(2, 96)
        self._view.setColumnWidth(3, 120)
        self._view.setColumnWidth(4, 360)
        self._view.setColumnWidth(5, 60)
        self._view.selectionModel().currentChanged.connect(self._show_detail)

        self._detail = QPlainTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setPlaceholderText("选择一条记录查看原始字段（只读）")
        self._detail.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        splitter.addWidget(self._view)
        splitter.addWidget(self._detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([840, 420])
        layout.addWidget(splitter, 1)
        self._connect_filters()

    # ------------------------------------------------------------- 加载
    def refresh(self) -> None:
        self._loaded = load_history(self._log_directory, max_bytes=DEFAULT_MAX_BYTES)
        self._limit = PAGE_SIZE
        self._apply_filters()
        self._summary.setText(self._summary_text())

    def _summary_text(self) -> str:
        loaded = self._loaded
        if loaded is None:
            return "正在读取动作历史…"
        if not loaded.records:
            return (
                f"日志目录：{self._log_directory}\n"
                "暂无动作历史（执行层动作默认关闭；执行过动作后这里会显示记录）。"
            )
        text = (
            f"日志目录：{self._log_directory}｜读取 {loaded.files_read} 个文件（{loaded.bytes_read} 字节）"
            f"｜记录 {len(loaded.records)} 条，会话 {len(loaded.sessions)} 个"
            f"｜跳过坏行 {loaded.skipped_lines} 行｜只读"
        )
        if loaded.truncated:
            text += "｜⚠ 日志较大，仅载入最新部分"
        unfinished = incomplete_sessions(loaded.sessions)
        if unfinished:
            text += f"｜⚠ 未完成会话 {len(unfinished)} 个（可能中断，仅提示）"
        return text

    def _current_filters(self) -> tuple[str, str, str]:
        return (
            str(self._action_combo.currentData() or ""),
            str(self._result_combo.currentData() or ""),
            self._search_edit.text(),
        )

    def _apply_filters(self) -> None:
        if self._loaded is None:
            return
        action, result, search = self._current_filters()
        self._filtered = filter_records(
            self._loaded.records, action=action or None, result=result or None, search=search
        )
        self._limit = PAGE_SIZE
        self._render()

    def _render(self) -> None:
        shown = self._filtered[: self._limit]
        self._model.set_records(list(shown))
        self._btn_load_more.setEnabled(len(self._filtered) > len(shown))
        if self._loaded is not None and self._loaded.records:
            self._summary.setText(
                self._summary_text()
                + f"｜当前筛选 {len(self._filtered)} 条，显示 {len(shown)} 条"
            )

    def _load_more(self) -> None:
        self._limit += PAGE_SIZE
        self._render()

    def _show_detail(self, current, previous=None) -> None:
        record = self._model.record_at(current)
        if record is None:
            self._detail.clear()
            return
        self._detail.setPlainText(json.dumps(record.raw, ensure_ascii=False, indent=2))

    def _open_log_directory(self) -> None:
        ok, error = open_containing_folder(str(self._log_directory))
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    # 槽：筛选条件变化
    def _on_filter_changed(self) -> None:
        self._limit = PAGE_SIZE
        self._apply_filters()

    def _connect_filters(self) -> None:
        self._action_combo.currentIndexChanged.connect(self._on_filter_changed)
        self._result_combo.currentIndexChanged.connect(self._on_filter_changed)
        self._search_edit.textChanged.connect(self._on_filter_changed)
