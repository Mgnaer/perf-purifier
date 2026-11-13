"""大文件排行页（模块 B · 阶段 1C，只读）。

数据来自“重复文件”页触发的同一次文件扫描；本页只展示与导出，不删除文件。
"""

from __future__ import annotations

import logging

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ...core.config import AppConfig, default_export_dir
from ...core.fmt import human_bytes, human_duration_ms, now_text
from ...core.models import FileScanResult
from ...core.shell import open_containing_folder
from ...module_b.report import export_large_files_csv
from ..models.file_models import LargeFileTableModel

logger = logging.getLogger(__name__)


class LargeFilesPage(QWidget):
    status_message = Signal(str)
    refresh_requested = Signal(str)

    def __init__(self, config: AppConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._config = config
        self._result: FileScanResult | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self._btn_refresh = QPushButton("重新扫描")
        self._btn_refresh.clicked.connect(lambda: self.refresh_requested.emit("large_files"))
        self._btn_export = QPushButton("导出 CSV")
        self._btn_export.setEnabled(False)
        self._btn_export.clicked.connect(self.export_csv)
        self._btn_open = QPushButton("打开所在目录")
        self._btn_open.clicked.connect(self._open_selected)
        toolbar.addWidget(self._btn_refresh)
        toolbar.addWidget(self._btn_export)
        toolbar.addWidget(self._btn_open)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        self._hint = QLabel("尚未扫描：请到“重复文件”页选择目录并开始扫描。")
        self._hint.setWordWrap(True)
        self._hint.setStyleSheet("color: palette(dark); font-size: 11px;")
        layout.addWidget(self._hint)

        self._model = LargeFileTableModel(self)
        self._view = QTableView()
        self._view.setModel(self._model)
        self._view.setAlternatingRowColors(True)
        self._view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._view.setWordWrap(False)
        self._view.doubleClicked.connect(self._on_double_clicked)
        header = self._view.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._view.setColumnWidth(0, 56)
        self._view.setColumnWidth(1, 620)
        self._view.setColumnWidth(2, 110)
        self._view.setColumnWidth(3, 150)
        layout.addWidget(self._view, 1)

    # ------------------------------------------------------------- 对外 API
    def set_result(self, result: FileScanResult | None) -> None:
        self._result = result
        if result is None:
            self._model.set_files([])
            self._btn_export.setEnabled(False)
            self._hint.setText("尚未扫描：请到“重复文件”页选择目录并开始扫描。")
            return
        self._model.set_files(result.large_files)
        self._btn_export.setEnabled(bool(result.large_files))
        self._hint.setText(
            f"扫描目录：{result.root}　共 {result.files_scanned} 个文件，"
            f"{human_bytes(result.total_bytes)}，按大小显示 Top {len(result.large_files)}；"
            f"用时 {human_duration_ms(result.duration_ms)}。双击行可打开所在目录。"
        )

    # ------------------------------------------------------------- 动作
    def _selected_file(self):
        return self._model.file_at(self._view.currentIndex())

    def _on_double_clicked(self, index) -> None:
        item = self._model.file_at(index)
        if item is None:
            return
        ok, error = open_containing_folder(item.path)
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    def _open_selected(self) -> None:
        item = self._selected_file()
        if item is None:
            QMessageBox.information(self, "未选择", "请先在表格中选择一个文件。")
            return
        ok, error = open_containing_folder(item.path)
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    def export_csv(self) -> None:
        if self._result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次文件扫描再导出。")
            return
        try:
            export_dir = default_export_dir()
            export_dir.mkdir(parents=True, exist_ok=True)
            suggested = str(export_dir / f"大文件排行_{now_text()}.csv")
        except OSError:
            suggested = f"大文件排行_{now_text()}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "导出大文件 CSV", suggested, "CSV 文件 (*.csv)")
        if not path:
            return
        if not path.casefold().endswith(".csv"):
            path += ".csv"
        ok, message = export_large_files_csv(path, self._result)
        if ok:
            self.status_message.emit(f"已导出大文件排行：{path}")
            QMessageBox.information(self, "导出成功", f"{message}\n\n文件：{path}")
        else:
            QMessageBox.critical(self, "导出失败", message)
