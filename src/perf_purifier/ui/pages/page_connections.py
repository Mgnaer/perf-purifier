"""网络连接页（模块 A · 阶段 1B，只读）。

数据来自"进程血缘"页触发的同一次扫描；本页负责筛选、查看与导出，不发起独立扫描。
"""

from __future__ import annotations

import logging

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ...core.config import AppConfig, default_export_dir
from ...core.fmt import now_text
from ...core.models import (
    Completeness,
    ConnectionInfo,
    ProcessScanResult,
    RemoteClass,
    completeness_label,
    remote_class_label,
)
from ...core.shell import open_containing_folder
from ...module_a.report import export_network_csv
from ..models.table_models import ConnectionTableModel
from ..widgets.kpi_bar import KpiBar

logger = logging.getLogger(__name__)

_FILTERS: tuple[tuple[str, str], ...] = (
    ("全部", "all"),
    ("仅公网远端", "public"),
    ("仅需人工核实", "review"),
    ("仅监听中", "listen"),
)


class ConnectionsPage(QWidget):
    refresh_requested = Signal(str)
    status_message = Signal(str)

    def __init__(self, config: AppConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._config = config
        self._result: ProcessScanResult | None = None
        self._all: list[ConnectionInfo] = []
        self._busy = False
        self._build_ui()
        self._refresh_export_state()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self._btn_refresh = QPushButton("重新扫描")
        self._btn_refresh.clicked.connect(lambda: self.refresh_requested.emit("connections"))
        self._filter_combo = QComboBox()
        for text, key in _FILTERS:
            self._filter_combo.addItem(text, key)
        self._filter_combo.currentIndexChanged.connect(self._apply_filter)
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("搜索：进程名 / PID / 远端 IP / 路径 / 原因")
        self._search_edit.setClearButtonEnabled(True)
        self._search_edit.textChanged.connect(self._apply_filter)
        self._btn_export = QPushButton("导出 CSV")
        self._btn_export.clicked.connect(self.export_csv)

        toolbar.addWidget(self._btn_refresh)
        toolbar.addSpacing(8)
        toolbar.addWidget(QLabel("筛选："))
        toolbar.addWidget(self._filter_combo)
        toolbar.addWidget(self._search_edit, 1)
        toolbar.addWidget(self._btn_export)
        layout.addLayout(toolbar)

        self._hint = QLabel("尚未扫描：点击“重新扫描”生成一次完整只读检查（进程 + 网络 + 临时占用）。")
        self._hint.setWordWrap(True)
        self._hint.setStyleSheet("color: palette(dark); font-size: 11px;")
        layout.addWidget(self._hint)

        self._kpi = KpiBar(
            [
                ("total", "连接总数"),
                ("public", "公网连接"),
                ("review", "需人工核实"),
                ("listen", "监听中"),
                ("completeness", "数据完整度"),
            ]
        )
        layout.addWidget(self._kpi)

        self._model = ConnectionTableModel(self)
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
        self._view.setColumnWidth(0, 130)
        self._view.setColumnWidth(1, 64)
        self._view.setColumnWidth(2, 90)
        self._view.setColumnWidth(3, 170)
        self._view.setColumnWidth(4, 170)
        self._view.setColumnWidth(5, 100)
        self._view.setColumnWidth(6, 80)
        self._view.setColumnWidth(7, 88)
        self._view.setColumnWidth(8, 280)
        layout.addWidget(self._view, 1)

    # ------------------------------------------------------------- 对外 API
    def set_result(self, result: ProcessScanResult | None) -> None:
        self._result = result
        if result is None or result.connections is None:
            self._all = []
            self._model.set_connections([])
            self._kpi.reset()
            self._hint.setText(
                "尚未扫描：点击“重新扫描”生成一次完整只读检查（进程 + 网络 + 临时占用）。"
            )
            self._refresh_export_state()
            return
        self._all = list(result.connections.connections)
        network = result.connections
        self._kpi.set_value("total", str(len(self._all)))
        self._kpi.set_value(
            "public", str(network.public_count), "warn" if network.public_count else "normal"
        )
        self._kpi.set_value(
            "review", str(network.review_count), "danger" if network.review_count else "good"
        )
        self._kpi.set_value("listen", str(network.listen_count))
        self._kpi.set_value(
            "completeness",
            completeness_label(network.completeness),
            "good" if network.completeness is Completeness.FULL else "warn",
        )
        hint = (
            "判定口径：公网远端 + 进程不在受信路径（Windows/Program Files）且签名非有效签名"
            "（或无法关联用户进程）时标记为“需人工核实”。离线环境无法可靠识别 CDN，"
            "该标记只是核实提示，不是恶意判定。双击行可打开进程所在目录。"
        )
        if network.kernel_public_count:
            hint += (
                f" 另有 {network.kernel_public_count} 条 PID 0 内核/系统公网连接，"
                "无法归因到用户进程，未计入“需人工核实”。"
            )
        self._hint.setText(hint)
        self._apply_filter()
        self._refresh_export_state()

    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._btn_refresh.setEnabled(not busy)
        self._refresh_export_state()

    def clear(self) -> None:
        self.set_result(None)

    # ------------------------------------------------------------- 过滤/导出
    def _current_filter(self) -> str:
        value = self._filter_combo.currentData()
        return str(value) if value is not None else "all"

    def _apply_filter(self) -> None:
        key = self._current_filter()
        search = self._search_edit.text().strip().casefold()
        filtered: list[ConnectionInfo] = []
        for connection in self._all:
            if key == "public" and connection.remote_class is not RemoteClass.PUBLIC:
                continue
            if key == "review" and not connection.needs_review:
                continue
            if key == "listen" and not connection.is_listen:
                continue
            if search:
                haystack = " ".join(
                    (
                        connection.process_name or "",
                        connection.process_exe or "",
                        str(connection.pid) if connection.pid is not None else "",
                        connection.laddr.text if connection.laddr else "",
                        connection.raddr.text if connection.raddr else "",
                        connection.status,
                        connection.review_reason,
                        remote_class_label(connection.remote_class),
                    )
                ).casefold()
                if search not in haystack:
                    continue
            filtered.append(connection)
        self._model.set_connections(filtered)

    def _refresh_export_state(self) -> None:
        self._btn_export.setEnabled(not self._busy and self._result is not None)

    def _on_double_clicked(self, index) -> None:
        connection = self._model.connection_at(index)
        if connection is None:
            return
        exe = connection.process_exe
        if not exe:
            QMessageBox.information(self, "无法定位", "该进程的可执行文件路径不可读（可能需要管理员权限）。")
            return
        ok, error = open_containing_folder(exe)
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    def export_csv(self) -> None:
        if self._result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次扫描再导出。")
            return
        try:
            export_dir = default_export_dir()
            export_dir.mkdir(parents=True, exist_ok=True)
            suggested = str(export_dir / f"网络连接_{now_text()}.csv")
        except OSError:
            suggested = f"网络连接_{now_text()}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "导出网络连接 CSV", suggested, "CSV 文件 (*.csv)")
        if not path:
            return
        if not path.casefold().endswith(".csv"):
            path += ".csv"
        ok, message = export_network_csv(path, self._result)
        if ok:
            self.status_message.emit(f"已导出网络连接：{path}")
            QMessageBox.information(self, "导出成功", f"{message}\n\n文件：{path}")
        else:
            QMessageBox.critical(self, "导出失败", message)
