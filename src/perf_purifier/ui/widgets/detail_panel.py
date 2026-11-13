"""进程详情面板：基本信息 + 风险标记证据 + 只读辅助动作。

注意：面板内**不存在**结束进程/删除文件按钮——阶段 1 只读。
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...core.config import AppConfig
from ...core.fmt import format_status, format_timestamp, human_bytes
from ...core.models import (
    ProcessNode,
    severity_color,
    severity_label,
    signature_label,
)
from ...core.shell import open_containing_folder

_FIELDS: tuple[str, ...] = (
    "PID",
    "父进程",
    "可执行文件",
    "用户",
    "状态",
    "创建时间",
    "内存",
    "签名",
)


class DetailPanel(QWidget):
    def __init__(self, config: AppConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._config = config
        self._node: ProcessNode | None = None
        self._build_ui()
        self.show_node(None)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)

        self._title = QLabel("未选择进程")
        title_font = self._title.font()
        title_font.setPointSize(max(12, title_font.pointSize() + 3))
        title_font.setBold(True)
        self._title.setFont(title_font)
        self._title.setWordWrap(True)
        self._subtitle = QLabel("在左侧进程树中点击任意进程查看详情")
        self._subtitle.setWordWrap(True)
        self._subtitle.setStyleSheet("color: palette(dark);")
        outer.addWidget(self._title)
        outer.addWidget(self._subtitle)

        info_box = QGroupBox("基本信息")
        form = QFormLayout(info_box)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._labels: dict[str, QLabel] = {}
        for field in _FIELDS:
            value_label = QLabel("—")
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            form.addRow(f"{field}：", value_label)
            self._labels[field] = value_label
        outer.addWidget(info_box)

        risk_box = QGroupBox("风险标记（启发式提示，不构成安全结论）")
        risk_layout = QVBoxLayout(risk_box)
        self._risk_list = QListWidget()
        self._risk_list.setAlternatingRowColors(True)
        self._risk_list.setMinimumHeight(120)
        risk_layout.addWidget(self._risk_list)
        self._risk_hint = QLabel("证据为规则命中原值，可能误报；敏感命令行已脱敏。")
        self._risk_hint.setWordWrap(True)
        self._risk_hint.setStyleSheet("color: palette(dark); font-size: 11px;")
        risk_layout.addWidget(self._risk_hint)
        outer.addWidget(risk_box)

        actions = QHBoxLayout()
        self._btn_open = QPushButton("打开所在目录")
        self._btn_open.clicked.connect(self._open_folder)
        self._btn_copy = QPushButton("复制路径")
        self._btn_copy.clicked.connect(self._copy_path)
        actions.addWidget(self._btn_open)
        actions.addWidget(self._btn_copy)
        actions.addStretch(1)
        outer.addLayout(actions)

        readonly_hint = QLabel("阶段 1 为只读检查模式：本界面不提供结束进程 / 删除文件操作。")
        readonly_hint.setWordWrap(True)
        readonly_hint.setStyleSheet("color: palette(dark); font-size: 11px;")
        outer.addWidget(readonly_hint)
        outer.addStretch(1)

    # --------------------------------------------------------------- 数据
    def show_node(
        self,
        node: ProcessNode | None,
        parent_node: ProcessNode | None = None,
    ) -> None:
        self._node = node
        if node is None:
            self._title.setText("未选择进程")
            self._subtitle.setText("在左侧进程树中点击任意进程查看详情")
            for label in self._labels.values():
                label.setText("—")
            self._risk_list.clear()
            placeholder = QListWidgetItem("未选择进程")
            placeholder.setForeground(QColor("#6b7280"))
            self._risk_list.addItem(placeholder)
            self._btn_open.setEnabled(False)
            self._btn_copy.setEnabled(False)
            return

        info = node.info
        self._title.setText(f"{info.display_name}  (PID {info.pid})")
        subtitle = f"父 PID：{info.ppid if info.ppid >= 0 else '不可读'}"
        if node.orphaned:
            subtitle += "　孤儿进程（父进程已退出或 PID 被复用）"
        self._subtitle.setText(subtitle)

        parent_text = "不可读"
        if node.parent_pid is not None:
            if parent_node is not None:
                parent_text = f"{parent_node.info.display_name} (PID {parent_node.pid})"
            else:
                parent_text = f"PID {node.parent_pid}（不在快照中）"
        memory_text = f"{human_bytes(info.rss)} (RSS) / {human_bytes(info.vms)} (虚拟)"
        signature_text = signature_label(info.sig_status)
        if info.sig_publisher:
            signature_text += f"（{info.sig_publisher}）"

        values = {
            "PID": str(info.pid),
            "父进程": parent_text,
            "可执行文件": info.exe or "不可读（权限不足？）",
            "用户": info.username or "不可读（权限不足？）",
            "状态": format_status(info.status),
            "创建时间": format_timestamp(info.create_time),
            "内存": memory_text,
            "签名": signature_text,
        }
        for field, text in values.items():
            self._labels[field].setText(text)

        self._risk_list.clear()
        if not node.flags:
            item = QListWidgetItem("未命中启发式规则（不代表绝对安全，仅表示无已知特征）")
            item.setForeground(QColor("#6b7280"))
            self._risk_list.addItem(item)
        else:
            for flag in node.flags:
                text = f"[{flag.rule_id}] {severity_label(flag.severity)}｜{flag.title}\n    {flag.evidence}"
                item = QListWidgetItem(text)
                item.setForeground(QColor(severity_color(flag.severity)))
                item.setToolTip(flag.evidence)
                self._risk_list.addItem(item)

        self._btn_open.setEnabled(bool(info.exe))
        self._btn_copy.setEnabled(bool(info.exe))

    # ------------------------------------------------------------- 动作
    def _open_folder(self) -> None:
        if self._node is None or not self._node.info.exe:
            return
        ok, error = open_containing_folder(self._node.info.exe)
        if not ok:
            QMessageBox.warning(self, "打开失败", error)

    def _copy_path(self) -> None:
        if self._node is None or not self._node.info.exe:
            return
        QApplication.clipboard().setText(self._node.info.exe)
        self._subtitle.setText(self._subtitle.text() + "　✅ 路径已复制到剪贴板")
