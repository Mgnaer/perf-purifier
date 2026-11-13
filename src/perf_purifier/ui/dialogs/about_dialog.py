"""阶段 5C：关于/安全说明对话框（只读，无任何执行入口）。"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ... import __version__
from ...core.config import APP_NAME, app_data_dir, config_path, log_dir
from ...core.shell import open_containing_folder

_SAFETY_TEXT = (
    "• 扫描/展示为只读；执行层（删除到回收站/硬链接/结束进程）默认关闭，"
    "开启需手工编辑 config.json 并重启；\n"
    "• 每个真实动作都需要：首次预演 + 勾选目标 + 二次确认（结束进程需输入确认词）；\n"
    "• 删除只调用回收站，失败不会改为永久删除；硬链接仅同卷 NTFS 且执行前重算哈希；\n"
    "• 不自动提权、不联网、不上传任何数据、不修改系统设置；\n"
    "• 这不是杀毒软件，风险标记来自启发式规则，可能误报，不构成安全结论。"
)


class AboutDialog(QDialog):
    def __init__(
        self,
        *,
        is_admin: bool,
        app_version: str = "",
        config_file: Path | None = None,
        log_directory: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("关于 / 安全说明")
        self.setMinimumWidth(560)
        self._config_file = config_file or config_path()
        self._log_directory = log_directory or log_dir()

        layout = QVBoxLayout(self)
        title = QLabel(f"{APP_NAME} {app_version or __version__}")
        font = title.font()
        font.setPointSize(font.pointSize() + 3)
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)

        form = QFormLayout()
        form.addRow("运行权限：", QLabel("管理员（提升权限）" if is_admin else "普通用户"))
        form.addRow("配置文件：", self._path_label(self._config_file))
        form.addRow("日志目录：", self._path_label(self._log_directory))
        form.addRow("数据目录：", self._path_label(app_data_dir()))
        layout.addLayout(form)

        safety_title = QLabel("安全边界")
        safety_font = safety_title.font()
        safety_font.setBold(True)
        safety_title.setFont(safety_font)
        layout.addWidget(safety_title)
        safety = QLabel(_SAFETY_TEXT)
        safety.setWordWrap(True)
        safety.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(safety)

        row = QVBoxLayout()
        self._btn_open_docs = QPushButton("打开文档目录")
        self._btn_open_docs.clicked.connect(self._open_docs)
        row.addWidget(self._btn_open_docs)
        layout.addLayout(row)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _path_label(path: Path) -> QLabel:
        label = QLabel(str(path))
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        return label

    def _open_docs(self) -> None:
        docs = Path(__file__).resolve().parents[4] / "docs"
        if not docs.is_dir():
            docs = app_data_dir()
        ok, error = open_containing_folder(str(docs))
        if not ok:
            QMessageBox.warning(self, "打开失败", error)
