"""扫描进度条 + 状态文案（不阻塞 UI，仅展示 job 信号）。"""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QProgressBar, QVBoxLayout, QWidget


class ScanProgressBar(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(8)
        self._label = QLabel("就绪：点击“开始扫描”生成只读进程快照")
        self._label.setStyleSheet("color: palette(dark); font-size: 11px;")
        layout.addWidget(self._bar)
        layout.addWidget(self._label)

    def value(self) -> int:
        return self._bar.value()

    def set_idle(self, text: str = "就绪") -> None:
        self._bar.setValue(0)
        self._label.setText(text)

    def set_running(self, text: str = "正在扫描…") -> None:
        self._bar.setValue(0)
        self._label.setText(text)

    def set_progress(self, percent: int, text: str = "") -> None:
        self._bar.setValue(max(0, min(100, percent)))
        if text:
            self._label.setText(text)

    def set_finished(self, text: str) -> None:
        self._bar.setValue(100)
        self._label.setText(text)
