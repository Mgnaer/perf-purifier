"""KPI 摘要卡片条（进程数 / 可疑数 / 高风险 / 孤儿 / 数据完整度）。"""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

_TONE_STYLES: dict[str, str] = {
    "normal": "",
    "warn": "color: #b45309;",
    "danger": "color: #b91c1c;",
    "good": "color: #15803d;",
}


class KpiCard(QFrame):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("kpiCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(1)
        self._title = QLabel(title)
        self._title.setObjectName("kpiTitle")
        self._value = QLabel("—")
        self._value.setObjectName("kpiValue")
        layout.addWidget(self._title)
        layout.addWidget(self._value)
        self.setMinimumWidth(94)

    def set_value(self, text: str, tone: str = "normal") -> None:
        self._value.setText(text)
        self._value.setStyleSheet(_TONE_STYLES.get(tone, ""))


class KpiBar(QWidget):
    """按 key 更新数值的卡片条。"""

    def __init__(self, specs: Sequence[tuple[str, str]], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._cards: dict[str, KpiCard] = {}
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        for key, title in specs:
            card = KpiCard(title)
            self._cards[key] = card
            layout.addWidget(card)
        layout.addStretch(1)
        self.setStyleSheet(
            """
            QFrame#kpiCard {
                background: palette(alternate-base);
                border: 1px solid palette(mid);
                border-radius: 6px;
            }
            QLabel#kpiTitle { color: palette(dark); font-size: 11px; }
            QLabel#kpiValue { font-size: 18px; font-weight: 600; }
            """
        )

    def set_value(self, key: str, text: str, tone: str = "normal") -> None:
        card = self._cards.get(key)
        if card is not None:
            card.set_value(text, tone)

    def reset(self, text: str = "—") -> None:
        for card in self._cards.values():
            card.set_value(text)
