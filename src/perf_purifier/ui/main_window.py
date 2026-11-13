"""主窗口：顶部安全横幅 + 五个标签页 + 状态栏 + 菜单。

阶段 1B：进程血缘 / 网络连接 / 临时占用三页可用；重复文件、大文件排行仍为 1C 占位。
任何页面都不提供结束进程 / 删除文件 / 建立硬链接入口。
"""

from __future__ import annotations

import logging

from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __app_name__, __version__
from ..core.config import AppConfig, default_export_dir
from ..core.fmt import human_bytes, human_duration_ms, now_text
from ..core.models import ProcessScanResult, Severity, completeness_label
from ..core.relaunch import relaunch_as_admin
from ..core.whitelist import Whitelist
from ..module_a.report import export_report_html
from .dialogs.disclaimer_dialog import DisclaimerDialog
from .pages.page_connections import ConnectionsPage
from .pages.page_duplicates import DuplicatesPage
from .pages.page_history import HistoryPage
from .pages.page_large_files import LargeFilesPage
from .pages.page_process_tree import ProcessTreePage
from .pages.page_settings import SettingsPage
from .pages.page_space import SpacePage
from .pages.page_temp import TempPage

logger = logging.getLogger(__name__)

_BANNER_ADMIN = (
    "扫描/展示为只读；执行层（删除到回收站 / 硬链接去重 / 结束进程 / 磁盘垃圾清理）默认关闭，"
    "开启需手工编辑配置并重启，且每次执行前需二次确认。"
)
_BANNER_NORMAL = (
    "⚠ 当前以普通用户运行：部分进程详情/网络数据不可读，数据完整度会显示“部分”。"
    "建议以管理员身份重新运行以获得更完整数据（本版本不会自动提权）。"
    "执行层默认关闭；系统级磁盘清理需要管理员权限。"
)


class MainWindow(QMainWindow):
    def __init__(
        self,
        config: AppConfig,
        whitelist: Whitelist,
        *,
        is_admin: bool,
        logger: logging.Logger,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._logger = logger
        self._is_admin = is_admin
        self._last_result: ProcessScanResult | None = None

        self.setWindowTitle(f"{__app_name__} {__version__} — 只读扫描 · 安全执行（默认关闭）")
        self.resize(1360, 840)
        self.setMinimumSize(1120, 700)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        banner = QLabel(_BANNER_ADMIN if is_admin else _BANNER_NORMAL)
        banner.setWordWrap(True)
        banner.setStyleSheet(
            """
            QLabel {
                padding: 8px 12px;
                background: #e8f5e9;
                color: #1b5e20;
                border-bottom: 1px solid #a5d6a7;
            }
            """
            if is_admin
            else """
            QLabel {
                padding: 8px 12px;
                background: #fff4e5;
                color: #7a4a00;
                border-bottom: 1px solid #f0b429;
            }
            """
        )
        layout.addWidget(banner)
        self._btn_relaunch: QPushButton | None = None
        if not is_admin:
            relaunch_row = QHBoxLayout()
            relaunch_row.setContentsMargins(8, 4, 8, 4)
            self._btn_relaunch = QPushButton("以管理员身份重新启动…")
            self._btn_relaunch.setToolTip(
                "仅在你需要更完整的进程/网络数据时使用：会先二次确认，"
                "然后由系统弹出 UAC 授权窗口；当前窗口将关闭，扫描结果会丢失。程序不会自动提权。"
            )
            self._btn_relaunch.clicked.connect(self._on_relaunch_as_admin)
            relaunch_row.addWidget(self._btn_relaunch)
            relaunch_row.addStretch(1)
            layout.addLayout(relaunch_row)

        self._tabs = QTabWidget()
        self._page_process = ProcessTreePage(
            config,
            whitelist,
            is_admin=is_admin,
            app_version=__version__,
            parent=self._tabs,
        )
        self._page_connections = ConnectionsPage(config, parent=self._tabs)
        self._page_temp = TempPage(
            config,
            is_admin=is_admin,
            app_version=__version__,
            parent=self._tabs,
        )
        self._page_duplicates = DuplicatesPage(
            config,
            is_admin=is_admin,
            app_version=__version__,
            parent=self._tabs,
        )
        self._page_large = LargeFilesPage(config, parent=self._tabs)
        self._page_space = SpacePage(
            config,
            is_admin=is_admin,
            app_version=__version__,
            parent=self._tabs,
        )
        self._page_history = HistoryPage(parent=self._tabs)
        self._page_settings = SettingsPage(
            config,
            is_admin=is_admin,
            app_version=__version__,
            parent=self._tabs,
        )
        self._page_settings.actions_disabled.connect(self._on_actions_disabled)
        self._tabs.addTab(self._page_process, "进程血缘")
        self._tabs.addTab(self._page_connections, "网络连接")
        self._tabs.addTab(self._page_temp, "临时占用")
        self._tabs.addTab(self._page_duplicates, "重复文件")
        self._tabs.addTab(self._page_large, "大文件排行")
        self._tabs.addTab(self._page_space, "磁盘空间")
        self._tabs.addTab(self._page_history, "动作历史")
        self._tabs.addTab(self._page_settings, "设置")
        layout.addWidget(self._tabs, 1)
        self.setCentralWidget(central)

        self._build_menu()
        self._build_statusbar()
        self._connect_signals()

    # -------------------------------------------------------------- 菜单
    def process_page(self) -> ProcessTreePage:
        """供冒烟脚本/测试访问各页面。"""

        return self._page_process

    def connections_page(self) -> ConnectionsPage:
        return self._page_connections

    def temp_page(self) -> TempPage:
        return self._page_temp

    def duplicates_page(self) -> DuplicatesPage:
        return self._page_duplicates

    def large_files_page(self) -> LargeFilesPage:
        return self._page_large

    def space_page(self) -> SpacePage:
        return self._page_space

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("文件(&F)")

        self._action_refresh = QAction("重新扫描(&R)", self)
        self._action_refresh.setShortcut("F5")
        self._action_refresh.triggered.connect(self._page_process.refresh)
        file_menu.addAction(self._action_refresh)

        file_menu.addSeparator()
        self._action_csv = QAction("导出进程树 CSV…", self)
        self._action_csv.setShortcut("Ctrl+E")
        self._action_csv.setEnabled(False)
        self._action_csv.triggered.connect(self._page_process.export_csv)
        file_menu.addAction(self._action_csv)

        self._action_json = QAction("导出扫描 JSON…", self)
        self._action_json.setShortcut("Ctrl+Shift+E")
        self._action_json.setEnabled(False)
        self._action_json.triggered.connect(self._page_process.export_json)
        file_menu.addAction(self._action_json)

        self._action_html = QAction("导出 HTML 报告…", self)
        self._action_html.setShortcut("Ctrl+H")
        self._action_html.setEnabled(False)
        self._action_html.triggered.connect(self._export_html)
        file_menu.addAction(self._action_html)

        file_menu.addSeparator()
        action_quit = QAction("退出(&Q)", self)
        action_quit.setShortcut("Ctrl+Q")
        action_quit.triggered.connect(self.close)
        file_menu.addAction(action_quit)

        help_menu = self.menuBar().addMenu("帮助(&H)")
        action_disclaimer = QAction("免责声明 / 使用须知…", self)
        action_disclaimer.triggered.connect(self._show_disclaimer)
        help_menu.addAction(action_disclaimer)
        action_about = QAction("关于…", self)
        action_about.triggered.connect(self._show_about)
        help_menu.addAction(action_about)

    def _build_statusbar(self) -> None:
        status_bar = self.statusBar()
        self._label_stage = QLabel("就绪")
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedWidth(180)
        self._progress_bar.setFixedHeight(10)
        self._label_readonly = QLabel("默认只读 · 执行层默认关闭（删除只进回收站）")
        self._label_completeness = QLabel("数据完整度：—")
        self._label_elapsed = QLabel("用时：—")
        status_bar.addPermanentWidget(self._label_stage)
        status_bar.addPermanentWidget(self._progress_bar)
        status_bar.addPermanentWidget(self._label_elapsed)
        status_bar.addPermanentWidget(self._label_completeness)
        status_bar.addPermanentWidget(self._label_readonly)
        status_bar.showMessage("就绪：点击“开始扫描”生成只读检查结果")

    def _connect_signals(self) -> None:
        page = self._page_process
        page.status_message.connect(self.statusBar().showMessage)
        page.result_ready.connect(self._on_result_ready)
        page.scan_started.connect(self._on_scan_started)
        page.scan_progress.connect(self._on_scan_progress)
        page.scan_finished.connect(self._on_scan_finished)
        page.scan_stopped.connect(self._on_scan_stopped)
        self._page_connections.refresh_requested.connect(self._request_scan)
        self._page_temp.refresh_requested.connect(self._request_scan)
        self._page_connections.status_message.connect(self.statusBar().showMessage)
        self._page_temp.status_message.connect(self.statusBar().showMessage)
        self._page_duplicates.status_message.connect(self.statusBar().showMessage)
        self._page_large.status_message.connect(self.statusBar().showMessage)
        self._page_space.status_message.connect(self.statusBar().showMessage)
        self._page_duplicates.scan_finished.connect(self._page_large.set_result)
        self._page_duplicates.result_ready.connect(
            lambda ready: self._page_large.set_result(
                self._page_duplicates.current_result() if ready else None
            )
        )
        self._page_large.refresh_requested.connect(self._request_file_scan)

    def _request_file_scan(self, reason: str) -> None:
        self._logger.info("来自大文件页的文件扫描请求：%s", reason)
        self._tabs.setCurrentWidget(self._page_duplicates)
        self._page_duplicates.start_scan()

    # ------------------------------------------------------------ 扫描联动
    def _request_scan(self, reason: str) -> None:
        self._logger.info("来自其他页面的扫描请求：%s", reason)
        self._tabs.setCurrentWidget(self._page_process)
        self._page_process.refresh()

    def _on_scan_started(self) -> None:
        self._last_result = None
        self._progress_bar.setValue(0)
        self._label_stage.setText("正在扫描…")
        self._label_completeness.setText("数据完整度：扫描中…")
        self._label_elapsed.setText("用时：—")
        self._page_connections.set_busy(True)
        self._page_temp.set_busy(True)
        self._action_html.setEnabled(False)

    def _on_scan_progress(self, percent: int, text: str) -> None:
        self._progress_bar.setValue(max(0, min(100, percent)))
        if text:
            self._label_stage.setText(text)

    def _on_scan_finished(self, result: ProcessScanResult) -> None:
        self._last_result = result
        tree = result.tree
        self._label_stage.setText("扫描完成")
        self._progress_bar.setValue(100)
        self._label_completeness.setText(f"数据完整度：{completeness_label(tree.completeness)}")
        self._label_elapsed.setText(f"用时：{human_duration_ms(result.duration_ms)}")
        self._action_html.setEnabled(True)
        self._page_connections.set_result(result)
        self._page_temp.set_result(result)
        self._page_connections.set_busy(False)
        self._page_temp.set_busy(False)
        network = result.connections
        temp = result.temp
        network_text = (
            f"，网络连接 {len(network.connections)} 条（需核实 {network.review_count}）"
            if network is not None
            else ""
        )
        temp_text = f"，临时文件 {human_bytes(temp.total_size)}" if temp is not None else ""
        self.statusBar().showMessage(
            f"扫描完成：{tree.total_processes} 个进程，"
            f"{tree.count_at_least(Severity.NOTICE)} 个命中关注及以上规则"
            f"{network_text}{temp_text}，用时 {human_duration_ms(result.duration_ms)}",
            15_000,
        )

    def _on_scan_stopped(self) -> None:
        self._label_stage.setText("已停止")
        self._page_connections.set_busy(False)
        self._page_temp.set_busy(False)

    def _on_result_ready(self, ready: bool) -> None:
        self._action_csv.setEnabled(ready)
        self._action_json.setEnabled(ready)
        if not ready:
            self._action_html.setEnabled(False)

    # ------------------------------------------------------------ 导出/帮助
    def _export_html(self) -> None:
        result = self._last_result or self._page_process.current_result()
        if result is None:
            QMessageBox.information(self, "暂无数据", "请先完成一次扫描再导出。")
            return
        try:
            export_dir = default_export_dir()
            export_dir.mkdir(parents=True, exist_ok=True)
            suggested = str(export_dir / f"性能与净化报告_{now_text()}.html")
        except OSError:
            suggested = f"性能与净化报告_{now_text()}.html"
        path, _ = QFileDialog.getSaveFileName(self, "导出 HTML 报告", suggested, "HTML 文件 (*.html)")
        if not path:
            return
        if not path.casefold().endswith(".html"):
            path += ".html"
        ok, message = export_report_html(path, result, self._config)
        if ok:
            self.statusBar().showMessage(f"已导出 HTML 报告：{path}", 15_000)
            QMessageBox.information(self, "导出成功", f"{message}\n\n文件：{path}")
        else:
            QMessageBox.critical(self, "导出失败", message)

    def _show_disclaimer(self) -> None:
        DisclaimerDialog(self).exec()

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            f"关于 {__app_name__}",
            f"<b>{__app_name__}</b> v{__version__}<br><br>"
            "本地只读系统检查工具 + 安全执行层（默认关闭）：<br>"
            "进程血缘 / 网络连接 / 临时占用 / 重复文件 / 大文件排行 / 磁盘空间（垃圾清理）。<br>"
            "本工具不是杀毒软件，启发式标记可能误报。<br>"
            "当前版本不结束进程、不删除文件、不建立硬链接、不联网上传数据；"
            "执行层动作默认关闭且只调用回收站。<br><br>"
            "PySide6 + psutil · 仅在本机运行",
        )

    # ------------------------------------------------------------ 设置页联动
    def _on_actions_disabled(self) -> None:
        """设置页一键关闭执行层开关后，刷新各动作页的按钮状态。"""

        for page in (
            self._page_process,
            self._page_temp,
            self._page_duplicates,
            self._page_space,
        ):
            refresh = getattr(page, "refresh_action_switches", None)
            if callable(refresh):
                refresh()
        self._logger.info("设置页：已关闭全部执行层开关")
        self.statusBar().showMessage(
            "已关闭全部执行层开关（如需重新开启请手工编辑 config.json 并重启程序）", 8000
        )

    # ------------------------------------------------------------ 管理员重启
    def _on_relaunch_as_admin(self) -> None:
        """显式请求以管理员身份重启；单次、可失败、不自动提权。"""

        for page in (self._page_process, self._page_temp, self._page_duplicates, self._page_space):
            if page.is_action_running():
                QMessageBox.warning(
                    self,
                    "动作执行中",
                    "当前有执行层动作正在运行，不能重启。\n请等待动作完成或取消后再试。",
                )
                return
        answer = QMessageBox.warning(
            self,
            "以管理员身份重新启动？",
            "将关闭当前窗口并重新启动本程序（请求管理员权限）：\n\n"
            "• 当前扫描结果与选择会丢失；\n"
            "• 管理员权限可获得更完整的进程/网络数据，提高扫描与动作成功率；\n"
            "• 随后由系统弹出 UAC 授权窗口（由系统控制），你可以拒绝；\n"
            "• 本程序不会自动提权，也不会循环弹窗。\n\n"
            "是否继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        started, error = relaunch_as_admin()
        if not started:
            QMessageBox.information(self, "未重启", error)
            self._logger.info("管理员重启未完成：%s", error)
            return
        self._logger.info("已请求以管理员身份重新启动，关闭当前窗口")
        self.close()

    # ------------------------------------------------------------ 关闭
    def closeEvent(self, event: QCloseEvent) -> None:
        if self._page_process.is_scanning():
            self._logger.info("窗口关闭：请求取消进程扫描并等待线程退出")
            self._page_process.cancel_scan()
            stopped = self._page_process.wait_for_stop(3000)
            if not stopped:
                self._logger.warning("扫描线程 3 秒内未退出，仍继续关闭窗口")
        if self._page_duplicates.is_scanning():
            self._logger.info("窗口关闭：请求取消文件扫描并等待线程退出")
            self._page_duplicates.cancel_scan()
            stopped = self._page_duplicates.wait_for_stop(3000)
            if not stopped:
                self._logger.warning("文件扫描线程 3 秒内未退出，仍继续关闭窗口")
        if self._page_temp.is_action_running():
            self._logger.info("窗口关闭：请求取消 Temp 删除动作并等待线程退出")
            self._page_temp.cancel_action()
            if not self._page_temp.wait_action(3000):
                self._logger.warning("删除动作线程 3 秒内未退出，仍继续关闭窗口")
        if self._page_duplicates.is_action_running():
            self._logger.info("窗口关闭：请求取消硬链接动作并等待线程退出")
            self._page_duplicates.cancel_action()
            if not self._page_duplicates.wait_action(3000):
                self._logger.warning("硬链接动作线程 3 秒内未退出，仍继续关闭窗口")
        if self._page_space.is_scanning():
            self._logger.info("窗口关闭：请求取消磁盘空间扫描并等待线程退出")
            self._page_space.cancel_scan()
            if not self._page_space.wait_scan(3000):
                self._logger.warning("磁盘空间扫描线程 3 秒内未退出，仍继续关闭窗口")
        if self._page_space.is_action_running():
            self._logger.info("窗口关闭：请求取消磁盘清理动作并等待线程退出")
            self._page_space.cancel_action()
            if not self._page_space.wait_action(3000):
                self._logger.warning("磁盘清理线程 3 秒内未退出，仍继续关闭窗口")
        if self._page_process.is_action_running():
            self._logger.info("窗口关闭：请求取消结束进程动作并等待线程退出")
            self._page_process.cancel_action()
            if not self._page_process.wait_action(3000):
                self._logger.warning("结束进程动作线程 3 秒内未退出，仍继续关闭窗口")
        event.accept()
        super().closeEvent(event)
