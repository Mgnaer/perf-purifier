"""首次运行免责声明对话框。

必须在用户第一次启动时展示，并明确：
* 本工具不是杀毒软件，启发式标记可能误报；
* 默认只读；执行层（回收站删除 / 硬链接 / 结束进程 / 磁盘清理）默认关闭，需手工开启；
* 删除只进回收站、失败不回退永久删除；数据仅保存在本机、不联网上传。
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

_DISCLAIMER_HTML = """
<h3>这不是杀毒软件</h3>
<p>“可疑/高风险”均来自<strong>启发式规则</strong>（路径、命令行、进程血缘等），
只代表“值得人工核实”，<strong>不构成恶意软件结论</strong>，也可能误报。</p>

<h3>默认只读，执行层默认关闭</h3>
<ul>
  <li>扫描 / 展示 / 导出全部只读，不需要任何开关；</li>
  <li>删除文件（含磁盘垃圾清理）、建立/拆解硬链接、结束进程默认<strong>全部关闭</strong>；</li>
  <li>开启必须<strong>手工编辑</strong> <code>config.json</code> 并重启程序，
      且首次使用需先“预演”、执行前需二次确认；</li>
  <li>删除<strong>只调用回收站</strong>（可在回收站还原），失败只报告，
      <strong>绝不</strong>回退为永久删除；</li>
  <li>不自动提权、不修改系统设置。</li>
</ul>
<p>导出仅为 CSV / JSON / HTML 报告文件，由你自行选择保存位置。</p>

<h3>数据只在本机</h3>
<p>程序不联网、不上传扫描结果；日志与配置保存在
<code>%LOCALAPPDATA%\\PerfPurifier\\</code>，动作审计写入
<code>operations.jsonl</code>。</p>

<h3>权限说明</h3>
<p>普通用户权限下部分进程详情不可读（数据完整度会显示“部分”）；
“系统级”磁盘清理规则需要管理员权限（本程序不会自动提权）。</p>
"""


class DisclaimerDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.accepted = False
        self.setWindowTitle("使用前须知 — 性能与净化")
        self.setMinimumSize(640, 480)

        layout = QVBoxLayout(self)
        title = QLabel("使用前须知")
        title_font = title.font()
        title_font.setPointSize(max(13, title_font.pointSize() + 4))
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        browser = QTextBrowser()
        browser.setHtml(_DISCLAIMER_HTML)
        browser.setOpenExternalLinks(False)
        layout.addWidget(browser, 1)

        buttons = QDialogButtonBox()
        buttons.addButton("我已知晓（默认只读，执行层需手动开启）", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton("退出", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        self.accepted = True
        self.accept()
