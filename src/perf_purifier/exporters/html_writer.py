"""HTML 报告写出原语。

约束：
* 完全自包含（内联 CSS、无外部资源、无 JS 依赖），断网可读；
* 所有动态内容由调用方用 ``html.escape`` 处理后再传入；
* 使用 ``<details>`` 折叠长表格，避免报告过长。
"""

from __future__ import annotations

from pathlib import Path

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px 32px 48px;
  font-family: "Microsoft YaHei UI", "Segoe UI", "Noto Sans CJK SC", sans-serif;
  font-size: 13px; line-height: 1.55; color: #1f2937; background: #f8fafc;
}
h1 { font-size: 22px; margin: 0 0 6px; }
h2 { font-size: 16px; margin: 28px 0 10px; padding-bottom: 6px; border-bottom: 2px solid #e5e7eb; }
.meta { color: #6b7280; font-size: 12px; margin-bottom: 16px; }
.badges { margin: 10px 0 4px; }
.badge {
  display: inline-block; margin: 0 8px 6px 0; padding: 2px 10px;
  border-radius: 999px; font-size: 12px; border: 1px solid #d1d5db; background: #fff;
}
.badge.readonly { border-color: #86efac; background: #f0fdf4; color: #166534; }
.badge.warn { border-color: #fcd34d; background: #fffbeb; color: #92400e; }
.badge.admin { border-color: #93c5fd; background: #eff6ff; color: #1d4ed8; }
.cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0 4px; }
.card {
  min-width: 130px; padding: 10px 14px; border: 1px solid #e5e7eb;
  border-radius: 8px; background: #fff;
}
.card .num { font-size: 20px; font-weight: 600; }
.card .label { font-size: 12px; color: #6b7280; }
table { width: 100%; border-collapse: collapse; background: #fff; margin: 8px 0 4px; }
th, td { border: 1px solid #e5e7eb; padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: #f1f5f9; font-weight: 600; white-space: nowrap; }
tr:nth-child(even) td { background: #fafcff; }
.s-high { color: #b91c1c; font-weight: 600; }
.s-suspicious { color: #c2410c; font-weight: 600; }
.s-notice { color: #b45309; }
.s-info { color: #6b7280; }
.review { color: #b91c1c; font-weight: 600; }
.mono { font-family: Consolas, "Courier New", monospace; font-size: 12px; word-break: break-all; }
.muted { color: #6b7280; }
details { margin: 8px 0 4px; }
summary { cursor: pointer; color: #1d4ed8; margin-bottom: 6px; }
.notice {
  margin: 16px 0; padding: 10px 14px; border-left: 4px solid #f59e0b;
  background: #fffbeb; color: #78350f;
}
footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 12px; }
"""


def build_html_document(*, title: str, body_html: str, subtitle: str = "") -> str:
    """把正文包装成完整 HTML 文档（标题、内联样式、页脚）。"""

    subtitle_html = f'<div class="meta">{subtitle}</div>' if subtitle else ""
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>{title}</h1>
{subtitle_html}
{body_html}
<footer>
本报告由“性能与净化”（Perf Purifier）只读扫描生成，仅在本机保存；未执行任何删除动作。<br>
工具不是杀毒软件：风险标记来自启发式规则，可能误报，不构成恶意软件结论。
</footer>
</body>
</html>
"""


def write_html(path: str | Path, html_text: str) -> tuple[bool, str]:
    """写入 UTF-8 HTML 文件，返回 ``(是否成功, 说明)``。"""

    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(html_text, encoding="utf-8")
        return True, f"已写入 HTML 报告（{len(html_text)} 字符）"
    except OSError as exc:
        return False, f"写入 HTML 失败：{exc}"
