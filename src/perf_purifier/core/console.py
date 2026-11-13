"""命令行输出层（无 Qt 依赖）：UTF-8 / ANSI 颜色 / 中文对齐表格 / 进度 / 确认。

与 GUI 共用同一套核心模块，但输出走纯文本：
* Windows 控制台自动切 UTF-8 并启用 ANSI 颜色（失败则降级为无色）；
* 输出被重定向（非 TTY）时自动关闭颜色与动态进度，保证日志干净；
* 表格按"东亚全角字符占 2 列"计算宽度，中文列不会错位。
"""

from __future__ import annotations

import ctypes
import os
import shutil
import sys
import unicodedata

_ANSI_CODES = {
    "reset": "0",
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "gray": "90",
}

_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_STD_OUTPUT_HANDLE = -11


def setup_console_utf8() -> None:
    """把控制台代码页切到 UTF-8，并让 Python 流使用 UTF-8 输出。"""

    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
        except Exception:  # noqa: BLE001 - 控制台不可用时静默降级
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - 非标准流（测试替身）保持原样
            pass


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(_STD_OUTPUT_HANDLE)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(
            kernel32.SetConsoleMode(handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        )
    except Exception:  # noqa: BLE001
        return False


def display_width(text: str) -> int:
    """终端显示宽度：东亚宽字符记 2 列。"""

    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def _truncate(text: str, max_width: int) -> str:
    if max_width <= 0:
        return ""
    if display_width(text) <= max_width:
        return text
    out: list[str] = []
    used = 0
    for char in text:
        char_width = 2 if display_width(char) == 2 else 1
        if used + char_width > max_width - 1:
            break
        out.append(char)
        used += char_width
    return "".join(out) + "…"


def _pad(text: str, width: int, align: str = "left") -> str:
    padding = max(0, width - display_width(text))
    if align == "right":
        return " " * padding + text
    if align == "center":
        left = padding // 2
        return " " * left + text + " " * (padding - left)
    return text + " " * padding


class Console:
    """统一的输出/交互入口（便于测试时注入假流）。"""

    def __init__(self, color: str = "auto", stream=None) -> None:
        setup_console_utf8()
        self.stream = stream if stream is not None else sys.stdout
        is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        if color == "never" or os.environ.get("NO_COLOR"):
            self.color = False
        elif color == "always":
            self.color = _enable_windows_ansi()
        else:
            self.color = is_tty and _enable_windows_ansi()
        self._tty = is_tty
        self._progress_active = False

    # ------------------------------------------------------------------ 基础
    def _write(self, text: str = "") -> None:
        print(text, file=self.stream)

    def _style(self, name: str, text: str) -> str:
        if not self.color:
            return text
        code = _ANSI_CODES.get(name)
        return f"\x1b[{code}m{text}\x1b[0m" if code else text

    def reset_line(self) -> None:
        if self._progress_active:
            try:
                self.stream.write("\r\x1b[K")
                self.stream.flush()
            except Exception:  # noqa: BLE001
                pass
            self._progress_active = False

    # ------------------------------------------------------------------ 文本
    def title(self, text: str) -> None:
        self.reset_line()
        self._write()
        self._write(self._style("bold", self._style("cyan", f"  {text}  ")))
        self._write(self._style("gray", "  " + "─" * min(60, max(20, display_width(text) + 6))))

    def section(self, text: str) -> None:
        self.reset_line()
        self._write()
        self._write(self._style("bold", f"◆ {text}"))

    def info(self, text: str) -> None:
        self.reset_line()
        self._write(f"  {text}")

    def ok(self, text: str) -> None:
        self.reset_line()
        self._write(f"  {self._style('green', '✓')} {text}")

    def warn(self, text: str) -> None:
        self.reset_line()
        self._write(f"  {self._style('yellow', '!')} {self._style('yellow', text)}")

    def error(self, text: str) -> None:
        self.reset_line()
        self._write(f"  {self._style('red', '✗')} {self._style('red', text)}")

    def hint(self, text: str) -> None:
        self.reset_line()
        self._write(f"  {self._style('gray', text)}")

    def dim(self, text: str) -> None:
        self.reset_line()
        self._write(f"  {self._style('dim', text)}")

    # ------------------------------------------------------------------ 表格
    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        aligns: list[str] | None = None,
        *,
        min_widths: list[int] | None = None,
    ) -> None:
        if not headers:
            return
        columns = len(headers)
        aligns = aligns or ["left"] * columns
        min_widths = min_widths or [0] * columns
        widths: list[int] = []
        for index, header in enumerate(headers):
            cell_width = display_width(header)
            for row in rows:
                if index < len(row):
                    cell_width = max(cell_width, display_width(str(row[index])))
            widths.append(max(cell_width, min_widths[index] if index < len(min_widths) else 0))

        def render(cells: list[str], *, bold: bool = False) -> str:
            parts = []
            for index in range(columns):
                text = str(cells[index]) if index < len(cells) else ""
                text = _truncate(text, widths[index])
                parts.append(_pad(text, widths[index], aligns[index] if index < len(aligns) else "left"))
            line = "  ".join(parts).rstrip()
            return self._style("bold", line) if bold else line

        self.reset_line()
        self._write("  " + render(headers, bold=True))
        self._write("  " + self._style("gray", "─" * min(200, sum(widths) + 2 * (columns - 1))))
        for row in rows:
            self._write("  " + render([str(item) for item in row]))

    def kv(self, pairs: list[tuple[str, str]]) -> None:
        width = max((display_width(key) for key, _value in pairs), default=0)
        for key, value in pairs:
            self.reset_line()
            self._write(f"  {_pad(key, width)}  {value}")

    # ------------------------------------------------------------------ 进度
    def progress(self, text: str) -> None:
        if not self._tty:
            return
        try:
            columns = shutil.get_terminal_size((100, 24)).columns
        except OSError:
            columns = 100
        line = _truncate(text, max(10, columns - 4))
        try:
            self.stream.write("\r\x1b[K" + "  " + line)
            self.stream.flush()
            self._progress_active = True
        except Exception:  # noqa: BLE001
            pass

    def progress_done(self, text: str = "") -> None:
        self.reset_line()
        if text:
            self.hint(text)

    # ------------------------------------------------------------------ 交互
    def ask_yes_no(self, question: str, *, default: bool = False) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        try:
            answer = input(f"  {question} {suffix} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            self._write()
            return False
        if not answer:
            return default
        return answer in ("y", "yes", "是", "1")

    def ask_phrase(self, question: str, phrase: str) -> bool:
        try:
            answer = input(f"  {question}（请输入「{phrase}」确认）：").strip()
        except (EOFError, KeyboardInterrupt):
            self._write()
            return False
        return answer == phrase


__all__ = ["Console", "display_width", "setup_console_utf8"]
