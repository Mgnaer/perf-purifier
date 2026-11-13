"""命令行启动脚本：``python run_cli.py <命令>``。

与 ``run.py``（GUI 入口）并列；打包时作为 ``perfpurifier-cli`` 单文件入口。
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_src_on_path() -> None:
    if getattr(sys, "frozen", False):
        return
    src = Path(__file__).resolve().parent / "src"
    if src.is_dir() and str(src) not in sys.path:
        sys.path.insert(0, str(src))


def main() -> int:
    _ensure_src_on_path()
    try:
        from perf_purifier.cli import main as cli_main
    except ModuleNotFoundError as exc:
        print(f"[PerfPurifier] 缺少依赖：{exc}", file=sys.stderr)
        print(
            "[PerfPurifier] 请先安装依赖：\n"
            "  python -m pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 2
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
