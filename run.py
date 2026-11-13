"""项目启动脚本：``python run.py``（GUI 入口，无需安装包，自动加入 src 路径）。

命令行版入口见 ``run_cli.py``。默认只读扫描；执行层默认关闭。
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_src_on_path() -> None:
    src = Path(__file__).resolve().parent / "src"
    if src.is_dir() and str(src) not in sys.path:
        sys.path.insert(0, str(src))


def main() -> int:
    _ensure_src_on_path()
    try:
        from perf_purifier.app import main as run_app
    except ModuleNotFoundError as exc:
        missing = getattr(exc, "name", "") or "未知依赖"
        print(f"[PerfPurifier] 缺少依赖：{missing}", file=sys.stderr)
        print("[PerfPurifier] 请先安装依赖：", file=sys.stderr)
        print("  .\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt", file=sys.stderr)
        return 2
    return run_app()


if __name__ == "__main__":
    raise SystemExit(main())
