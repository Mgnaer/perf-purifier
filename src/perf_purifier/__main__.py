"""``python -m perf_purifier`` 入口（需要 src 在 sys.path 或已安装本包）。"""

from __future__ import annotations

from .app import main

if __name__ == "__main__":
    raise SystemExit(main())
