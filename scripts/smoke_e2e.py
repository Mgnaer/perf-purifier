"""端到端冒烟：无头模式跑一次真实进程扫描 + CSV/JSON 导出。

用途：在没有可视化桌面的环境（CI / 远程会话）验证
采集 -> 建树 -> 评分 -> 信号回主线程 -> 导出 的完整链路。

运行：
    .\\.venv\\Scripts\\python.exe scripts\\smoke_e2e.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from PySide6.QtWidgets import QApplication  # noqa: E402

from perf_purifier.core.config import AppConfig, log_dir  # noqa: E402
from perf_purifier.core.logging_setup import setup_logging  # noqa: E402
from perf_purifier.core.models import Severity  # noqa: E402
from perf_purifier.core.whitelist import Whitelist  # noqa: E402
from perf_purifier.module_a.report import (  # noqa: E402
    export_process_csv,
    export_process_json,
    export_report_html,
)
from perf_purifier.ui.main_window import MainWindow  # noqa: E402

TIMEOUT_S = 120.0


def main() -> int:
    logger = setup_logging(log_dir())
    app = QApplication([])
    window = MainWindow(AppConfig(), Whitelist(), is_admin=False, logger=logger)
    page = window.process_page()

    def run_scan() -> object | None:
        page.refresh()
        deadline = time.monotonic() + TIMEOUT_S
        while page.is_scanning() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.02)
        app.processEvents()
        return page.current_result()

    cold_result = run_scan()
    if cold_result is None:
        print("FAIL: 第一次扫描未产出结果（可能失败/超时），请查看日志")
        return 1
    cold_ms = cold_result.duration_ms
    warm_result = run_scan()
    if warm_result is None:
        print("FAIL: 第二次扫描未产出结果（可能失败/超时），请查看日志")
        return 1
    result = warm_result

    tree = result.tree
    print(
        "OK: 进程数={}，命中关注及以上={}，可疑及以上={}，高风险={}，孤儿={}，完整度={}，"
        "首次扫描={}ms，二次扫描={}ms".format(
            tree.total_processes,
            tree.count_at_least(Severity.NOTICE),
            tree.count_at_least(Severity.SUSPICIOUS),
            tree.count_at_least(Severity.HIGH),
            len(tree.orphans),
            tree.completeness.value,
            cold_ms,
            result.duration_ms,
        )
    )
    for warning in tree.warnings:
        print(f"  提示[{warning.code}] {warning.message}")

    network = result.connections
    if network is None:
        print("网络连接：未采集")
    else:
        print(
            "网络连接：{} 条（公网 {}，需人工核实 {}，内核/系统公网 {}，监听 {}，完整度 {}）".format(
                len(network.connections),
                network.public_count,
                network.review_count,
                network.kernel_public_count,
                network.listen_count,
                network.completeness.value,
            )
        )
        for connection in [c for c in network.connections if c.needs_review][:5]:
            print(f"  需核实：{connection.process_name} -> {connection.raddr.text if connection.raddr else '—'}  {connection.review_reason}")

    temp = result.temp
    if temp is None:
        print("临时占用：未采集")
    else:
        print(
            "临时占用：{} / {} 个文件，疑似被占用 {}，完整度 {}，{}".format(
                temp.total_size,
                temp.total_files,
                sum(1 for entry in temp.entries if entry.occupancy.value == "locked"),
                temp.completeness.value,
                temp.probe_note,
            )
        )

    out_dir = Path(tempfile.mkdtemp(prefix="perfpurifier_smoke_"))
    config = AppConfig()
    csv_ok, csv_message = export_process_csv(str(out_dir / "processes.csv"), result, config)
    json_ok, json_message = export_process_json(str(out_dir / "processes.json"), result, config)
    html_ok, html_message = export_report_html(str(out_dir / "report.html"), result, config)
    print(f"CSV : {csv_ok} {csv_message}")
    print(f"JSON: {json_ok} {json_message}")
    print(f"HTML: {html_ok} {html_message}")
    print(f"输出目录：{out_dir}")

    window.close()
    return 0 if (csv_ok and json_ok and html_ok) else 2


if __name__ == "__main__":
    raise SystemExit(main())
