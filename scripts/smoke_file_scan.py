"""模块 B 端到端冒烟（1C 增强）：排除规则 / 类型过滤 / 并行哈希 / 哈希缓存 / 保留建议。

运行：
    .\\.venv\\Scripts\\python.exe scripts\\smoke_file_scan.py
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

from PySide6.QtCore import QThread  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from perf_purifier.core.cancel import CancelToken  # noqa: E402
from perf_purifier.core.config import AppConfig, log_dir  # noqa: E402
from perf_purifier.core.logging_setup import setup_logging  # noqa: E402
from perf_purifier.core.models import FileScanOptions  # noqa: E402
from perf_purifier.jobs.file_scan_job import FileScanJob  # noqa: E402
from perf_purifier.module_b.report import (  # noqa: E402
    export_duplicate_files_csv,
    export_duplicates_csv,
    export_file_report_html,
    export_file_scan_json,
    export_large_files_csv,
)

TIMEOUT_S = 120.0


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def run_scan(app: QApplication, options: FileScanOptions):
    job = FileScanJob(options, token=CancelToken())
    box: dict[str, object] = {}
    job.finished.connect(lambda result: box.setdefault("result", result))
    job.failed.connect(lambda message: box.setdefault("error", message))
    thread = QThread()
    job.moveToThread(thread)
    thread.started.connect(job.run)
    job.finished.connect(thread.quit)
    job.failed.connect(thread.quit)
    job.cancelled.connect(thread.quit)
    thread.start()
    deadline = time.monotonic() + TIMEOUT_S
    while thread.isRunning() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.02)
    thread.wait(2000)
    return box.get("result"), box.get("error")


def main() -> int:
    logger = setup_logging(log_dir())
    app = QApplication([])

    base = Path(tempfile.mkdtemp(prefix="perfpurifier_files_"))
    root = base / "data"
    _write(root / "a" / "one.bin", b"A" * 5000 + b"tail-1")
    _write(root / "b" / "two.bin", b"A" * 5000 + b"tail-1")
    _write(root / "c" / "three.bin", b"A" * 5000 + b"tail-2")  # 4KB 前缀相同、尾部不同
    _write(root / "d" / "four.bin", b"B" * 3000)
    _write(root / "e" / "five.bin", b"B" * 3000)
    _write(root / "node_modules" / "ignored_copy.bin", b"A" * 5000 + b"tail-1")  # 应被排除
    original = root / "f" / "orig.bin"
    _write(original, b"Z" * 6000)
    try:
        os.link(original, root / "f" / "link.bin")
        hardlink_note = "已创建硬链接样本"
    except OSError as exc:
        hardlink_note = f"无法创建硬链接样本：{exc}"
    _write(root / "big" / "huge.bin", b"0" * (3 * 1024 * 1024))

    options = FileScanOptions(
        root=str(root),
        min_size=1024,
        max_files=100_000,
        walk_budget_s=30.0,
        large_limit=100,
        exclude_patterns=("node_modules",),
        use_cache=True,
    )

    first, error = run_scan(app, options)
    if first is None:
        print(f"FAIL: 第一次扫描失败/超时：{error}")
        return 1
    print(
        "首次：文件数={}，重复组={}，重复文件={}，可回收={}，排除跳过={}，"
        "哈希并发={}（介质 {}），缓存命中={}，完整度={}，用时={}ms".format(
            first.files_scanned,
            len(first.duplicate_groups),
            first.duplicate_file_count,
            first.reclaimable_bytes,
            first.skipped_excluded,
            first.hash_workers,
            first.media_type,
            first.cache_hits,
            first.completeness.value,
            first.duration_ms,
        )
    )
    print(f"  硬链接样本：{hardlink_note}")
    for group in first.duplicate_groups:
        keep = group.suggested_keep.path if group.suggested_keep else "—"
        print(
            f"  组 {group.group_id}: 单文件 {group.size} 字节 × {len(group.files)}，"
            f"可回收 {group.reclaimable_bytes}，硬链接={group.has_hardlinks}，建议保留={keep}"
        )
    for warning in first.warnings:
        print(f"  提示[{warning.code}] {warning.message}")

    second, error = run_scan(app, options)
    if second is None:
        print(f"FAIL: 第二次扫描失败/超时：{error}")
        return 1
    print(f"二次（缓存）：重复组={len(second.duplicate_groups)}，缓存命中={second.cache_hits}，用时={second.duration_ms}ms")

    out = base / "reports"
    out.mkdir(parents=True, exist_ok=True)
    checks = [
        ("组CSV", export_duplicates_csv(str(out / "duplicates.csv"), first)),
        ("明细CSV", export_duplicate_files_csv(str(out / "duplicate_files.csv"), first)),
        ("大文件CSV", export_large_files_csv(str(out / "large_files.csv"), first)),
        ("JSON", export_file_scan_json(str(out / "scan.json"), first)),
        ("HTML", export_file_report_html(str(out / "report.html"), first)),
    ]
    for label, (ok, message) in checks:
        print(f"{label}: {ok} {message}")
    print(f"输出目录：{out}")

    ok = (
        len(first.duplicate_groups) == 3
        and first.skipped_excluded >= 1
        and second.cache_hits > 0
        and all(item_ok for _label, (item_ok, _message) in checks)
    )
    print("CHECK_EXCLUSION=", first.skipped_excluded >= 1)
    print("CHECK_CACHE_HITS=", second.cache_hits > 0)
    print("CHECK_GROUP_COUNT=", len(first.duplicate_groups) == 3)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
