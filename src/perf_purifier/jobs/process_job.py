"""模块 A 扫描任务：进程快照 -> 签名校验 -> 建树评分 -> 网络连接 -> 临时占用。

全部为只读操作；任一子阶段失败只降级该阶段（写 ScanWarning），不阻断整次扫描。
"""

from __future__ import annotations

import time

from PySide6.QtCore import QObject

from ..core.cancel import CancelToken
from ..core.config import AppConfig
from ..core.models import ProcessScanResult, ScanWarning
from ..core.whitelist import Whitelist
from ..module_a.heuristics import analyze_tree
from ..module_a.network_scan import collect_connections
from ..module_a.process_snapshot import collect_processes
from ..module_a.signature import enrich_process_signatures
from ..module_a.temp_scan import scan_temp
from ..module_a.tree_builder import build_tree
from .base_job import ScanJob


class ProcessScanJob(ScanJob):
    """阶段 1B：进程 + 签名 + 网络 + 临时占用的只读扫描。"""

    def __init__(
        self,
        config: AppConfig,
        whitelist: Whitelist,
        *,
        is_admin: bool,
        token: CancelToken | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(token, parent)
        self._config = config
        self._whitelist = whitelist
        self._is_admin = is_admin

    def _run(self) -> None:
        started_at = time.time()
        config = self._config
        all_warnings: list[ScanWarning] = []

        def record(warning: ScanWarning) -> None:
            all_warnings.append(warning)
            self._warn(warning)

        # ---- 1. 进程快照（0-28%）----
        self._stage("正在采集进程快照…")

        def on_snapshot_progress(done: int, total: int, name: str) -> None:
            percent = (done / total * 28.0) if total else 0.0
            self._progress(percent, f"进程 {done}/{total}：{name}")

        processes, snapshot_warnings, completeness = collect_processes(
            self.token,
            progress=on_snapshot_progress,
            max_processes=config.max_processes,
        )
        for warning in snapshot_warnings:
            record(warning)

        # ---- 2. 数字签名（28-42%）----
        if config.signature_check_enabled and processes:
            self._stage("正在校验可执行文件数字签名…")

            def on_signature_progress(done: int, total: int) -> None:
                percent = 28.0 + (done / total * 14.0 if total else 14.0)
                self._progress(percent, f"签名校验 {done}/{total}")

            try:
                processes, signature_warnings = enrich_process_signatures(
                    processes,
                    self._whitelist,
                    token=self.token,
                    max_files=config.signature_max_files,
                    budget_s=config.signature_budget_s,
                    progress=on_signature_progress,
                )
                for warning in signature_warnings:
                    record(warning)
            except Exception as exc:  # noqa: BLE001 - 签名阶段失败不应阻断整体扫描
                record(
                    ScanWarning(
                        "signature_failed",
                        f"数字签名校验失败（{type(exc).__name__}: {exc}），签名状态保持未检查",
                        phase="signature",
                    )
                )
        else:
            self._progress(42, "跳过签名校验", force=True)

        # ---- 3. 建树 + 启发式评分（42-56%）----
        self._progress(56, "正在构建进程树并评估可疑规则…", force=True)
        tree = build_tree(processes, completeness=completeness)
        for warning in tree.warnings:
            record(warning)
        analyze_tree(tree, self._whitelist)

        # ---- 4. 网络连接（56-72%）----
        connections = None
        if config.network_scan_enabled:
            self._stage("正在采集网络连接…")
            process_index = {pid: node.info for pid, node in tree.nodes.items()}

            def on_network_progress(done: int, total: int) -> None:
                percent = 56.0 + (done / total * 16.0 if total else 16.0)
                self._progress(percent, f"网络连接 {done}/{total}")

            try:
                connections = collect_connections(
                    process_index=process_index,
                    whitelist=self._whitelist,
                    token=self.token,
                    progress=on_network_progress,
                )
                for warning in connections.warnings:
                    record(warning)
            except Exception as exc:  # noqa: BLE001 - 网络阶段失败只降级
                record(
                    ScanWarning(
                        "network_failed",
                        f"网络连接采集失败（{type(exc).__name__}: {exc}）",
                        phase="network",
                    )
                )
                connections = None
        else:
            self._progress(72, "跳过网络连接采集", force=True)

        # ---- 5. 临时文件占用（72-97%）----
        temp_result = None
        if config.temp_scan_enabled:
            self._stage("正在扫描临时文件占用…")

            def on_temp_progress(hint: int, text: str) -> None:
                self._progress(72.0 + (hint / 100.0) * 25.0, text)

            try:
                temp_result = scan_temp(
                    self.token,
                    max_files=config.temp_max_files,
                    budget_s=config.temp_budget_s,
                    probe_max_files=config.temp_probe_max_files,
                    probe_budget_s=config.temp_probe_budget_s,
                    progress=on_temp_progress,
                )
                for warning in temp_result.warnings:
                    record(warning)
            except Exception as exc:  # noqa: BLE001 - 临时目录阶段失败只降级
                record(
                    ScanWarning(
                        "temp_failed",
                        f"临时文件扫描失败（{type(exc).__name__}: {exc}）",
                        phase="temp",
                    )
                )
                temp_result = None
        else:
            self._progress(97, "跳过临时文件扫描", force=True)

        # ---- 6. 收尾 ----
        tree.elapsed_ms = int((time.time() - started_at) * 1000)
        tree.warnings = all_warnings
        result = ProcessScanResult(
            tree=tree,
            started_at=started_at,
            finished_at=time.time(),
            is_admin=self._is_admin,
            connections=connections,
            temp=temp_result,
        )
        self._progress(100, "扫描完成", force=True)
        self.finished.emit(result)
