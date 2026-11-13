"""阶段 2B 结束进程测试（只结束测试自己启动的子进程；系统进程只测拒绝分支）。

覆盖：完整度适配、祖先链/网络复核映射、目标构建、策略预览、
执行器身份重验/自保护/真实子进程终止、ActionJob 端到端审计、UI 选择与默认关闭。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import psutil
from PySide6.QtCore import QItemSelectionModel

from perf_purifier.core.action_policy import ActionKind, ActionPolicy
from perf_purifier.core.audit import ActionAuditWriter
from perf_purifier.core.config import AppConfig
from perf_purifier.core.judgements import CompletenessVerdict, Reason
from perf_purifier.core.models import (
    Completeness,
    ProcessScanResult,
    ProcessTree,
    ScanWarning,
)
from perf_purifier.jobs.action_job import ActionJob, ActionSessionResult
from perf_purifier.module_a.kill_action import (
    KillExecutor,
    ancestor_pids,
    build_kill_preview,
    kill_targets_from_pids,
    network_review_by_pid,
    process_scan_verdict,
)
from perf_purifier.ui.pages.page_process_tree import ProcessTreePage

NOW = 1_700_000_000.0
CHILD_SCRIPT = "import time; time.sleep(60)"


def enabled_policy() -> ActionPolicy:
    return ActionPolicy(stage2_enabled=True, allow_kill_process=True)


def partial_verdict() -> CompletenessVerdict:
    return CompletenessVerdict("partial", (Reason("permission_limited", "非管理员"),))


def _tree(total: int, completeness: Completeness = Completeness.FULL, warnings=()) -> ProcessTree:
    return ProcessTree(total_processes=total, completeness=completeness, warnings=list(warnings))


def _spawn_child() -> subprocess.Popen:
    child = subprocess.Popen([sys.executable, "-c", CHILD_SCRIPT])
    time.sleep(0.2)
    return child


def _kill_quietly(process: subprocess.Popen) -> None:
    try:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    except Exception:  # noqa: BLE001 - 测试清理
        pass


# ---------------------------------------------------------------- 完整度
def test_process_verdict_mapping() -> None:
    full = ProcessScanResult(tree=_tree(100), started_at=NOW, finished_at=NOW + 1)
    assert process_scan_verdict(full, is_admin=True).level == "full"

    non_admin_scan = ProcessScanResult(
        tree=_tree(100, completeness=Completeness.PARTIAL),
        started_at=NOW,
        finished_at=NOW + 1,
    )
    non_admin = process_scan_verdict(non_admin_scan, is_admin=False)
    assert non_admin.level == "partial"
    assert any(reason.code == "permission_limited" for reason in non_admin.reasons)

    budget = ProcessScanResult(
        tree=_tree(100, warnings=[ScanWarning("process_limit", "达到上限")]),
        started_at=NOW,
        finished_at=NOW + 1,
    )
    assert process_scan_verdict(budget, is_admin=True).level == "limited"

    degraded = ProcessScanResult(
        tree=_tree(0, completeness=Completeness.DEGRADED),
        started_at=NOW,
        finished_at=NOW + 1,
    )
    assert process_scan_verdict(degraded, is_admin=True).level == "limited"


# ---------------------------------------------------------------- 祖先链/网络
def test_ancestor_pids(make_info) -> None:
    infos = [make_info(1, 0, "root"), make_info(10, 1, "mid"), make_info(20, 10, "leaf")]
    assert ancestor_pids(infos, 20) == {20, 10, 1}
    assert ancestor_pids(infos, 999) == {999}


def test_network_review_by_pid(synthetic_result) -> None:
    reviews = network_review_by_pid(synthetic_result.connections)
    assert 100 in reviews
    assert "非受信路径" in reviews[100]
    assert 200 not in reviews


# ---------------------------------------------------------------- 目标/预览
def test_kill_targets_from_pids(synthetic_result) -> None:
    targets = kill_targets_from_pids(synthetic_result, [4, 100, 200])
    by_pid = {target.pid: target for target in targets}
    assert set(by_pid) == {4, 100, 200}
    assert by_pid[4].is_protected_pid is True
    assert by_pid[100].needs_review_network is True
    assert "非受信路径" in by_pid[100].needs_review_reason
    assert by_pid[100].never_terminate is False

    _targets, decision, token = build_kill_preview(
        synthetic_result,
        [4, 100, 200],
        policy=enabled_policy(),
        verdict=partial_verdict(),
        now=NOW,
        token_id="t1",
    )
    # PID 4 被拒绝，100/200 可执行
    assert decision.allowed is True
    assert token is not None and token.item_count == 2
    assert {refusal.code for refusal in decision.refusals} == {"protected_pid"}
    assert any("需人工核实" in warning for warning in decision.warnings)

    _targets, refused, refused_token = build_kill_preview(
        synthetic_result,
        [100],
        policy=ActionPolicy(),
        verdict=partial_verdict(),
        now=NOW,
        token_id="t2",
    )
    assert refused.allowed is False and refused_token is None


# ---------------------------------------------------------------- 执行器
def test_executor_refuses_self() -> None:
    process = psutil.Process(os.getpid())
    from perf_purifier.core.action_policy import KillTarget

    target = KillTarget(
        pid=os.getpid(),
        name=process.name(),
        create_time=process.create_time(),
        exe=process.exe(),
    )
    result = KillExecutor()(target)
    assert result.result == "refused"
    assert result.error_code == "self_protected"


def test_executor_kills_spawned_child() -> None:
    from perf_purifier.core.action_policy import KillTarget

    child = _spawn_child()
    try:
        process = psutil.Process(child.pid)
        target = KillTarget(
            pid=child.pid,
            name=process.name(),
            create_time=process.create_time(),
            exe=process.exe(),
        )
        result = KillExecutor()(target)
        assert result.result == "success"
        child.wait(timeout=5)
        assert child.poll() is not None
    finally:
        _kill_quietly(child)


def test_executor_refuses_identity_mismatch() -> None:
    from perf_purifier.core.action_policy import KillTarget

    child = _spawn_child()
    try:
        process = psutil.Process(child.pid)
        target = KillTarget(
            pid=child.pid,
            name=process.name(),
            create_time=process.create_time() + 100.0,
            exe=process.exe(),
        )
        result = KillExecutor()(target)
        assert result.result == "refused"
        assert result.error_code == "identity_changed"
        assert child.poll() is None
    finally:
        _kill_quietly(child)


def test_executor_refuses_stale_pid() -> None:
    from perf_purifier.core.action_policy import KillTarget

    child = _spawn_child()
    _kill_quietly(child)
    target = KillTarget(pid=child.pid, name="gone.exe", create_time=NOW)
    result = KillExecutor()(target)
    assert result.result == "refused"
    assert result.error_code in {"stale", "identity_changed"}


# ---------------------------------------------------------------- 端到端（真实子进程）
def test_kill_job_full_flow(tmp_path) -> None:
    from perf_purifier.core.action_policy import (
        KillTarget,
        build_preview_token,
        evaluate_kill_targets,
    )

    child = _spawn_child()
    try:
        process = psutil.Process(child.pid)
        targets = [
            KillTarget(
                pid=child.pid,
                name=process.name(),
                create_time=process.create_time(),
                exe=process.exe(),
            )
        ]
        decision = evaluate_kill_targets(targets, enabled_policy(), partial_verdict())
        assert decision.allowed is True
        token = build_preview_token(
            action=ActionKind.KILL_PROCESS,
            target_signature_value="sig",
            item_count=1,
            total_bytes=0,
            token_id="token-1",
            now=NOW,
        )
        audit = ActionAuditWriter(tmp_path)
        job = ActionJob(
            action=ActionKind.KILL_PROCESS,
            token=token,
            targets=targets,
            allowed_indices=decision.allowed_indices,
            executor=KillExecutor(),
            audit=audit,
            verdict=partial_verdict(),
            is_admin=False,
            app_version="0.1.0",
            session_id="session-1",
            dry_run=False,
            clock=lambda: NOW,
        )
        box: dict = {}
        job.finished.connect(lambda result: box.setdefault("result", result))
        job.run()
        session: ActionSessionResult = box["result"]
        assert [item.result for item in session.results] == ["success"]
        child.wait(timeout=5)
        records = [
            json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines()
        ]
        assert records[0]["action"] == "kill_process"
        assert records[1]["result"] == "success"
    finally:
        _kill_quietly(child)


# ---------------------------------------------------------------- UI
def _dispose_page(page, qapp) -> None:
    from PySide6.QtCore import QCoreApplication, QEvent

    page.setParent(None)
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()


def test_process_page_kill_default_off(qapp, synthetic_result) -> None:
    from perf_purifier.core.whitelist import Whitelist

    page = ProcessTreePage(
        AppConfig(), Whitelist(), is_admin=False, app_version="0.1.0"
    )
    page.set_result(synthetic_result)
    model = page._model
    root = model.index(0, 0)
    page._view.selectionModel().select(
        root, QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
    )
    assert "已选 1 个进程" in page._kill_selection_label.text()
    assert page._btn_kill.isEnabled() is False  # 默认关闭
    _dispose_page(page, qapp)


def test_process_page_kill_enabled_with_config(qapp, synthetic_result) -> None:
    from perf_purifier.core.whitelist import Whitelist

    config = AppConfig()
    config.stage2_enabled = True
    config.allow_kill_process = True
    page = ProcessTreePage(config, Whitelist(), is_admin=False, app_version="0.1.0")
    page.set_result(synthetic_result)
    model = page._model
    root = model.index(0, 0)
    child = model.index(0, 0, root)
    selection = page._view.selectionModel()
    for index in (root, child):
        selection.select(
            index,
            QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
        )
    assert "已选 2 个进程" in page._kill_selection_label.text()
    assert page._btn_kill.isEnabled() is True
    selection.clear()
    assert page._btn_kill.isEnabled() is False
    _dispose_page(page, qapp)
