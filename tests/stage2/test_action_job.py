"""2A 动作任务框架测试：token 校验、审计先写、逐项失败隔离、取消、dry-run。

所有测试都只使用 ``DryRunExecutor`` 或注入的假 executor，**不执行任何真实动作**。
"""

from __future__ import annotations

import json

from perf_purifier.core.action_policy import (
    ActionKind,
    DeleteTarget,
    HardlinkTarget,
    KillTarget,
    build_preview_token,
)
from perf_purifier.core.audit import ActionAuditWriter
from perf_purifier.core.cancel import CancelToken
from perf_purifier.core.judgements import CompletenessVerdict, FileMeta, Reason
from perf_purifier.jobs.action_job import (
    ActionExecutionResult,
    ActionJob,
    DryRunExecutor,
    target_identity,
    target_label,
    target_total_bytes,
)

NOW = 1_700_000_000.0


class FakeClock:
    def __init__(self, start: float = NOW) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_token(**overrides):
    values = dict(
        action=ActionKind.DELETE_TEMP,
        target_signature_value="sig",
        item_count=2,
        total_bytes=300,
        token_id="token-1",
        now=NOW,
        ttl_s=60.0,
    )
    values.update(overrides)
    return build_preview_token(**values)


def make_targets() -> list[DeleteTarget]:
    return [
        DeleteTarget(path=r"C:\Temp\a.tmp", root=r"C:\Temp", size=100, occupancy="free"),
        DeleteTarget(path=r"C:\Temp\b.tmp", root=r"C:\Temp", size=200, occupancy="free"),
    ]


def partial_verdict() -> CompletenessVerdict:
    return CompletenessVerdict("partial", (Reason("permission_limited", "非管理员"),))


def run_job(job: ActionJob) -> dict:
    box: dict = {}
    job.finished.connect(lambda result: box.setdefault("result", result))
    job.failed.connect(lambda message: box.setdefault("failed", message))
    job.cancelled.connect(lambda: box.setdefault("cancelled", True))
    job.run()
    return box


def read_audit(writer: ActionAuditWriter) -> list[dict]:
    return [json.loads(line) for line in writer.path.read_text(encoding="utf-8").splitlines()]


def make_job(qapp, tmp_path, *, executor=None, allowed=(0, 1), token=None, clock=None) -> tuple[ActionJob, ActionAuditWriter]:
    writer = ActionAuditWriter(tmp_path)
    job = ActionJob(
        action=ActionKind.DELETE_TEMP,
        token=token or make_token(),
        targets=make_targets(),
        allowed_indices=list(allowed),
        executor=executor or DryRunExecutor(),
        audit=writer,
        verdict=partial_verdict(),
        is_admin=False,
        app_version="0.1.0",
        session_id="session-test",
        dry_run=True,
        clock=clock or FakeClock(),
    )
    return job, writer


# ---------------------------------------------------------------- dry-run 正常流
def test_dry_run_writes_header_then_items(qapp, tmp_path) -> None:
    job, writer = make_job(qapp, tmp_path)
    box = run_job(job)

    result = box["result"]
    assert result.dry_run is True
    assert len(result.results) == 2
    assert result.success_count == 2
    assert result.session_id == "session-test"
    records = read_audit(writer)
    assert [record["record_type"] for record in records] == [
        "action_header",
        "action_item",
        "action_item",
        "action_end",
    ]
    header = records[0]
    assert header["token_id"] == "token-1"
    assert header["verdict_level"] == "partial"
    assert header["verdict_codes"] == ["permission_limited"]
    assert header["item_count"] == 2
    assert header["total_bytes"] == 300
    assert records[1]["result"] == "dry_run"


# ---------------------------------------------------------------- token 校验
def test_expired_token_blocks_before_any_execution(qapp, tmp_path) -> None:
    calls: list[object] = []
    clock = FakeClock(NOW + 120)
    job, writer = make_job(
        qapp,
        tmp_path,
        executor=lambda target: calls.append(target) or ActionExecutionResult("dry_run"),
        clock=clock,
    )
    box = run_job(job)
    assert "failed" in box
    assert "预览已过期" in box["failed"]
    assert calls == []
    assert not writer.path.exists()


def test_empty_allowed_indices_fails(qapp, tmp_path) -> None:
    job, _writer = make_job(qapp, tmp_path, allowed=())
    box = run_job(job)
    assert "failed" in box
    assert "没有可执行的目标" in box["failed"]


# ---------------------------------------------------------------- 审计严格性
def test_audit_failure_aborts_before_execution(qapp, tmp_path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    writer = ActionAuditWriter(blocker)
    calls: list[object] = []
    job = ActionJob(
        action=ActionKind.DELETE_TEMP,
        token=make_token(),
        targets=make_targets(),
        allowed_indices=[0, 1],
        executor=lambda target: calls.append(target) or ActionExecutionResult("dry_run"),
        audit=writer,
        verdict=partial_verdict(),
        is_admin=False,
        app_version="0.1.0",
        session_id="session-test",
        clock=FakeClock(),
    )
    box = run_job(job)
    assert "failed" in box
    assert "审计日志写入失败" in box["failed"]
    assert calls == []


# ---------------------------------------------------------------- 失败隔离
def test_item_failure_does_not_stop_others(qapp, tmp_path) -> None:
    def executor(target: object) -> ActionExecutionResult:
        if getattr(target, "path", "").endswith("a.tmp"):
            return ActionExecutionResult("failed", "permission_denied", "拒绝访问")
        return ActionExecutionResult("success")

    job, writer = make_job(qapp, tmp_path, executor=executor)
    box = run_job(job)
    result = box["result"]
    assert [item.result for item in result.results] == ["failed", "success"]
    assert result.failed_count == 1
    records = read_audit(writer)
    assert records[1]["error_code"] == "permission_denied"


def test_executor_exception_becomes_failed_item(qapp, tmp_path) -> None:
    def executor(target: object) -> ActionExecutionResult:
        raise RuntimeError("boom")

    job, writer = make_job(qapp, tmp_path, executor=executor)
    box = run_job(job)
    result = box["result"]
    assert all(item.result == "failed" for item in result.results)
    assert result.results[0].error_code == "executor_exception"


# ---------------------------------------------------------------- 取消
def test_cancel_after_first_item_stops_batch(qapp, tmp_path) -> None:
    cancel_token = CancelToken()
    calls: list[object] = []

    def executor(target: object) -> ActionExecutionResult:
        calls.append(target)
        cancel_token.cancel()
        return ActionExecutionResult("dry_run")

    writer = ActionAuditWriter(tmp_path)
    job = ActionJob(
        action=ActionKind.DELETE_TEMP,
        token=make_token(),
        targets=make_targets(),
        allowed_indices=[0, 1],
        executor=executor,
        audit=writer,
        verdict=partial_verdict(),
        is_admin=False,
        app_version="0.1.0",
        session_id="session-cancel",
        clock=FakeClock(),
        cancel_token=cancel_token,
    )
    box = run_job(job)
    assert box.get("cancelled") is True
    assert len(calls) == 1
    records = read_audit(writer)
    assert len(records) == 2  # header + 已执行项


# ---------------------------------------------------------------- 目标辅助函数
def test_target_helpers() -> None:
    delete = DeleteTarget(path=r"C:\Temp\a.tmp", root=r"C:\Temp", size=42)
    assert target_label(delete) == r"C:\Temp\a.tmp"
    assert "path=" in target_identity(delete)
    assert target_total_bytes(delete) == 42

    kill = KillTarget(pid=1234, name="demo.exe", create_time=10.0, exe=r"C:\demo\demo.exe")
    assert target_label(kill) == "PID 1234"
    assert "create_time=10.0" in target_identity(kill)
    assert target_total_bytes(kill) == 0

    canonical = FileMeta(path=r"C:\d\keep.bin", st_dev=1, st_ino=100, st_nlink=2, size=500)
    redundant = FileMeta(path=r"C:\d\dup.bin", st_dev=1, st_ino=200, st_nlink=1, size=500)
    hardlink = HardlinkTarget(
        canonical=canonical,
        redundant=redundant,
        group=(canonical, redundant),
        content_sha256="a" * 64,
    )
    assert r"C:\d\dup.bin" in target_label(hardlink)
    assert "redundant=" in target_identity(hardlink)
    assert target_total_bytes(hardlink) == 500
