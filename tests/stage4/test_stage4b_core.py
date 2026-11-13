"""阶段 4B 核心测试：HARDLINK_DETACH 策略与独立化执行器（真实临时硬链接）。"""

from __future__ import annotations

import os

from perf_purifier.core.action_policy import (
    ActionPolicy,
    HardlinkDetachTarget,
    evaluate_detach_targets,
)
from perf_purifier.core.judgements import CompletenessVerdict, Reason
from perf_purifier.core.models import FileRecord
from perf_purifier.module_b.hardlink_action import (
    HardlinkDetachExecutor,
    build_detach_preview,
    detach_targets_from_records,
)

NOW = 1_700_000_000.0


def _policy(**overrides) -> ActionPolicy:
    values = dict(stage2_enabled=True, allow_hardlink_detach=True)
    values.update(overrides)
    return ActionPolicy(**values)


def _verdict() -> CompletenessVerdict:
    return CompletenessVerdict("partial", (Reason("permission_limited", "非管理员"),))


def test_policy_requires_nlink_and_switch() -> None:
    linked = HardlinkDetachTarget(path=r"C:\data\a.bin", size=10, mtime=NOW, nlink=2)
    plain = HardlinkDetachTarget(path=r"C:\data\b.bin", size=10, mtime=NOW, nlink=1)
    decision = evaluate_detach_targets([linked, plain], _policy(), _verdict())
    assert decision.allowed is True
    assert decision.allowed_indices == (0,)
    assert {refusal.code for refusal in decision.refusals} == {"not_hardlinked"}

    disabled = evaluate_detach_targets([linked], ActionPolicy(), _verdict())
    assert disabled.allowed is False
    assert "stage2_disabled" in {refusal.code for refusal in disabled.refusals}


def test_detach_preview_builds_token() -> None:
    record = FileRecord(path=os.path.abspath(__file__), size=1, mtime=NOW)
    targets, decision, token = build_detach_preview(
        [record], policy=_policy(), verdict=_verdict(), now=NOW, token_id="t1"
    )
    assert len(targets) == 1
    # 普通文件 nlink==1 → 策略拒绝、token 为 None（不产生动作）
    assert decision.allowed is False
    assert token is None


def test_executor_detaches_real_hardlink(tmp_path) -> None:
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    content = b"perf-purifier detach test" * 1024
    first.write_bytes(content)
    os.link(first, second)
    assert os.stat(second).st_nlink == 2

    record = FileRecord(
        path=str(second),
        size=len(content),
        mtime=float(os.stat(second).st_mtime),
    )
    targets = detach_targets_from_records([record])
    assert targets[0].nlink == 2
    result = HardlinkDetachExecutor()(targets[0])
    assert result.result == "success", result
    first_stat = os.stat(first)
    second_stat = os.stat(second)
    assert second_stat.st_nlink == 1
    assert second_stat.st_ino != first_stat.st_ino
    assert second.read_bytes() == content
    assert first.read_bytes() == content
    leftovers = [name for name in os.listdir(tmp_path) if ".pp-detach-" in name]
    assert leftovers == []


def test_executor_refuses_plain_file(tmp_path) -> None:
    path = tmp_path / "plain.bin"
    path.write_bytes(b"x" * 16)
    record = FileRecord(path=str(path), size=16, mtime=float(os.stat(path).st_mtime))
    target = detach_targets_from_records([record])[0]
    result = HardlinkDetachExecutor()(target)
    assert result.result == "refused"
    assert result.error_code == "not_hardlinked"
