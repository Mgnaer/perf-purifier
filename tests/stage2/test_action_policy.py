"""2A 动作安全策略测试（纯函数：无 I/O、无时间依赖、无真实动作）。

覆盖：总开关/分动作开关、完整度闸门（limited 禁动作）、批量上限、
预览 token 生命周期、三类动作的逐项拒绝/警告、目标签名稳定性。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from perf_purifier.core.action_policy import (
    POLICY_VERSION,
    ActionKind,
    ActionPolicy,
    DeleteTarget,
    HardlinkTarget,
    KillTarget,
    build_preview_token,
    evaluate_delete_targets,
    evaluate_hardlink_targets,
    evaluate_kill_targets,
    is_action_permitted,
    target_signature,
    validate_preview_token,
)
from perf_purifier.core.config import AppConfig
from perf_purifier.core.judgements import (
    CompletenessVerdict,
    FileMeta,
    Reason,
)

NOW = 1_700_000_000.0


def enabled_policy(**overrides) -> ActionPolicy:
    values = dict(
        stage2_enabled=True,
        allow_delete_temp=True,
        allow_hardlink_dedupe=True,
        allow_kill_process=True,
    )
    values.update(overrides)
    return ActionPolicy(**values)


def partial_verdict() -> CompletenessVerdict:
    return CompletenessVerdict("partial", (Reason("permission_limited", "非管理员"),))


def limited_verdict() -> CompletenessVerdict:
    return CompletenessVerdict("limited", (Reason("budget_truncated", "预算截断"),))


def meta(path: str, *, dev: int = 1, ino: int = 100, size: int = 5000, nlink: int = 2) -> FileMeta:
    return FileMeta(path=path, st_dev=dev, st_ino=ino, st_nlink=nlink, size=size)


# ---------------------------------------------------------------- 开关与闸门
def test_all_actions_disabled_by_default() -> None:
    policy = ActionPolicy.from_config(AppConfig())
    for kind in ActionKind:
        decision = is_action_permitted(kind, policy, partial_verdict())
        assert decision.allowed is False
        assert {refusal.code for refusal in decision.refusals} >= {
            "stage2_disabled",
            "action_disabled",
        }


def test_enabled_policy_allows_action_with_partial_verdict() -> None:
    decision = is_action_permitted(ActionKind.DELETE_TEMP, enabled_policy(), partial_verdict())
    assert decision.allowed is True


def test_limited_verdict_blocks_everything() -> None:
    for kind in ActionKind:
        decision = is_action_permitted(kind, enabled_policy(), limited_verdict())
        assert decision.allowed is False
        assert decision.refusals[0].code == "completeness_limited"
        assert "budget_truncated" in decision.refusals[0].text


def test_no_scan_result_blocks_action() -> None:
    decision = is_action_permitted(ActionKind.DELETE_TEMP, enabled_policy(), None)
    assert decision.allowed is False
    assert decision.refusals[0].code == "no_scan_result"


def test_batch_limits() -> None:
    policy = enabled_policy(max_delete_items=2, max_delete_bytes=1000)
    targets = [
        DeleteTarget(path=f"C:\\Temp\\f{i}.bin", root="C:\\Temp", size=600) for i in range(3)
    ]
    decision = evaluate_delete_targets(targets, policy, partial_verdict())
    codes = {refusal.code for refusal in decision.refusals}
    assert decision.allowed is False
    assert "batch_too_large" in codes
    assert "batch_bytes_too_large" in codes


def test_policy_from_config_maps_fields() -> None:
    config = SimpleNamespace(
        stage2_enabled=True,
        allow_delete_temp=True,
        allow_hardlink_dedupe=False,
        allow_kill_process=False,
        action_preview_ttl_s=30.0,
        action_max_delete_items=10,
        action_max_delete_bytes=2048,
        action_max_hardlink_items=5,
        action_max_kill_items=3,
    )
    policy = ActionPolicy.from_config(config)
    assert policy.stage2_enabled is True
    assert policy.action_enabled(ActionKind.DELETE_TEMP) is True
    assert policy.action_enabled(ActionKind.HARDLINK_DEDUPE) is False
    assert policy.preview_ttl_s == 30.0
    assert policy.max_items(ActionKind.KILL_PROCESS) == 3


# ---------------------------------------------------------------- 预览 token
def test_preview_token_roundtrip_and_expiry() -> None:
    token = build_preview_token(
        action=ActionKind.DELETE_TEMP,
        target_signature_value="sig",
        item_count=3,
        total_bytes=1024,
        token_id="token-1",
        now=NOW,
        ttl_s=60,
    )
    assert token.expires_at == NOW + 60
    assert validate_preview_token(token, action=ActionKind.DELETE_TEMP, now=NOW + 1) == (True, "")
    ok, reason = validate_preview_token(token, action=ActionKind.DELETE_TEMP, now=NOW + 61)
    assert ok is False and "过期" in reason


def test_preview_token_rejects_action_and_version_mismatch() -> None:
    token = build_preview_token(
        action=ActionKind.DELETE_TEMP,
        target_signature_value="sig",
        item_count=1,
        total_bytes=1,
        token_id="t",
        now=NOW,
    )
    assert validate_preview_token(token, action=ActionKind.KILL_PROCESS, now=NOW)[0] is False
    assert (
        validate_preview_token(
            token, action=ActionKind.DELETE_TEMP, now=NOW, policy_version="old"
        )[0]
        is False
    )
    assert POLICY_VERSION == token.policy_version


def test_too_long_ttl_falls_back_to_default() -> None:
    token = build_preview_token(
        action=ActionKind.DELETE_TEMP,
        target_signature_value="sig",
        item_count=1,
        total_bytes=0,
        token_id="t",
        now=NOW,
        ttl_s=-5,
    )
    assert token.expires_at > NOW


def test_target_signature_is_order_independent() -> None:
    assert target_signature(["a", "b", "c"]) == target_signature(["c", "a", "b"])
    assert target_signature(["a"]) != target_signature(["b"])


# ---------------------------------------------------------------- 2C 删除目标
def _delete_target(path: str, **overrides) -> DeleteTarget:
    values = dict(path=path, root="C:\\Temp", size=100, occupancy="free")
    values.update(overrides)
    return DeleteTarget(**values)


def test_delete_allows_free_file() -> None:
    decision = evaluate_delete_targets(
        [_delete_target(r"C:\Temp\a.tmp")], enabled_policy(), partial_verdict()
    )
    assert decision.allowed is True
    assert decision.allowed_indices == (0,)
    assert decision.refusals == ()


@pytest.mark.parametrize(
    ("overrides", "expected_code"),
    [
        ({"is_dir": True}, "dir_not_supported"),
        ({"exists": False}, "stale"),
        ({"inside_declared_root": False}, "outside_root"),
        ({"root_allowed": False}, "root_not_allowed"),
        ({"is_reparse": True}, "reparse_point"),
        ({"occupancy": "locked"}, "in_use"),
        ({"occupancy": "no_access"}, "no_access"),
    ],
)
def test_delete_refusals(overrides: dict, expected_code: str) -> None:
    decision = evaluate_delete_targets(
        [_delete_target(r"C:\Temp\a.tmp", **overrides)], enabled_policy(), partial_verdict()
    )
    assert decision.allowed is False
    assert decision.refusals[0].code == expected_code


def test_delete_duplicate_and_not_probed_warning() -> None:
    decision = evaluate_delete_targets(
        [
            _delete_target(r"C:\Temp\a.tmp", occupancy="not_probed"),
            _delete_target(r"C:\\Temp\\A.tmp"),
        ],
        enabled_policy(),
        partial_verdict(),
    )
    assert decision.allowed is True
    assert len(decision.allowed_indices) == 1
    assert any("未探测" in warning for warning in decision.warnings)
    assert {refusal.code for refusal in decision.refusals} == {"duplicate_target"}


# ---------------------------------------------------------------- 2B 结束进程
def _kill_target(pid: int = 1234, **overrides) -> KillTarget:
    values = dict(pid=pid, name="demo.exe", create_time=100.0, exe=r"C:\demo\demo.exe")
    values.update(overrides)
    return KillTarget(**values)


def test_kill_allows_normal_process() -> None:
    decision = evaluate_kill_targets([_kill_target()], enabled_policy(), partial_verdict())
    assert decision.allowed is True


@pytest.mark.parametrize(
    ("overrides", "expected_code"),
    [
        ({"pid": 0}, "protected_pid"),
        ({"pid": 4, "is_protected_pid": True}, "protected_pid"),
        ({"never_terminate": True}, "protected_process"),
        ({"is_self_or_ancestor": True}, "self_protected"),
        ({"identity_matches_snapshot": False}, "identity_changed"),
        ({"create_time": 0.0}, "invalid_identity"),
        ({"name": ""}, "invalid_identity"),
    ],
)
def test_kill_refusals(overrides: dict, expected_code: str) -> None:
    decision = evaluate_kill_targets([_kill_target(**overrides)], enabled_policy(), partial_verdict())
    assert decision.allowed is False
    assert decision.refusals[0].code == expected_code


def test_kill_dedupes_pid_and_warns_review_network() -> None:
    decision = evaluate_kill_targets(
        [
            _kill_target(needs_review_network=True, needs_review_reason="公网连接"),
            _kill_target(),
        ],
        enabled_policy(),
        partial_verdict(),
    )
    assert decision.allowed is True
    assert len(decision.allowed_indices) == 1
    assert any("需人工核实" in warning for warning in decision.warnings)
    assert {refusal.code for refusal in decision.refusals} == {"duplicate_target"}


# ---------------------------------------------------------------- 2D 硬链接
def _hardlink_target(**overrides) -> HardlinkTarget:
    canonical = meta(r"C:\data\keep.bin", ino=100)
    redundant = meta(r"C:\data\dup.bin", ino=200)
    values = dict(
        canonical=canonical,
        redundant=redundant,
        group=(canonical, redundant),
        content_sha256="a" * 64,
        same_volume=True,
        ntfs=True,
        rehash_matches=True,
        paths_exist=True,
    )
    values.update(overrides)
    return HardlinkTarget(**values)


def test_hardlink_allows_safe_pair() -> None:
    decision = evaluate_hardlink_targets([_hardlink_target()], enabled_policy(), partial_verdict())
    assert decision.allowed is True
    assert any("修改时间" in warning for warning in decision.warnings)


def test_hardlink_refuses_already_hardlinked_group() -> None:
    canonical = meta(r"C:\data\keep.bin", ino=100)
    redundant = meta(r"C:\data\dup.bin", ino=100)
    target = _hardlink_target(canonical=canonical, redundant=redundant, group=(canonical, redundant))
    decision = evaluate_hardlink_targets([target], enabled_policy(), partial_verdict())
    assert decision.allowed is False
    assert {refusal.code for refusal in decision.refusals} & {
        "already_hardlinked",
        "group_has_hardlinks",
    }


def test_hardlink_refuses_group_with_existing_hardlink_pair() -> None:
    """组内另一对路径已互为硬链接 → 整个组不再自动建链接（避免语义混乱）。"""

    canonical = meta(r"C:\data\keep.bin", ino=100)
    redundant = meta(r"C:\data\dup.bin", ino=200)
    linked_a = meta(r"C:\data\x.bin", ino=300)
    linked_b = meta(r"C:\data\y.bin", ino=300)
    target = _hardlink_target(
        canonical=canonical,
        redundant=redundant,
        group=(canonical, redundant, linked_a, linked_b),
    )
    decision = evaluate_hardlink_targets([target], enabled_policy(), partial_verdict())
    assert decision.allowed is False
    assert "group_has_hardlinks" in {refusal.code for refusal in decision.refusals}


@pytest.mark.parametrize(
    ("overrides", "expected_code"),
    [
        ({"same_volume": False}, "cross_volume"),
        ({"ntfs": False}, "non_ntfs"),
        ({"rehash_matches": False}, "content_changed"),
        ({"paths_exist": False}, "stale"),
        ({"content_sha256": ""}, "missing_hash"),
    ],
)
def test_hardlink_refusals(overrides: dict, expected_code: str) -> None:
    decision = evaluate_hardlink_targets(
        [_hardlink_target(**overrides)], enabled_policy(), partial_verdict()
    )
    assert decision.allowed is False
    assert expected_code in {refusal.code for refusal in decision.refusals}


def test_hardlink_refuses_same_identity_and_duplicate_paths() -> None:
    canonical = meta(r"C:\data\keep.bin", ino=100)
    duplicate = meta(r"C:\data\keep.bin", ino=100)
    same_identity = _hardlink_target(canonical=canonical, redundant=duplicate, group=(canonical,))
    decision = evaluate_hardlink_targets([same_identity], enabled_policy(), partial_verdict())
    assert {refusal.code for refusal in decision.refusals} & {"same_path", "already_hardlinked"}
