"""模块 C 扫描编排 + 动作策略测试（批量闸门 / 逐项拒绝 / 预览 token）。"""

from __future__ import annotations

from pathlib import Path

import pytest

from perf_purifier.core.action_policy import ActionKind, ActionPolicy
from perf_purifier.core.judgements import ScanStats, compute_completeness
from perf_purifier.module_c import policy as policy_module
from perf_purifier.module_c import scan as scan_module
from perf_purifier.module_c.models import (
    MODE_CHILDREN,
    RISK_SAFE,
    JunkItem,
    JunkRule,
    JunkRuleResult,
)
from perf_purifier.module_c.policy import (
    build_slim_preview,
    evaluate_slim_targets,
    refusal_text,
    slim_targets_from_items,
)
from perf_purifier.module_c.safety import normalize_path
from perf_purifier.module_c.scan import dedupe_junk_results, scan_junk_rules, scan_space


def _rule(root: Path, *, rule_id: str = "t", risk: str = RISK_SAFE) -> JunkRule:
    return JunkRule(
        id=rule_id,
        name="测试规则",
        category="测试",
        risk=risk,
        mode=MODE_CHILDREN,
        roots=(str(root),),
    )


def _item(root: Path, path: Path, *, size: int = 10, risk: str = RISK_SAFE, **overrides) -> JunkItem:
    defaults = {
        "rule_id": "t",
        "rule_name": "测试规则",
        "category": "测试",
        "risk": risk,
        "path": str(path),
        "size": size,
        "file_count": 1,
        "mtime": 0.0,
        "kind": "file",
        "allowed_root": str(root),
    }
    defaults.update(overrides)
    return JunkItem(**defaults)


def _full_verdict(items: int = 2):
    return compute_completeness(ScanStats(total_items=items, permission_limited=False))


def _policy(**overrides) -> ActionPolicy:
    values = {"stage2_enabled": True, "allow_clean_space": True}
    values.update(overrides)
    return ActionPolicy(**values)


# --------------------------------------------------------------------------- 扫描
def build_cache(root: Path) -> dict[str, int]:
    root.mkdir(parents=True, exist_ok=True)
    (root / "f1.tmp").write_bytes(b"x" * 100)
    (root / "f2.tmp").write_bytes(b"x" * 200)
    sub = root / "sub"
    sub.mkdir()
    (sub / "f3.tmp").write_bytes(b"x" * 50)
    return {"f1.tmp": 100, "f2.tmp": 200, "sub": 50}


def test_scan_junk_rules_children(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    sizes = build_cache(cache)
    results, warnings = scan_junk_rules([_rule(cache)])
    assert warnings == []
    assert len(results) == 1
    names = {Path(item.path).name: item.size for item in results[0].items}
    assert names["f1.tmp"] == sizes["f1.tmp"]
    assert names["f2.tmp"] == sizes["f2.tmp"]
    assert names["sub"] == sizes["sub"]
    assert results[0].total_size == sum(sizes.values())


def test_scan_junk_rules_missing_root(tmp_path: Path) -> None:
    results, warnings = scan_junk_rules([_rule(tmp_path / "missing")])
    assert len(results) == 1
    assert results[0].items == []
    assert warnings == []


def test_dedupe_junk_results(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    build_cache(cache)
    first = JunkRuleResult(rule=_rule(cache, rule_id="r1"))
    second = JunkRuleResult(rule=_rule(cache, rule_id="r2"))
    results, _warnings = scan_junk_rules([_rule(cache, rule_id="r1"), _rule(cache, rule_id="r2")])
    first.items = list(results[0].items)
    second.items = list(results[0].items)
    removed, warnings = dedupe_junk_results([first, second])
    assert removed == len(first.items)
    assert second.items == []
    assert warnings and warnings[0].code == "junk_duplicates"


def test_scan_space_with_stubbed_overview(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from perf_purifier.module_c.models import LargeFileHit, OverviewEntry
    from perf_purifier.module_c.scanner import OverviewScanResult, WalkStats

    cache = tmp_path / "cache"
    build_cache(cache)

    def fake_drive_usage(root: str) -> tuple[int, int]:
        return 100 * 1024**3, 40 * 1024**3

    def fake_overview(root: str, **kwargs) -> OverviewScanResult:
        return OverviewScanResult(
            entries=[OverviewEntry("Windows", "C:\\Windows", True, 20 * 1024**3, 10, 0.0)],
            top_files=[LargeFileHit("C:\\big.bin", 1024, 0.0)],
            stats=WalkStats(files=10, total_bytes=20 * 1024**3),
            warnings=[],
        )

    monkeypatch.setattr(scan_module.scanner, "drive_usage", fake_drive_usage)
    monkeypatch.setattr(scan_module.scanner, "overview_scan", fake_overview)
    monkeypatch.setattr(scan_module, "select_rules", lambda **_kwargs: [_rule(cache)])

    result = scan_space(config=None, is_admin=False)
    assert result.total_bytes == 100 * 1024**3
    assert result.free_bytes == 40 * 1024**3
    assert result.used_bytes == 60 * 1024**3
    assert result.files_scanned == 10
    assert len(result.overview_entries) == 1
    assert len(result.top_files) == 1
    assert result.verdict is not None
    assert result.junk_total_size == 350


# --------------------------------------------------------------------------- 策略
def test_targets_from_items(tmp_path: Path) -> None:
    item = _item(tmp_path, tmp_path / "f.tmp")
    targets = slim_targets_from_items([item])
    assert len(targets) == 1
    assert targets[0].size == 10
    assert targets[0].root_allowed is True


def test_evaluate_allows_good_targets(tmp_path: Path) -> None:
    items = [_item(tmp_path, tmp_path / "a.tmp"), _item(tmp_path, tmp_path / "b.tmp")]
    targets = slim_targets_from_items(items)
    decision = evaluate_slim_targets(targets, _policy(), _full_verdict(), is_admin=False)
    assert decision.allowed is True
    assert decision.allowed_indices == (0, 1)


def test_evaluate_refuses_when_stage2_disabled(tmp_path: Path) -> None:
    targets = slim_targets_from_items([_item(tmp_path, tmp_path / "a.tmp")])
    decision = evaluate_slim_targets(
        targets, ActionPolicy(stage2_enabled=False), _full_verdict()
    )
    assert decision.allowed is False
    codes = {refusal.code for refusal in decision.refusals}
    assert "stage2_disabled" in codes
    assert "action_disabled" in codes


def test_evaluate_refuses_without_scan_result(tmp_path: Path) -> None:
    targets = slim_targets_from_items([_item(tmp_path, tmp_path / "a.tmp")])
    decision = evaluate_slim_targets(targets, _policy(), None)
    assert decision.allowed is False
    assert "no_scan_result" in {refusal.code for refusal in decision.refusals}


def test_evaluate_refuses_limited_verdict(tmp_path: Path) -> None:
    limited = compute_completeness(ScanStats(total_items=3, budget_truncated=True))
    assert limited.level == "limited"
    targets = slim_targets_from_items([_item(tmp_path, tmp_path / "a.tmp")])
    decision = evaluate_slim_targets(targets, _policy(), limited)
    assert decision.allowed is False
    assert "completeness_limited" in {refusal.code for refusal in decision.refusals}


def test_evaluate_batch_limits(tmp_path: Path) -> None:
    targets = slim_targets_from_items(
        [_item(tmp_path, tmp_path / f"{index}.tmp") for index in range(3)]
    )
    decision = evaluate_slim_targets(
        targets, _policy(max_clean_items=2), _full_verdict(3)
    )
    assert decision.allowed is False
    assert "batch_too_large" in {refusal.code for refusal in decision.refusals}


def test_evaluate_refuses_outside_root(tmp_path: Path) -> None:
    targets = slim_targets_from_items([_item(tmp_path / "cache", tmp_path / "other.tmp")])
    decision = evaluate_slim_targets(targets, _policy(), _full_verdict())
    assert decision.allowed is False
    assert "outside_root" in {refusal.code for refusal in decision.refusals}


def test_evaluate_refuses_admin_required_when_not_admin(tmp_path: Path) -> None:
    targets = slim_targets_from_items(
        [_item(tmp_path, tmp_path / "MRT.exe", requires_admin=True)]
    )
    decision = evaluate_slim_targets(targets, _policy(), _full_verdict(), is_admin=False)
    assert decision.allowed is False
    assert "admin_required" in {refusal.code for refusal in decision.refusals}

    allowed = evaluate_slim_targets(targets, _policy(), _full_verdict(), is_admin=True)
    assert allowed.allowed is True


def test_evaluate_refuses_protected_path(tmp_path: Path) -> None:
    item = _item(
        Path(r"C:\Windows"),
        Path(r"C:\Windows\WinSxS\fake.dll"),
        kind="file",
    )
    targets = slim_targets_from_items([item])
    decision = evaluate_slim_targets(targets, _policy(), _full_verdict())
    assert decision.allowed is False
    assert "protected_path" in {refusal.code for refusal in decision.refusals}


def test_evaluate_refuses_user_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "cache"
    user_data = root / "Docs"
    user_data.mkdir(parents=True)
    item = _item(root, user_data / "note.txt")
    monkeypatch.setattr(
        policy_module, "known_user_data_roots", lambda: (normalize_path(str(user_data)),)
    )
    targets = slim_targets_from_items([item])
    decision = evaluate_slim_targets(targets, _policy(), _full_verdict())
    assert decision.allowed is False
    assert "user_data" in {refusal.code for refusal in decision.refusals}


def test_evaluate_refuses_unknown_special(tmp_path: Path) -> None:
    item = _item(tmp_path, tmp_path / "x", kind="special", special="mystery")
    targets = slim_targets_from_items([item])
    decision = evaluate_slim_targets(targets, _policy(), _full_verdict())
    assert decision.allowed is False
    assert "unknown_special" in {refusal.code for refusal in decision.refusals}


def test_evaluate_allows_recycle_bin_special(tmp_path: Path) -> None:
    item = _item(
        Path("C:\\"), Path("C:\\$Recycle.Bin"), kind="special", special="recycle_bin", size=100
    )
    targets = slim_targets_from_items([item])
    decision = evaluate_slim_targets(targets, _policy(), _full_verdict(), is_admin=False)
    assert decision.allowed is True
    assert any("清空整个回收站" in warning for warning in decision.warnings)


def test_evaluate_refuses_duplicate_paths(tmp_path: Path) -> None:
    same = tmp_path / "a.tmp"
    targets = slim_targets_from_items([_item(tmp_path, same), _item(tmp_path, same)])
    decision = evaluate_slim_targets(targets, _policy(), _full_verdict())
    assert decision.allowed_indices == (0,)
    assert "duplicate_target" in {refusal.code for refusal in decision.refusals}


def test_build_preview_token(tmp_path: Path) -> None:
    items = [_item(tmp_path, tmp_path / "a.tmp", size=100)]
    targets, decision, token = build_slim_preview(
        items, policy=_policy(), verdict=_full_verdict(), is_admin=False, now=1_700_000_000.0
    )
    assert decision.allowed and token is not None
    assert token.action is ActionKind.CLEAN_SPACE
    assert token.item_count == 1
    assert token.total_bytes == 100
    assert token.target_signature


def test_build_preview_none_when_refused(tmp_path: Path) -> None:
    items = [_item(tmp_path, tmp_path / "a.tmp")]
    _targets, decision, token = build_slim_preview(
        items, policy=ActionPolicy(), verdict=_full_verdict(), is_admin=False, now=1_700_000_000.0
    )
    assert token is None
    assert "stage2_disabled" in refusal_text(decision)
