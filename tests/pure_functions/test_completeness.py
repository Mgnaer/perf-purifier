"""任务 4 P0 补测：完整度三档判定（纯函数，无 I/O、无权限依赖、无环境依赖）。

覆盖清单（对应阶段 2 依赖）：
* 2B/2C/2D 动作闸门：``limited`` 应禁止批量动作；``partial`` 允许单条并提示缺失；
* 审计日志：``reasons`` 的 ``code`` 稳定可入库（不随文案变化），档位可复现；
* 边界：比例恰好等于阈值、样本低于绝对下限、预算触顶、空扫描、字段级全不可读。
"""

from __future__ import annotations

from perf_purifier.core.judgements import (
    DEFAULT_UNREADABLE_MIN_ABSOLUTE,
    DEFAULT_UNREADABLE_RATIO_THRESHOLD,
    CompletenessVerdict,
    Reason,
    ScanStats,
    compute_completeness,
    to_completeness,
)
from perf_purifier.core.models import Completeness


def codes(verdict: CompletenessVerdict) -> tuple[str, ...]:
    return tuple(reason.code for reason in verdict.reasons)


# ---------------------------------------------------------------- 三档各 2 例
def test_full_clean_scan() -> None:
    verdict = compute_completeness(ScanStats(total_items=200))
    assert verdict.level == "full"
    assert verdict.reasons == ()
    assert verdict.allows_batch_actions is True


def test_full_with_excluded_items_only() -> None:
    """excluded_items 是用户主动缩小范围，只记录原因，不降档。"""

    verdict = compute_completeness(ScanStats(total_items=200, excluded_items=10))
    assert verdict.level == "full"
    assert codes(verdict) == ("excluded_items",)
    assert "排除" in verdict.reasons[0].text


def test_partial_permission_limited_only() -> None:
    verdict = compute_completeness(ScanStats(total_items=229, permission_limited=True))
    assert verdict.level == "partial"
    assert codes(verdict) == ("permission_limited",)
    assert verdict.allows_batch_actions is True


def test_partial_small_unreadable_counts() -> None:
    verdict = compute_completeness(
        ScanStats(total_items=200, unreadable_items=3, unreadable_fields=1, permission_limited=True)
    )
    assert verdict.level == "partial"
    assert codes(verdict) == ("permission_limited", "unreadable_fields", "unreadable_items")


def test_limited_budget_truncated() -> None:
    """预算截断 = 扫描未完成，即使其它数据干净也必须 limited（阶段 2 禁批量）。"""

    verdict = compute_completeness(ScanStats(total_items=200, budget_truncated=True))
    assert verdict.level == "limited"
    assert codes(verdict) == ("budget_truncated",)
    assert verdict.allows_batch_actions is False


def test_limited_core_enumeration_failed() -> None:
    verdict = compute_completeness(ScanStats(total_items=200, core_enumeration_failed=True))
    assert verdict.level == "limited"
    assert codes(verdict) == ("enumeration_failed",)


# ---------------------------------------------------------------- 比例阈值（limited）
def test_limited_unreadable_ratio_over_threshold() -> None:
    verdict = compute_completeness(ScanStats(total_items=100, unreadable_items=31))
    assert verdict.level == "limited"
    assert codes(verdict) == ("unreadable_ratio",)
    assert "31%" in verdict.reasons[0].text


def test_limited_unreadable_all_items() -> None:
    verdict = compute_completeness(ScanStats(total_items=20, unreadable_items=20))
    assert verdict.level == "limited"
    assert codes(verdict) == ("unreadable_ratio",)


# ---------------------------------------------------------------- 阈值边界
def test_boundary_ratio_equal_threshold_is_partial() -> None:
    """30% 恰好等于阈值：严格大于才 limited；且绝对数 3 < 5 双重未触发。"""

    verdict = compute_completeness(ScanStats(total_items=10, unreadable_items=3))
    assert verdict.level == "partial"
    assert "unreadable_ratio" not in codes(verdict)


def test_boundary_ratio_equal_threshold_with_enough_absolute_is_partial() -> None:
    verdict = compute_completeness(ScanStats(total_items=100, unreadable_items=30))
    assert verdict.level == "partial"
    assert codes(verdict) == ("unreadable_items",)


def test_boundary_ratio_over_but_absolute_below_min_is_partial() -> None:
    """40% > 30%，但只有 4 个不可读对象 → 小样本豁免，降为 partial。"""

    verdict = compute_completeness(ScanStats(total_items=10, unreadable_items=4))
    assert verdict.level == "partial"
    assert "unreadable_ratio" not in codes(verdict)
    assert "small_sample_ratio" in codes(verdict)


def test_boundary_ratio_just_over_with_min_absolute_is_limited() -> None:
    verdict = compute_completeness(ScanStats(total_items=100, unreadable_items=6))
    # 6% 未超 30%，仍是 partial；用于锁定"绝对数够但比例不够"不升级
    assert verdict.level == "partial"
    assert codes(verdict) == ("unreadable_items",)


def test_boundary_fields_all_unreadable_items_zero_is_partial() -> None:
    """字段级不可读不升级 limited（非管理员常态）。"""

    verdict = compute_completeness(ScanStats(total_items=200, unreadable_fields=9))
    assert verdict.level == "partial"
    assert codes(verdict) == ("unreadable_fields",)


def test_boundary_empty_scan_is_limited_no_data() -> None:
    verdict = compute_completeness(ScanStats(total_items=0))
    assert verdict.level == "limited"
    assert codes(verdict) == ("no_data",)


def test_boundary_budget_truncated_and_empty_scan_reasons_order() -> None:
    verdict = compute_completeness(ScanStats(total_items=0, budget_truncated=True))
    assert verdict.level == "limited"
    assert codes(verdict) == ("budget_truncated", "no_data")


# ---------------------------------------------------------------- 组合与参数覆盖
def test_limited_wins_over_partial_reasons() -> None:
    verdict = compute_completeness(
        ScanStats(
            total_items=100,
            unreadable_items=80,
            unreadable_fields=20,
            permission_limited=True,
            budget_truncated=True,
        )
    )
    assert verdict.level == "limited"
    # limited 时只保留 limited 级原因，避免 UI 噪音
    assert codes(verdict) == ("budget_truncated", "unreadable_ratio")


def test_excluded_items_never_changes_level() -> None:
    partial = compute_completeness(ScanStats(total_items=50, unreadable_items=1, excluded_items=7))
    limited = compute_completeness(ScanStats(total_items=10, budget_truncated=True, excluded_items=3))
    assert partial.level == "partial"
    assert "excluded_items" in codes(partial)
    assert limited.level == "limited"
    assert "excluded_items" in codes(limited)


def test_custom_thresholds_can_be_overridden() -> None:
    strict = compute_completeness(
        ScanStats(total_items=10, unreadable_items=6),
        ratio_threshold=0.5,
        min_absolute=5,
    )
    assert strict.level == "limited"
    relaxed = compute_completeness(
        ScanStats(total_items=10, unreadable_items=6),
        ratio_threshold=0.5,
        min_absolute=10,
    )
    assert relaxed.level == "partial"


def test_invalid_threshold_falls_back_to_default() -> None:
    verdict = compute_completeness(ScanStats(total_items=100, unreadable_items=40), ratio_threshold=2.0)
    assert verdict.level == "limited"
    assert DEFAULT_UNREADABLE_RATIO_THRESHOLD == 0.30
    assert DEFAULT_UNREADABLE_MIN_ABSOLUTE == 5


def test_negative_inputs_are_clamped() -> None:
    verdict = compute_completeness(ScanStats(total_items=-5, unreadable_items=-1, unreadable_fields=-2))
    assert verdict.level == "limited"
    assert codes(verdict) == ("no_data",)


# ---------------------------------------------------------------- 适配与纯函数性
def test_to_completeness_adapter_mapping() -> None:
    assert to_completeness(compute_completeness(ScanStats(total_items=10))) is Completeness.FULL
    assert (
        to_completeness(compute_completeness(ScanStats(total_items=10, permission_limited=True)))
        is Completeness.PARTIAL
    )
    assert (
        to_completeness(compute_completeness(ScanStats(total_items=10, budget_truncated=True)))
        is Completeness.DEGRADED
    )


def test_reason_codes_are_stable_and_texts_non_empty() -> None:
    verdict = compute_completeness(
        ScanStats(
            total_items=100,
            unreadable_items=1,
            unreadable_fields=2,
            permission_limited=True,
            excluded_items=4,
        )
    )
    assert codes(verdict) == (
        "permission_limited",
        "unreadable_fields",
        "unreadable_items",
        "excluded_items",
    )
    assert all(isinstance(reason, Reason) and reason.text for reason in verdict.reasons)


def test_verdict_and_stats_are_immutable() -> None:
    from dataclasses import FrozenInstanceError

    import pytest

    stats = ScanStats(total_items=10)
    verdict = compute_completeness(stats)
    with pytest.raises(FrozenInstanceError):
        stats.total_items = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        verdict.level = "full"  # type: ignore[misc]
