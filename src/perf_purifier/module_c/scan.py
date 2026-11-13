"""模块 C 扫描编排：空间盘点 + 垃圾规则扫描（只读，可取消）。

一次调用产出 :class:`~perf_purifier.module_c.models.SpaceScanResult`：

1. 读取分区用量（快速）；
2. 单遍全盘概览（顶层子项占用 + 最大文件）；
3. 按用户选择的风险等级逐条扫描垃圾规则；
4. 跨规则按物理路径去重、汇总告警、判定数据完整度（``limited`` 时禁止批量动作）。
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Sequence

from ..core.cancel import CancelToken
from ..core.judgements import ScanStats, compute_completeness, to_completeness
from ..core.models import ScanWarning
from . import safety, scanner
from .models import (
    MODE_CHILDREN,
    MODE_FILES,
    MODE_TREE,
    RISK_SAFE,
    JunkItem,
    JunkRule,
    JunkRuleResult,
    SpaceScanResult,
)
from .rules import resolve_roots, select_rules

ProgressCallback = Callable[[int, str], None]
"""``progress(percent 0-100, text)``。"""


def _is_excluded(path: str, exclude_roots: Sequence[str]) -> bool:
    return bool(exclude_roots) and safety.is_under(path, tuple(exclude_roots))


def _make_item(
    rule: JunkRule,
    *,
    path: str,
    size: int,
    file_count: int,
    mtime: float,
    kind: str,
    allowed_root: str,
    special: str = "",
) -> JunkItem:
    return JunkItem(
        rule_id=rule.id,
        rule_name=rule.name,
        category=rule.category,
        risk=rule.risk,
        path=path,
        size=max(0, int(size)),
        file_count=max(0, int(file_count)),
        mtime=float(mtime or 0.0),
        kind=kind,
        allowed_root=allowed_root,
        requires_admin=rule.requires_admin,
        note=rule.note,
        special=special,
    )


def _scan_recycle_bin(rule: JunkRule, drive: str) -> list[JunkItem]:
    items, size = safety.query_recycle_bin(drive)
    if items <= 0 and size <= 0:
        return []
    return [
        _make_item(
            rule,
            path=os.path.join(drive, "$Recycle.Bin"),
            size=size,
            file_count=items,
            mtime=0.0,
            kind="special",
            allowed_root=drive,
            special="recycle_bin",
        )
    ]


def _scan_defender_platforms(rule: JunkRule) -> tuple[list[JunkItem], str]:
    platform = safety.defender_platform_dir()
    if not os.path.isdir(platform):
        return [], ""
    items: list[JunkItem] = []
    try:
        entries = list(os.scandir(platform))
    except OSError as exc:
        return [], f"无法读取 {platform}：{exc}"
    for entry in entries:
        try:
            if not entry.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        if not safety.is_defender_platform_old_version(entry.path):
            continue
        stats = scanner.walk_size(entry.path)
        items.append(
            _make_item(
                rule,
                path=entry.path,
                size=stats.total_bytes,
                file_count=stats.files,
                mtime=0.0,
                kind="dir",
                allowed_root=platform,
                special="defender_platforms",
            )
        )
    return items, ""


def scan_rule(
    rule: JunkRule,
    *,
    token: CancelToken | None = None,
    drive: str | None = None,
    exclude_paths: Sequence[str] = (),
    progress: ProgressCallback | None = None,
) -> JunkRuleResult:
    """只读扫描单条规则。"""

    result = JunkRuleResult(rule=rule)
    if rule.mode == "special":
        try:
            if rule.special == "recycle_bin":
                result.items = _scan_recycle_bin(rule, drive or scanner.system_drive())
            elif rule.special == "defender_platforms":
                result.items, error = _scan_defender_platforms(rule)
                result.error = error
            else:
                result.error = f"未知的专用通道：{rule.special}"
        except OSError as exc:
            result.error = f"扫描失败：{exc}"
        return result

    roots = resolve_roots(rule)
    for root in roots:
        if _is_excluded(root, exclude_paths):
            continue
        if progress is not None:
            progress(0, f"扫描 {rule.name}：{root}")
        if rule.mode == MODE_TREE:
            stats = scanner.walk_size(root, token=token)
            result.items.append(
                _make_item(
                    rule,
                    path=root,
                    size=stats.total_bytes,
                    file_count=stats.files,
                    mtime=_safe_mtime(root),
                    kind="dir",
                    allowed_root=root,
                )
            )
            continue
        if rule.mode == MODE_CHILDREN:
            for child in scanner.list_children(root, token=token):
                if _is_excluded(child.path, exclude_paths):
                    continue
                if child.is_reparse:
                    continue
                result.items.append(
                    _make_item(
                        rule,
                        path=child.path,
                        size=child.size,
                        file_count=child.file_count,
                        mtime=child.mtime,
                        kind="dir" if child.is_dir else "file",
                        allowed_root=root,
                    )
                )
            continue
        if rule.mode == MODE_FILES:
            import glob  # noqa: PLC0415 - 局部使用

            for pattern in rule.file_globs:
                for match in glob.glob(os.path.join(root, pattern)):
                    if not os.path.isfile(match):
                        continue
                    if _is_excluded(match, exclude_paths):
                        continue
                    if safety.is_reparse_point(match) is True:
                        continue
                    try:
                        stat_result = os.stat(match, follow_symlinks=False)
                    except OSError:
                        continue
                    result.items.append(
                        _make_item(
                            rule,
                            path=match,
                            size=int(stat_result.st_size),
                            file_count=1,
                            mtime=float(stat_result.st_mtime),
                            kind="file",
                            allowed_root=root,
                        )
                    )
    result.items.sort(key=lambda item: item.size, reverse=True)
    return result


def _safe_mtime(path: str) -> float:
    try:
        return float(os.stat(path, follow_symlinks=False).st_mtime)
    except OSError:
        return 0.0


def scan_junk_rules(
    rules: Sequence[JunkRule],
    *,
    token: CancelToken | None = None,
    drive: str | None = None,
    exclude_paths: Sequence[str] = (),
    budget_s: float = 0.0,
    progress: ProgressCallback | None = None,
) -> tuple[list[JunkRuleResult], list[ScanWarning]]:
    """只扫描垃圾规则（不做空间盘点，CLI ``scan`` 用这条快路径）。"""

    results: list[JunkRuleResult] = []
    warnings: list[ScanWarning] = []
    started = time.monotonic()
    for index, rule in enumerate(rules):
        if token is not None:
            token.raise_if_cancelled("磁盘垃圾扫描")
        if budget_s > 0 and (time.monotonic() - started) > budget_s:
            warnings.append(
                ScanWarning(
                    "junk_budget",
                    f"垃圾规则扫描达到时间预算（{budget_s:.0f}s），结果可能不完整",
                    phase="junk",
                )
            )
            break
        if progress is not None:
            percent = int((index / max(1, len(rules))) * 100)
            progress(percent, f"扫描规则 {index + 1}/{len(rules)}：{rule.name}")
        rule_result = scan_rule(
            rule,
            token=token,
            drive=drive,
            exclude_paths=exclude_paths,
        )
        results.append(rule_result)
        if rule_result.error:
            warnings.append(
                ScanWarning("junk_rule_error", f"[{rule.name}] {rule_result.error}", phase="junk")
            )
    return results, warnings


def dedupe_junk_results(results: Sequence[JunkRuleResult]) -> tuple[int, list[ScanWarning]]:
    """跨规则按物理路径去重（原地修改），返回 ``(合并数量, 告警)``。"""

    seen: set[str] = set()
    removed = 0
    for rule_result in results:
        kept: list[JunkItem] = []
        for item in rule_result.items:
            key = item.path if item.is_special else safety.canonical_key(item.path)
            if key and key in seen:
                removed += 1
                continue
            if key:
                seen.add(key)
            kept.append(item)
        rule_result.items = kept
    warnings: list[ScanWarning] = []
    if removed:
        warnings.append(
            ScanWarning(
                "junk_duplicates",
                f"已合并 {removed} 个重复项（同一路径被多条规则命中）",
                phase="junk",
            )
        )
    return removed, warnings


def scan_space(
    *,
    drive: str | None = None,
    token: CancelToken | None = None,
    config: object | None = None,
    is_admin: bool = False,
    include_caution: bool = False,
    include_system: bool = False,
    top_files: int = 10,
    min_file_size: int = 0,
    progress: ProgressCallback | None = None,
) -> SpaceScanResult:
    """执行一次完整的「磁盘空间」扫描（只读，不修改任何文件）。"""

    started = time.monotonic()
    target_drive = safety.normalize_path(drive) if drive else scanner.system_drive()
    if target_drive and not target_drive.endswith(os.sep):
        target_drive += os.sep

    exclude_paths: list[str] = list(getattr(config, "slim_exclude_paths", []) or [])
    overview_budget = float(getattr(config, "slim_overview_budget_s", 60.0) or 0.0)
    junk_budget = float(getattr(config, "slim_junk_budget_s", 60.0) or 0.0)

    result = SpaceScanResult(
        drive=target_drive,
        include_caution=include_caution,
        include_system=include_system,
    )
    total, free = scanner.drive_usage(target_drive)
    result.total_bytes = total
    result.free_bytes = free

    if progress is not None:
        progress(3, "读取分区信息…")

    def overview_progress(files: int, current: str) -> None:
        if progress is not None:
            percent = 5 + min(50, int(files / 2000))
            progress(percent, f"空间盘点：{files:,} 个文件 · {current}")

    overview = scanner.overview_scan(
        target_drive,
        token=token,
        top_files=top_files,
        min_file_size=min_file_size,
        progress=overview_progress,
        budget_s=overview_budget,
    )
    result.overview_entries = overview.entries
    result.top_files = overview.top_files
    result.overview_truncated = overview.stats.truncated
    result.files_scanned = overview.stats.files
    result.warnings.extend(overview.warnings)

    rules = select_rules(include_caution=include_caution, include_system=include_system)
    rule_results, rule_warnings = scan_junk_rules(
        rules,
        token=token,
        drive=target_drive,
        exclude_paths=exclude_paths,
        budget_s=junk_budget,
        progress=progress,
    )
    result.junk_results = rule_results
    result.warnings.extend(rule_warnings)
    _removed, dedupe_warnings = dedupe_junk_results(result.junk_results)
    result.warnings.extend(dedupe_warnings)

    items = result.junk_items
    stats = ScanStats(
        total_items=len(items),
        unreadable_items=sum(1 for warning in result.warnings if warning.code.endswith("unreadable")),
        permission_limited=not is_admin,
        budget_truncated=bool(result.overview_truncated)
        or any(not result.overview_truncated and w.code.endswith("budget") for w in result.warnings),
    )
    verdict = compute_completeness(stats)
    result.verdict = verdict
    result.completeness = to_completeness(verdict)
    result.elapsed_ms = int((time.monotonic() - started) * 1000)
    if progress is not None:
        progress(100, "扫描完成")
    return result


def risk_safe_default() -> str:
    return RISK_SAFE


__all__ = ["dedupe_junk_results", "scan_junk_rules", "scan_rule", "scan_space"]
