"""Perf Purifier 命令行入口（``python run_cli.py <命令>``）。

与 GUI 共用同一套核心模块（``module_c``）与同一套安全模型：
* 默认只读扫描；``clean --apply`` 才会真正动作；
* 只调用回收站后端（send2trash），失败仅报告，绝不永久删除；
* 执行前逐项重验身份，全部动作写入 ``operations.jsonl`` 审计日志；
* 不联网、不上传数据、不自动提权。

命令::

    overview   空间盘点（分区 / 顶层占用 / 大文件）
    scan       垃圾规则扫描（只读）
    clean      预演 / 执行清理（默认预演，--apply 才执行）
    large      大文件排行（只读）
    history    动作审计历史（只读）
    rules      规则库（只读）
    config     配置与日志路径（只读）
    menu       交互式主菜单（双击 / 无参数时自动进入）
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from . import __version__
from .core import winapi
from .core.action_policy import ActionKind, ActionPolicy
from .core.audit import (
    AUDIT_FILENAME,
    ActionAuditWriter,
    AuditEnd,
    AuditHeader,
    AuditItem,
    AuditWriteError,
    format_audit_timestamp,
    rotate_audit_log,
)
from .core.config import (
    APP_NAME,
    AppConfig,
    app_data_dir,
    config_path,
    default_export_dir,
    log_dir,
)
from .core.console import Console, setup_console_utf8
from .core.fmt import (
    bar,
    format_timestamp,
    human_bytes,
    human_count,
    human_duration_ms,
    parse_size,
    percent_text,
)
from .core.judgements import ScanStats, compute_completeness
from .core.trash import Send2TrashBackend
from .module_c import safety, scanner
from .module_c.executor import SlimDeleteExecutor
from .module_c.models import RISK_CAUTION, RISK_LABELS, RISK_SAFE, RISK_SYSTEM, JunkItem
from .module_c.policy import build_slim_preview, refusal_text
from .module_c.rules import RULES, RULES_BY_ID, risk_sort_key, select_rules
from .module_c.scan import dedupe_junk_results, scan_junk_rules

EXIT_OK = 0
EXIT_FAILED = 2
EXIT_INTERRUPTED = 130


# --------------------------------------------------------------------------- 工具
def _load_config() -> AppConfig:
    return AppConfig.load()


def _make_console(args: argparse.Namespace, config: AppConfig) -> Console:
    color = "never" if getattr(args, "no_color", False) else "auto"
    return Console(color=color)


def _write_json(path: str | None, payload: object) -> int:
    if not path:
        return EXIT_OK
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if path == "-":
        print(text)
        return EXIT_OK
    try:
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"[错误] 写 JSON 失败：{exc}", file=sys.stderr)
        return EXIT_FAILED
    return EXIT_OK


def _version_payload() -> dict:
    return {
        "app": APP_NAME,
        "version": __version__,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "admin": winapi.is_admin(),
        "system_drive": scanner.system_drive(),
    }


def _exclude_roots(config: AppConfig, extra: str | None) -> list[str]:
    roots = [item for item in getattr(config, "slim_exclude_paths", []) if item]
    if extra:
        for chunk in extra.replace(";", ",").split(","):
            value = chunk.strip().strip('"')
            if value and value not in roots:
                roots.append(value)
    return roots


def _split_ids(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [chunk.strip() for chunk in raw.replace(";", ",").split(",") if chunk.strip()]


def _cli_policy(config: AppConfig) -> ActionPolicy:
    """CLI 的显式执行语义：``--apply`` 即本次调用的执行层开关。"""

    return replace(
        ActionPolicy.from_config(config), stage2_enabled=True, allow_clean_space=True
    )


def _verdict(item_count: int, *, is_admin: bool, budget_hit: bool):
    stats = ScanStats(
        total_items=max(0, item_count),
        permission_limited=not is_admin,
        budget_truncated=budget_hit,
    )
    return compute_completeness(stats)


def _budget(args: argparse.Namespace, attr: str, fallback: float) -> float:
    value = getattr(args, attr, None)
    return float(value) if value is not None else float(fallback)


# --------------------------------------------------------------------------- overview
def cmd_overview(args: argparse.Namespace) -> int:
    config = _load_config()
    console = _make_console(args, config)
    drive = scanner.resolve_drive_root(args.drive) or scanner.system_drive()
    total, free = scanner.drive_usage(drive)
    if total <= 0:
        console.error(f"无法读取磁盘信息：{drive}")
        return EXIT_FAILED
    used = total - free
    console.title(f"{APP_NAME} v{__version__} · 空间盘点")

    rows: list[list[str]] = []
    for info in scanner.list_drives(fixed_only=False):
        rows.append(
            [
                info.letter,
                info.type_label,
                human_bytes(info.total_bytes),
                human_bytes(info.used_bytes),
                human_bytes(info.free_bytes),
                percent_text(info.used_bytes, info.total_bytes),
                bar(info.used_bytes / info.total_bytes, 10) if info.total_bytes else "",
            ]
        )
    console.section("磁盘分区")
    console.table(
        ["盘符", "类型", "总量", "已用", "可用", "已用率", ""],
        rows,
        aligns=["left", "left", "right", "right", "right", "right", "left"],
    )

    min_file_size = parse_size(str(args.min_file_size)) or 0
    console.section(f"{drive} 顶层占用（单遍扫描）")
    budget = _budget(args, "budget", config.slim_overview_budget_s)
    result = scanner.overview_scan(
        drive,
        top_files=args.top_files,
        min_file_size=min_file_size,
        progress=lambda files, path: console.progress(f"已扫描 {human_count(files)} 个文件：{path}"),
        budget_s=budget,
    )
    console.progress_done(
        f"扫描完成：{human_count(result.stats.files)} 个文件，{human_duration_ms(result.stats.elapsed_ms)}"
    )
    entries = [entry for entry in result.entries if entry.size > 0]
    console.table(
        ["名称", "占用", "占已用", "文件数"],
        [
            [entry.name, human_bytes(entry.size), percent_text(entry.size, used), human_count(entry.file_count)]
            for entry in entries[: args.top]
        ],
        aligns=["left", "right", "right", "right"],
    )
    for warning in result.warnings:
        console.warn(warning.message)
    if result.top_files:
        console.section(f"最大文件 Top {len(result.top_files)}")
        console.table(
            ["大小", "修改时间", "路径"],
            [[human_bytes(hit.size), format_timestamp(hit.mtime), hit.path] for hit in result.top_files],
            aligns=["right", "left", "left"],
        )
    console.hint("下一步：perfpurifier-cli scan 查看可清理垃圾；perfpurifier-cli clean 预演清理")
    return _write_json(
        args.json,
        {
            **_version_payload(),
            "drive": drive,
            "total_bytes": total,
            "free_bytes": free,
            "used_bytes": used,
            "entries": [
                {"name": e.name, "path": e.path, "size": e.size, "files": e.file_count}
                for e in entries
            ],
            "top_files": [
                {"path": hit.path, "size": hit.size, "mtime": hit.mtime} for hit in result.top_files
            ],
            "elapsed_ms": result.stats.elapsed_ms,
        },
    )


# --------------------------------------------------------------------------- scan
def _scan_junk(
    console: Console,
    config: AppConfig,
    *,
    caution: bool,
    system: bool,
    budget: float,
    exclude: str | None,
) -> tuple[list, list, bool, list[str]]:
    """扫描垃圾规则，返回 ``(results, warnings, is_admin, exclude_roots)``。"""

    is_admin = winapi.is_admin()
    include_caution = bool(caution or config.slim_include_caution)
    include_system = bool(system or config.slim_include_system)
    if include_system and not is_admin:
        console.warn("系统级规则需要管理员权限，已自动跳过（可用管理员终端重试）")
        include_system = False
    excludes = _exclude_roots(config, exclude)
    rules = select_rules(include_caution=include_caution, include_system=include_system)
    results, warnings = scan_junk_rules(
        rules,
        drive=scanner.system_drive(),
        exclude_paths=excludes,
        budget_s=budget,
        progress=lambda _percent, text: console.progress(text),
    )
    dedupe_junk_results(results)
    return results, warnings, is_admin, excludes


def _flatten_items(results: list) -> list[JunkItem]:
    items: list[JunkItem] = []
    for result in results:
        items.extend(result.items)
    return items


def _print_scan_summary(console: Console, results: list) -> None:
    sizes = {RISK_SAFE: 0, RISK_CAUTION: 0, RISK_SYSTEM: 0}
    for result in results:
        sizes[result.rule.risk] = sizes.get(result.rule.risk, 0) + result.total_size
    console.section("可清理汇总")
    console.kv(
        [
            ("安全级（默认清理）", human_bytes(sizes[RISK_SAFE])),
            ("谨慎级（需 --caution）", human_bytes(sizes[RISK_CAUTION])),
            ("系统级（需 --system + 管理员）", human_bytes(sizes[RISK_SYSTEM])),
            ("合计可释放", human_bytes(sum(sizes.values()))),
        ]
    )


def cmd_scan(args: argparse.Namespace) -> int:
    config = _load_config()
    console = _make_console(args, config)
    console.title(f"{APP_NAME} v{__version__} · 垃圾扫描（只读）")
    results, warnings, _is_admin, _excludes = _scan_junk(
        console,
        config,
        caution=bool(args.caution),
        system=bool(args.system),
        budget=_budget(args, "budget", config.slim_junk_budget_s),
        exclude=args.exclude,
    )
    console.progress_done()

    rows: list[list[str]] = []
    empty_rules = 0
    for result in results:
        if result.total_size <= 0 and not args.show_empty:
            empty_rules += 1
            continue
        rows.append(
            [
                result.rule.category,
                result.rule.name,
                RISK_LABELS.get(result.rule.risk, result.rule.risk),
                human_bytes(result.total_size),
                human_count(result.file_count),
                "是" if result.rule.requires_admin else "否",
            ]
        )
    if rows:
        console.section("扫描结果（按规则）")
        console.table(
            ["类别", "规则", "等级", "可释放", "文件数", "需管理员"],
            rows,
            aligns=["left", "left", "left", "right", "right", "left"],
        )
    else:
        console.ok("没有发现可清理的内容（可能已经清理过了）")
    if empty_rules:
        console.dim(f"另有 {empty_rules} 条规则没有匹配到内容（--show-empty 可显示）")

    _print_scan_summary(console, results)
    for warning in warnings:
        console.warn(warning.message)

    items = sorted(_flatten_items(results), key=lambda item: item.size, reverse=True)[:10]
    if items:
        console.section("占用最大的 10 项")
        console.table(
            ["规则", "大小", "路径"],
            [[item.rule_name, human_bytes(item.size_bytes), item.path] for item in items],
            aligns=["left", "right", "left"],
        )
    console.hint("下一步：perfpurifier-cli clean 预演；确认后加 --apply 执行")
    payload = {
        **_version_payload(),
        "total_bytes": sum(result.total_size for result in results),
        "rules": [
            {
                "id": result.rule.id,
                "name": result.rule.name,
                "category": result.rule.category,
                "risk": result.rule.risk,
                "requires_admin": result.rule.requires_admin,
                "total_bytes": result.total_size,
                "files": result.file_count,
                "error": result.error,
            }
            for result in results
        ],
        "items": _items_payload(_flatten_items(results)),
        "warnings": [warning.message for warning in warnings],
    }
    return _write_json(args.json, payload)


def _items_payload(items: list[JunkItem]) -> list[dict]:
    return [
        {
            "rule": item.rule_id,
            "name": item.rule_name,
            "risk": item.risk,
            "kind": item.kind,
            "path": item.path,
            "size": item.size,
            "files": item.file_count,
            "special": item.special,
        }
        for item in items
    ]


# --------------------------------------------------------------------------- clean
def _print_plan(console: Console, items: list[JunkItem]) -> None:
    grouped: dict[str, list[JunkItem]] = {}
    order: list[str] = []
    for item in items:
        if item.rule_id not in grouped:
            grouped[item.rule_id] = []
            order.append(item.rule_id)
        grouped[item.rule_id].append(item)
    order.sort(key=lambda rule_id: risk_sort_key(RULES_BY_ID[rule_id].risk))
    rows = []
    for rule_id in order:
        bucket = grouped[rule_id]
        rule = RULES_BY_ID[rule_id]
        rows.append(
            [
                rule.id,
                rule.name,
                RISK_LABELS.get(rule.risk, rule.risk),
                human_count(len(bucket)),
                human_bytes(sum(item.size_bytes for item in bucket)),
            ]
        )
    console.section("清理计划")
    console.table(
        ["规则 id", "名称", "等级", "项数", "可释放"], rows, aligns=["left", "left", "left", "right", "right"]
    )
    console.kv(
        [
            ("计划项数", human_count(len(items))),
            ("计划释放", human_bytes(sum(item.size_bytes for item in items))),
        ]
    )


def cmd_clean(args: argparse.Namespace) -> int:
    config = _load_config()
    console = _make_console(args, config)
    console.title(f"{APP_NAME} v{__version__} · {'执行清理' if args.apply else '清理预演'}")

    results, warnings, is_admin, excludes = _scan_junk(
        console,
        config,
        caution=bool(args.caution),
        system=bool(args.system),
        budget=_budget(args, "budget", config.slim_junk_budget_s),
        exclude=args.exclude,
    )
    console.progress_done()
    for warning in warnings:
        console.warn(warning.message)

    only_ids = _split_ids(args.only)
    skip_ids = _split_ids(args.skip)
    items: list[JunkItem] = []
    for result in results:
        if only_ids and result.rule.id not in only_ids:
            continue
        if skip_ids and result.rule.id in skip_ids:
            continue
        items.extend(result.items)
    if not items:
        console.ok("没有符合当前筛选条件的清理项")
        console.hint("提示：谨慎级需要 --caution，系统级需要 --system 且管理员权限")
        return EXIT_OK

    policy = _cli_policy(config)
    budget_hit = any(warning.code.endswith("budget") for warning in warnings)
    verdict = _verdict(len(items), is_admin=is_admin, budget_hit=budget_hit)
    _targets, decision, token = build_slim_preview(
        items, policy=policy, verdict=verdict, is_admin=is_admin, now=time.time()
    )
    if token is None or not decision.allowed:
        console.error("策略拒绝执行：")
        console.info(refusal_text(decision))
        return EXIT_FAILED
    allowed_items = [items[index] for index in decision.allowed_indices]
    if decision.refusals:
        console.warn(f"有 {len(decision.refusals)} 项被策略拒绝（越界/受保护/需管理员等）")
    for note in decision.warnings[:5]:
        console.warn(note)

    _print_plan(console, allowed_items)
    total_bytes = sum(item.size_bytes for item in allowed_items)

    if not args.apply:
        console.section("预演结束（未做任何修改）")
        console.info("确认无误后执行：")
        console.info("  perfpurifier-cli clean --apply")
        console.info("  perfpurifier-cli clean --apply --yes --empty-trash   # 清理并立即清空回收站")
        if not args.caution:
            console.info("  perfpurifier-cli clean --apply --caution            # 含谨慎级")
        if not args.system:
            console.info("  perfpurifier-cli clean --apply --system             # 含系统级（需管理员）")
        return _write_json(
            args.json,
            {**_version_payload(), "mode": "dry_run", "items": _items_payload(allowed_items)},
        )

    # ------------------------------------------------------------------ 确认
    console.section("确认执行")
    console.kv(
        [
            ("删除方式", "移动到回收站（可还原；失败不回退永久删除）"),
            ("计划项数", human_count(len(allowed_items))),
            ("预计释放", human_bytes(total_bytes)),
        ]
    )
    if args.empty_trash:
        console.warn("执行后将清空 C 盘回收站（其中可能包含你此前删除的其他文件）")
    if not args.yes:
        if not console.ask_yes_no("确认执行以上清理吗？", default=False):
            console.info("已取消，未做任何修改")
            return EXIT_OK
        if args.empty_trash and not console.ask_yes_no("确认清空回收站吗？", default=False):
            console.info("已取消，未做任何修改")
            return EXIT_OK

    # ------------------------------------------------------------------ 执行
    console.section("开始清理（移动到回收站）")
    executor = SlimDeleteExecutor(
        Send2TrashBackend(), is_admin=is_admin, drive=scanner.system_drive()
    )
    audit_dir = log_dir()
    writer = ActionAuditWriter(audit_dir)
    session_id = uuid.uuid4().hex
    started_at = time.time()
    try:
        writer.write_header(
            AuditHeader(
                ts=format_audit_timestamp(started_at),
                session_id=session_id,
                token_id=token.token_id,
                action=ActionKind.CLEAN_SPACE.value,
                policy_version=token.policy_version,
                verdict_level=verdict.level if verdict else "unknown",
                verdict_codes=tuple(reason.code for reason in verdict.reasons) if verdict else (),
                is_admin=is_admin,
                item_count=len(allowed_items),
                total_bytes=total_bytes,
                app_version=__version__,
                dry_run=False,
            )
        )
    except AuditWriteError as exc:
        console.error(f"审计日志写入失败，已中止执行：{exc}")
        return EXIT_FAILED

    successes = 0
    failures: list[tuple[JunkItem, str, str]] = []
    total = len(allowed_items)
    for position, item in enumerate(allowed_items, start=1):
        item_started = time.time()
        outcome = executor(item)
        duration_ms = max(0, int((time.time() - item_started) * 1000))
        if outcome.result == "success":
            successes += 1
        elif outcome.result in ("failed", "refused"):
            failures.append((item, outcome.error_code, outcome.detail))
        try:
            writer.write_item(
                AuditItem(
                    ts=format_audit_timestamp(time.time()),
                    session_id=session_id,
                    action=ActionKind.CLEAN_SPACE.value,
                    target=item.path,
                    identity=f"path={item.path};size={item.size_bytes};mtime={item.mtime}",
                    result=outcome.result,
                    error_code=outcome.error_code,
                    detail=outcome.detail,
                    duration_ms=duration_ms,
                )
            )
        except AuditWriteError as exc:
            console.error(f"审计日志写入失败，已中止剩余动作：{exc}")
            break
        console.progress(f"清理中 {position}/{total} · 成功 {successes} · 失败 {len(failures)} · {item.rule_name}")

    finished_at = time.time()
    try:
        writer.write_end(
            AuditEnd(
                ts=format_audit_timestamp(finished_at),
                session_id=session_id,
                action=ActionKind.CLEAN_SPACE.value,
                status="completed",
                success=successes,
                failed=len(failures),
                total=total,
            )
        )
    except AuditWriteError as exc:  # pragma: no cover - 结束记录失败只提示
        console.warn(f"审计结束记录写入失败：{exc}")
    rotate_audit_log(audit_dir)
    console.progress_done()

    console.section("清理结果")
    console.kv(
        [
            ("成功", f"{successes} 项"),
            ("失败/拒绝", f"{len(failures)} 项"),
            ("移入回收站", human_bytes(sum(i.size_bytes for i in allowed_items[:successes]))),
            ("耗时", human_duration_ms((finished_at - started_at) * 1000)),
        ]
    )
    if failures:
        console.section("失败明细（最多 10 条）")
        for item, code, detail in failures[:10]:
            console.error(f"{item.path} → {code} {detail}")
        if len(failures) > 10:
            console.dim(f"其余 {len(failures) - 10} 条见审计日志：{audit_dir / AUDIT_FILENAME}")
    console.warn("注意：文件进入回收站后磁盘空间尚未释放，清空回收站后才会真正腾出空间")

    if args.empty_trash:
        ok, message = safety.empty_recycle_bin(scanner.system_drive())
        if ok:
            console.ok(f"{message}，已真正释放空间")
        else:
            console.error(message)

    payload = {
        **_version_payload(),
        "mode": "apply",
        "planned": len(allowed_items),
        "success": successes,
        "failed": len(failures),
        "items": _items_payload(allowed_items),
        "failures": [
            {"path": item.path, "code": code, "detail": detail} for item, code, detail in failures
        ],
    }
    code = _write_json(args.json, payload)
    if code != EXIT_OK:
        return code
    return EXIT_FAILED if failures else EXIT_OK


# --------------------------------------------------------------------------- large
def cmd_large(args: argparse.Namespace) -> int:
    config = _load_config()
    console = _make_console(args, config)
    drive = scanner.resolve_drive_root(args.drive) or scanner.system_drive()
    min_size = parse_size(str(args.min_size))
    if min_size is None:
        console.error(f"无法解析 --min-size：{args.min_size}")
        return EXIT_FAILED
    console.title(f"{APP_NAME} v{__version__} · 大文件排行（只读）")
    budget = _budget(args, "budget", config.slim_overview_budget_s)
    hits, stats = scanner.largest_files(
        drive,
        top=args.top,
        min_size=min_size,
        budget_s=budget,
        progress=lambda files, path: console.progress(f"已扫描 {human_count(files)} 个文件：{path}"),
    )
    console.progress_done(
        f"扫描完成：{human_count(stats.files)} 个文件，累计 {human_bytes(stats.total_bytes)}，"
        f"{human_duration_ms(stats.elapsed_ms)}"
    )
    if not hits:
        console.ok(f"没有发现大于 {human_bytes(min_size)} 的文件")
        return _write_json(args.json, {**_version_payload(), "files": []})
    console.table(
        ["大小", "修改时间", "路径"],
        [[human_bytes(hit.size), format_timestamp(hit.mtime), hit.path] for hit in hits],
        aligns=["right", "left", "left"],
    )
    console.hint("建议：优先迁移到其他盘或确认无用后再手动删除（本工具不删除大文件）")
    return _write_json(
        args.json,
        {
            **_version_payload(),
            "drive": drive,
            "files": [{"path": hit.path, "size": hit.size, "mtime": hit.mtime} for hit in hits],
            "files_scanned": stats.files,
            "elapsed_ms": stats.elapsed_ms,
        },
    )


# --------------------------------------------------------------------------- history
_ACTION_LABELS = {
    ActionKind.CLEAN_SPACE.value: "磁盘清理",
    ActionKind.DELETE_TEMP.value: "删除临时文件",
    ActionKind.HARDLINK_DEDUPE.value: "硬链接去重",
    ActionKind.KILL_PROCESS.value: "结束进程",
    ActionKind.HARDLINK_DETACH.value: "硬链接独立化",
}
_RESULT_LABELS = {"success": "成功", "failed": "失败", "refused": "拒绝", "skipped": "跳过", "dry_run": "预演"}


def _read_audit_records(limit: int) -> tuple[list[dict], int]:
    """读取最近 ``limit`` 条审计记录（含轮转文件），坏行容错。"""

    directory = log_dir()
    candidates: list[Path] = []
    try:
        candidates.extend(
            sorted(directory.glob("operations-*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        )
    except OSError:
        pass
    main_file = directory / AUDIT_FILENAME
    if main_file.exists():
        candidates.insert(0, main_file)
    records: list[dict] = []
    bad_lines = 0
    for path in candidates:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except ValueError:
                bad_lines += 1
                continue
            if isinstance(payload, dict):
                records.append(payload)
    if limit > 0:
        records = records[-limit:]
    return records, bad_lines


def cmd_history(args: argparse.Namespace) -> int:
    config = _load_config()
    console = _make_console(args, config)
    records, bad_lines = _read_audit_records(args.limit)
    console.title(f"{APP_NAME} v{__version__} · 动作历史（只读）")
    if not records:
        console.ok("还没有任何动作记录（执行一次 clean --apply 后会出现在这里）")
        console.hint(f"审计日志位置：{log_dir() / AUDIT_FILENAME}")
        return _write_json(args.json, {**_version_payload(), "records": []})
    rows: list[list[str]] = []
    for record in records:
        record_type = str(record.get("record_type", ""))
        action = _ACTION_LABELS.get(str(record.get("action", "")), str(record.get("action", "")))
        if record_type == "action_item":
            rows.append(
                [
                    str(record.get("ts", "")),
                    "动作",
                    action,
                    _RESULT_LABELS.get(str(record.get("result", "")), str(record.get("result", ""))),
                    str(record.get("target", "")),
                ]
            )
        elif record_type == "action_end":
            rows.append(
                [
                    str(record.get("ts", "")),
                    "会话结束",
                    action,
                    f"成功 {record.get('success', 0)} / 失败 {record.get('failed', 0)}",
                    str(record.get("status", "")),
                ]
            )
        else:
            rows.append(
                [
                    str(record.get("ts", "")),
                    "会话开始",
                    action,
                    f"共 {record.get('item_count', 0)} 项",
                    f"{human_bytes(int(record.get('total_bytes', 0) or 0))}",
                ]
            )
    console.table(
        ["时间", "类型", "动作", "结果", "目标/摘要"],
        rows,
        aligns=["left", "left", "left", "left", "left"],
    )
    if bad_lines:
        console.warn(f"审计日志中有 {bad_lines} 行损坏记录已跳过")
    console.hint(f"审计日志位置：{log_dir() / AUDIT_FILENAME}")
    return _write_json(args.json, {**_version_payload(), "records": records})


# --------------------------------------------------------------------------- rules / config
def cmd_rules(args: argparse.Namespace) -> int:
    config = _load_config()
    console = _make_console(args, config)
    console.title(f"{APP_NAME} v{__version__} · 垃圾规则库")
    categories: dict[str, list] = {}
    for rule in RULES:
        categories.setdefault(rule.category, []).append(rule)
    for category, rules in categories.items():
        if args.category and args.category not in category:
            continue
        console.section(category)
        console.table(
            ["规则 id", "名称", "等级", "删除方式", "需管理员", "根目录示例"],
            [
                [
                    rule.id,
                    rule.name,
                    RISK_LABELS.get(rule.risk, rule.risk),
                    rule.mode_label,
                    "是" if rule.requires_admin else "否",
                    rule.roots[0] if rule.roots else "（专用通道）",
                ]
                for rule in rules
            ],
            aligns=["left", "left", "left", "left", "left", "left"],
        )
    console.dim("等级说明：安全=可直接清理；谨慎=会重新生成或需人工判断；系统=需管理员权限")
    return _write_json(
        args.json,
        {
            **_version_payload(),
            "rules": [
                {
                    "id": rule.id,
                    "name": rule.name,
                    "category": rule.category,
                    "risk": rule.risk,
                    "mode": rule.mode,
                    "roots": list(rule.roots),
                    "file_globs": list(rule.file_globs),
                    "requires_admin": rule.requires_admin,
                    "note": rule.note,
                }
                for rule in RULES
            ],
        },
    )


def cmd_config(args: argparse.Namespace) -> int:
    config = _load_config()
    console = _make_console(args, config)
    console.title(f"{APP_NAME} v{__version__} · 配置")
    console.kv(
        [
            ("程序版本", __version__),
            ("当前权限", "管理员" if winapi.is_admin() else "普通用户"),
            ("配置文件", str(config_path())),
            ("审计日志", str(log_dir() / AUDIT_FILENAME)),
            ("数据目录", str(app_data_dir())),
            ("导出目录", str(default_export_dir())),
            ("执行层总开关", "开启" if config.stage2_enabled else "关闭（默认）"),
            ("磁盘清理开关", "开启" if config.allow_clean_space else "关闭（默认）"),
            ("扫描预算", f"概览 {config.slim_overview_budget_s:.0f}s / 垃圾 {config.slim_junk_budget_s:.0f}s"),
            ("批量上限", f"{config.action_max_clean_items} 项 / {human_bytes(config.action_max_clean_bytes)}"),
            ("排除路径", "、".join(config.slim_exclude_paths) if config.slim_exclude_paths else "（未设置）"),
        ]
    )
    console.hint("提示：CLI 的 clean --apply 是本次调用的显式执行授权；GUI 执行层开关不受影响")
    return EXIT_OK


# --------------------------------------------------------------------------- menu
_MENU_ITEMS: tuple[tuple[str, str, list[str] | None], ...] = (
    ("1", "空间盘点：看看磁盘被谁占了", ["overview"]),
    ("2", "扫描可清理垃圾（只读）", ["scan"]),
    ("3", "预演清理计划（只读）", ["clean"]),
    ("4", "执行清理（移到回收站）", ["clean", "--apply"]),
    ("5", "清理并清空回收站（立即释放空间）", ["clean", "--apply", "--empty-trash"]),
    ("6", "大文件排行", ["large"]),
    ("7", "查看清理历史", ["history"]),
    ("8", "查看规则库", ["rules"]),
    ("9", "查看配置", ["config"]),
    ("0", "退出", None),
)


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return "0"


def run_menu() -> int:
    console = Console(color="auto")
    while True:
        drive = scanner.system_drive()
        total, free = scanner.drive_usage(drive)
        console.title(f"{APP_NAME} v{__version__} · 主菜单")
        if total > 0:
            console.info(
                f"系统盘 {drive}   可用 {human_bytes(free)} / 共 {human_bytes(total)}"
                f"（可用率 {percent_text(free, total)}）"
            )
        console.info("权限：" + ("管理员" if winapi.is_admin() else "普通用户（系统级清理需要管理员）"))
        console.info("")
        for key, label, _argv in _MENU_ITEMS:
            console.info(f"  [{key}] {label}")
        console.info("")
        choice = _ask("  请选择并回车：")
        if choice in ("", "0", "q", "Q", "退出", "exit"):
            console.info("再见。")
            return EXIT_OK
        selected = next((item for item in _MENU_ITEMS if item[0] == choice), None)
        if selected is None or selected[2] is None:
            console.warn("没有这个选项，请重新输入（0 = 退出）。")
            continue
        console.title(f"{APP_NAME} · {selected[1]}")
        try:
            code = main(list(selected[2]))
        except KeyboardInterrupt:
            console.warn("已取消。")
            code = 0
        except Exception as exc:  # noqa: BLE001 - 菜单不能因单个命令崩溃
            console.error(f"该操作出错：{type(exc).__name__}: {exc}")
            code = EXIT_FAILED
        if code not in (0, None):
            console.warn(f"该操作退出码：{code}")
        _ask("\n  按回车返回主菜单…")


def cmd_menu(args: argparse.Namespace) -> int:
    return run_menu()


# --------------------------------------------------------------------------- 参数
def _add_json_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", metavar="路径", default=None, help="把结果导出为 JSON（- 表示打印到屏幕）")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="perfpurifier-cli",
        description=f"{APP_NAME} v{__version__} — 命令行版（默认只读，清理需显式 --apply）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  perfpurifier-cli            # 交互主菜单（有终端时）\n"
            "  perfpurifier-cli overview   # 空间盘点\n"
            "  perfpurifier-cli scan       # 只读扫描可清理垃圾\n"
            "  perfpurifier-cli clean      # 预演（不删除任何东西）\n"
            "  perfpurifier-cli clean --apply --yes --empty-trash   # 执行并立即释放空间\n"
            "  perfpurifier-cli clean --apply --caution --system    # 含谨慎/系统级（需管理员）\n"
            "  perfpurifier-cli large / history / rules / config\n"
            "\n安全：不带 --apply 时不会删除任何东西；删除只进回收站，失败不回退永久删除。"
        ),
    )
    parser.add_argument("--no-color", action="store_true", help="关闭彩色输出")
    parser.add_argument("--version", action="version", version=f"perfpurifier-cli {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<命令>")

    p = subparsers.add_parser("overview", aliases=["盘点"], help="空间盘点")
    p.add_argument("--drive", default=None, help="目标盘符（默认系统盘）")
    p.add_argument("--top", type=int, default=15, help="目录排行数量（默认 15）")
    p.add_argument("--top-files", type=int, default=10, help="大文件排行数量（默认 10）")
    p.add_argument("--min-file-size", default="100MB", help="大文件最小尺寸（默认 100MB）")
    p.add_argument("--budget", type=float, default=None, help="扫描时间预算秒（0 = 不限）")
    _add_json_arg(p)
    p.set_defaults(func=cmd_overview)

    p = subparsers.add_parser("scan", aliases=["扫描"], help="垃圾规则扫描（只读）")
    p.add_argument("--caution", action="store_true", help="包含谨慎级规则")
    p.add_argument("--system", action="store_true", help="包含系统级规则（需管理员）")
    p.add_argument("--show-empty", action="store_true", help="显示没有匹配内容的规则")
    p.add_argument("--exclude", default=None, help="额外排除路径（逗号分隔）")
    p.add_argument("--budget", type=float, default=None, help="扫描时间预算秒（0 = 不限）")
    _add_json_arg(p)
    p.set_defaults(func=cmd_scan)

    p = subparsers.add_parser("clean", aliases=["清理"], help="预演 / 执行清理")
    p.add_argument("--apply", action="store_true", help="真正执行（不带则只预演）")
    p.add_argument("--yes", action="store_true", help="跳过 y/N 确认")
    p.add_argument("--empty-trash", action="store_true", help="清理后清空回收站（立即释放空间）")
    p.add_argument("--caution", action="store_true", help="包含谨慎级规则")
    p.add_argument("--system", action="store_true", help="包含系统级规则（需管理员）")
    p.add_argument("--only", default=None, help="只处理这些规则 id（逗号分隔）")
    p.add_argument("--skip", default=None, help="跳过这些规则 id（逗号分隔）")
    p.add_argument("--exclude", default=None, help="额外排除路径（逗号分隔）")
    p.add_argument("--budget", type=float, default=None, help="扫描时间预算秒（0 = 不限）")
    _add_json_arg(p)
    p.set_defaults(func=cmd_clean)

    p = subparsers.add_parser("large", aliases=["大文件"], help="大文件排行（只读）")
    p.add_argument("--drive", default=None, help="目标盘符（默认系统盘）")
    p.add_argument("--top", type=int, default=30, help="排行数量（默认 30）")
    p.add_argument("--min-size", default="100MB", help="最小尺寸（默认 100MB）")
    p.add_argument("--budget", type=float, default=None, help="扫描时间预算秒（0 = 不限）")
    _add_json_arg(p)
    p.set_defaults(func=cmd_large)

    p = subparsers.add_parser("history", aliases=["历史"], help="动作审计历史（只读）")
    p.add_argument("--limit", type=int, default=30, help="显示最近多少条（默认 30）")
    _add_json_arg(p)
    p.set_defaults(func=cmd_history)

    p = subparsers.add_parser("rules", aliases=["规则"], help="规则库（只读）")
    p.add_argument("--category", default=None, help="只看某个类别")
    _add_json_arg(p)
    p.set_defaults(func=cmd_rules)

    p = subparsers.add_parser("config", aliases=["配置"], help="配置与日志路径（只读）")
    p.set_defaults(func=cmd_config)

    p = subparsers.add_parser("menu", aliases=["菜单"], help="交互式主菜单")
    p.set_defaults(func=cmd_menu)

    return parser


def main(argv: list[str] | None = None) -> int:
    setup_console_utf8()
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        interactive = False
        try:
            interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
        except (AttributeError, OSError):
            interactive = False
        if interactive or os.environ.get("PERFPURIFIER_FORCE_MENU"):
            try:
                return run_menu()
            except KeyboardInterrupt:
                print("\n已退出")
                return EXIT_OK
        parser.print_help()
        return EXIT_OK
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return EXIT_OK
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\n已取消（Ctrl+C）")
        return EXIT_INTERRUPTED
    except BrokenPipeError:  # pragma: no cover - 管道断开
        return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
