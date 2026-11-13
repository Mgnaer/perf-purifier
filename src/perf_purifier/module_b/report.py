"""模块 B 导出内容构建（CSV / JSON / HTML）。

HTML 报告自包含、动态内容全部 ``html.escape``；不包含任何删除/硬链接操作入口。
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

from ..core.config import APP_VERSION
from ..core.fmt import format_timestamp, human_bytes
from ..core.models import (
    FILE_SCAN_SCHEMA_VERSION,
    DuplicateGroup,
    FileRecord,
    FileScanResult,
    completeness_label,
)
from ..exporters.csv_writer import write_csv
from ..exporters.html_writer import build_html_document, write_html
from ..exporters.json_writer import write_json

DUPLICATE_CSV_HEADERS: tuple[str, ...] = (
    "组号",
    "单文件大小",
    "文件数",
    "可回收(硬链接感知)",
    "硬链接情况",
    "建议保留",
    "SHA256",
    "文件列表",
)

DUPLICATE_FILE_CSV_HEADERS: tuple[str, ...] = (
    "组号",
    "文件路径",
    "大小",
    "修改时间",
    "设备号",
    "inode",
    "硬链接副本",
    "建议保留",
)

LARGE_FILE_CSV_HEADERS: tuple[str, ...] = ("排名", "文件路径", "大小", "修改时间")


# ---------------------------------------------------------------- 通用格式
def _hardlink_text(group: DuplicateGroup) -> str:
    if group.already_hardlinked:
        return "已互为硬链接（删除无收益）"
    if group.has_hardlinks:
        return f"含硬链接副本（{group.distinct_inodes}/{len(group.files)} 个独立文件）"
    return "无硬链接"


def _identity_counts(group: DuplicateGroup) -> dict[tuple[int, int], int]:
    counts: dict[tuple[int, int], int] = {}
    for record in group.files:
        counts[record.identity] = counts.get(record.identity, 0) + 1
    return counts


# ---------------------------------------------------------------- CSV
def build_duplicate_rows(result: FileScanResult) -> list[list[str]]:
    rows: list[list[str]] = []
    for group in result.duplicate_groups:
        rows.append(
            [
                str(group.group_id),
                human_bytes(group.size),
                str(len(group.files)),
                human_bytes(group.reclaimable_bytes),
                _hardlink_text(group),
                group.suggested_keep_path,
                group.full_sha256,
                " | ".join(record.path for record in group.files),
            ]
        )
    return rows


def export_duplicates_csv(path: str, result: FileScanResult) -> tuple[bool, str]:
    return write_csv(path, DUPLICATE_CSV_HEADERS, build_duplicate_rows(result))


def build_duplicate_file_rows(result: FileScanResult) -> list[list[str]]:
    rows: list[list[str]] = []
    for group in result.duplicate_groups:
        counts = _identity_counts(group)
        for record in group.files:
            rows.append(
                [
                    str(group.group_id),
                    record.path,
                    human_bytes(record.size),
                    format_timestamp(record.mtime),
                    str(record.dev),
                    str(record.ino),
                    "是" if counts.get(record.identity, 0) > 1 else "",
                    "是" if record.path == group.suggested_keep_path else "",
                ]
            )
    return rows


def export_duplicate_files_csv(path: str, result: FileScanResult) -> tuple[bool, str]:
    return write_csv(path, DUPLICATE_FILE_CSV_HEADERS, build_duplicate_file_rows(result))


def build_large_file_rows(result: FileScanResult) -> list[list[str]]:
    return [
        [str(index), item.path, human_bytes(item.size), format_timestamp(item.mtime)]
        for index, item in enumerate(result.large_files, start=1)
    ]


def export_large_files_csv(path: str, result: FileScanResult) -> tuple[bool, str]:
    return write_csv(path, LARGE_FILE_CSV_HEADERS, build_large_file_rows(result))


# ---------------------------------------------------------------- JSON
def _record_json(record: FileRecord) -> dict[str, Any]:
    return {
        "path": record.path,
        "size": record.size,
        "mtime": record.mtime,
        "mtime_text": format_timestamp(record.mtime),
        "dev": record.dev,
        "ino": record.ino,
    }


def build_file_scan_export(result: FileScanResult) -> dict[str, Any]:
    options = result.options
    return {
        "schema_version": FILE_SCAN_SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "read_only": True,
        "scan": {
            "root": result.root,
            "started_at": format_timestamp(result.started_at),
            "finished_at": format_timestamp(result.finished_at),
            "duration_ms": result.duration_ms,
            "completeness": result.completeness.value,
            "completeness_text": completeness_label(result.completeness),
            "truncated": result.truncated,
            "options": {
                "min_size": options.min_size,
                "max_files": options.max_files,
                "walk_budget_s": options.walk_budget_s,
                "large_limit": options.large_limit,
                "exclude_patterns": list(options.exclude_patterns),
                "extensions": list(options.extensions),
                "modified_after": options.modified_after,
                "hash_workers": options.hash_workers,
                "use_cache": options.use_cache,
            },
        },
        "summary": {
            "files_scanned": result.files_scanned,
            "dirs_scanned": result.dirs_scanned,
            "total_bytes": result.total_bytes,
            "skipped_reparse": result.skipped_reparse,
            "skipped_unreadable": result.skipped_unreadable,
            "skipped_cloud": result.skipped_cloud,
            "skipped_excluded": result.skipped_excluded,
            "failed_reads": result.failed_reads,
            "unstable_files": result.unstable_files,
            "partial_hashed": result.partial_hashed,
            "full_hashed": result.full_hashed,
            "cache_hits": result.cache_hits,
            "hash_bytes": result.hash_bytes,
            "hash_workers": result.hash_workers,
            "media_type": result.media_type,
            "duplicate_groups": len(result.duplicate_groups),
            "duplicate_files": result.duplicate_file_count,
            "reclaimable_bytes": result.reclaimable_bytes,
        },
        "duplicate_groups": [
            {
                "group_id": group.group_id,
                "size": group.size,
                "file_count": len(group.files),
                "reclaimable_bytes": group.reclaimable_bytes,
                "distinct_inodes": group.distinct_inodes,
                "has_hardlinks": group.has_hardlinks,
                "already_hardlinked": group.already_hardlinked,
                "hardlink_text": _hardlink_text(group),
                "suggested_keep_path": group.suggested_keep_path,
                "sha256": group.full_sha256,
                "files": [
                    {
                        **_record_json(record),
                        "suggested_keep": record.path == group.suggested_keep_path,
                    }
                    for record in group.files
                ],
            }
            for group in result.duplicate_groups
        ],
        "large_files": [
            {
                "rank": index,
                "path": item.path,
                "size": item.size,
                "mtime": item.mtime,
                "mtime_text": format_timestamp(item.mtime),
            }
            for index, item in enumerate(result.large_files, start=1)
        ],
        "warnings": [
            {"code": warning.code, "message": warning.message, "path": warning.path, "phase": warning.phase}
            for warning in result.warnings
        ],
    }


def export_file_scan_json(path: str, result: FileScanResult) -> tuple[bool, str]:
    return write_json(path, build_file_scan_export(result))


# ---------------------------------------------------------------- HTML
def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _table(headers: tuple[str, ...], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_e(header)}</th>" for header in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def build_file_report_html(result: FileScanResult) -> str:
    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    badges = [
        '<span class="badge readonly">只读检查模式</span>',
        f'<span class="badge">数据完整度：{_e(completeness_label(result.completeness))}</span>',
        f'<span class="badge">生成时间：{_e(generated_at)}</span>',
        f'<span class="badge">版本 v{_e(APP_VERSION)}</span>',
    ]
    cards = [
        (result.files_scanned, "扫描文件数"),
        (human_bytes(result.total_bytes), "文件总大小"),
        (len(result.duplicate_groups), "重复组"),
        (result.duplicate_file_count, "重复文件数"),
        (human_bytes(result.reclaimable_bytes), "可回收估算"),
    ]
    if result.cache_hits:
        cards.append((result.cache_hits, "哈希缓存命中"))
    cards_html = "".join(
        f'<div class="card"><div class="num">{_e(value)}</div><div class="label">{_e(label)}</div></div>'
        for value, label in cards
    )
    parts = [
        f'<div class="meta">扫描目录：<span class="mono">{_e(result.root)}</span>　'
        f"耗时：{_e(result.duration_ms)} ms　最小文件：{_e(human_bytes(result.options.min_size))}　"
        f"哈希并发：{_e(result.hash_workers)}（介质 {_e(result.media_type)}）　"
        f"排除跳过：{_e(result.skipped_excluded)}</div>",
        f'<div class="badges">{"".join(badges)}</div>',
        f'<div class="cards">{cards_html}</div>',
    ]

    if result.warnings:
        rows = [
            [_e(warning.phase or "—"), _e(warning.code), _e(warning.message), _e(warning.path or "")]
            for warning in result.warnings
        ]
        parts.append("<h2>扫描提示</h2>")
        parts.append(_table(("阶段", "代码", "说明", "路径"), rows))

    parts.append(f"<h2>重复文件分组（共 {len(result.duplicate_groups)} 组）</h2>")
    parts.append(
        '<p class="muted">口径：先按大小分桶，再比对前 4KB 指纹与全文件 SHA-256；'
        "硬链接副本指向同一份数据，删除不会释放空间，因此不计入可回收估算。</p>"
    )
    if not result.duplicate_groups:
        parts.append('<p class="muted">未发现重复文件。</p>')
    else:
        rows = []
        for group in result.duplicate_groups:
            file_lines = "<br>".join(
                f'<span class="mono">{_e(record.path)}</span>'
                f'<span class="muted">（{_e(human_bytes(record.size))}，'
                f"{_e(format_timestamp(record.mtime))}）</span>"
                + ("　<b>建议保留</b>" if record.path == group.suggested_keep_path else "")
                for record in group.files
            )
            rows.append(
                [
                    _e(group.group_id),
                    _e(human_bytes(group.size)),
                    _e(len(group.files)),
                    _e(human_bytes(group.reclaimable_bytes)),
                    _e(_hardlink_text(group)),
                    f'<span class="mono">{_e(group.suggested_keep_path or "—")}</span>',
                    file_lines,
                ]
            )
        parts.append(_table(("组号", "单文件大小", "文件数", "可回收(硬链接感知)", "硬链接情况", "建议保留", "文件列表"), rows))

    parts.append(f"<h2>大文件排行（Top {len(result.large_files)}）</h2>")
    if not result.large_files:
        parts.append('<p class="muted">未扫描到文件。</p>')
    else:
        rows = [
            [
                _e(index),
                f'<span class="mono">{_e(item.path)}</span>',
                _e(human_bytes(item.size)),
                _e(format_timestamp(item.mtime)),
            ]
            for index, item in enumerate(result.large_files, start=1)
        ]
        parts.append(_table(("排名", "文件路径", "大小", "修改时间"), rows))

    parts.append(
        '<div class="notice">安全说明：本报告由只读扫描生成，未删除任何文件、未建立任何硬链接。'
        "重复文件与“可回收空间”为扫描估算，删除/硬链接能力将在后续阶段提供，"
        "并会要求预览、二次确认与操作日志。</div>"
    )
    return build_html_document(
        title="性能与净化 · 重复文件与大文件报告",
        subtitle="只读扫描：大小分桶 → 4KB 指纹 → SHA-256 全量哈希",
        body_html="\n".join(parts),
    )


def export_file_report_html(path: str, result: FileScanResult) -> tuple[bool, str]:
    return write_html(path, build_file_report_html(result))
