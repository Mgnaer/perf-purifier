"""模块 C 导出：空间盘点 CSV / 垃圾明细 CSV / 完整 JSON。

沿用模块 B 的导出风格：CSV 使用 ``utf-8-sig``（Excel 打开中文不乱码）、CRLF 行尾；
JSON 使用 ``ensure_ascii=False`` 便于人读。导出失败返回 ``(False, 原因)`` 不抛异常。
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.fmt import human_bytes
from ..exporters.csv_writer import write_csv
from .models import SpaceScanResult

_OVERVIEW_HEADERS = ("名称", "类型", "占用字节", "占用", "占已用", "文件数", "路径")
_JUNK_HEADERS = ("规则 id", "规则名称", "类别", "风险等级", "类型", "大小字节", "大小", "文件数", "路径")


def build_overview_rows(result: SpaceScanResult) -> list[list[str]]:
    """卷根顶层占用行。"""

    used = result.used_bytes
    rows: list[list[str]] = []
    for entry in result.overview_entries:
        rows.append(
            [
                entry.name,
                "目录" if entry.is_dir else "文件",
                str(entry.size),
                human_bytes(entry.size),
                f"{entry.size / used * 100:.1f}%" if used > 0 else "—",
                str(entry.file_count),
                entry.path,
            ]
        )
    return rows


def build_junk_rows(result: SpaceScanResult) -> list[list[str]]:
    """垃圾明细行（按大小降序）。"""

    items = sorted(result.junk_items, key=lambda item: item.size, reverse=True)
    rows: list[list[str]] = []
    for item in items:
        rows.append(
            [
                item.rule_id,
                item.rule_name,
                item.category,
                item.risk,
                item.kind,
                str(item.size),
                human_bytes(item.size),
                str(item.file_count),
                item.path,
            ]
        )
    return rows


def build_large_file_rows(result: SpaceScanResult) -> list[list[str]]:
    return [
        [hit.path, str(hit.size), human_bytes(hit.size)]
        for hit in result.top_files
    ]


def export_overview_csv(path: str | Path, result: SpaceScanResult) -> tuple[bool, str]:
    return write_csv(path, _OVERVIEW_HEADERS, build_overview_rows(result))


def export_junk_csv(path: str | Path, result: SpaceScanResult) -> tuple[bool, str]:
    return write_csv(path, _JUNK_HEADERS, build_junk_rows(result))


def build_space_export(result: SpaceScanResult) -> dict:
    """完整 JSON 结构（供 CLI ``--json`` 与 GUI 导出共用）。"""

    return {
        "schema": "space_scan/1.0",
        "drive": result.drive,
        "total_bytes": result.total_bytes,
        "free_bytes": result.free_bytes,
        "used_bytes": result.used_bytes,
        "files_scanned": result.files_scanned,
        "elapsed_ms": result.elapsed_ms,
        "include_caution": result.include_caution,
        "include_system": result.include_system,
        "overview_truncated": result.overview_truncated,
        "completeness": {
            "level": result.verdict.level if result.verdict else "unknown",
            "reasons": [
                {"code": reason.code, "text": reason.text}
                for reason in (result.verdict.reasons if result.verdict else ())
            ],
        },
        "overview": [
            {
                "name": entry.name,
                "path": entry.path,
                "is_dir": entry.is_dir,
                "size": entry.size,
                "file_count": entry.file_count,
                "mtime": entry.mtime,
            }
            for entry in result.overview_entries
        ],
        "large_files": [
            {"path": hit.path, "size": hit.size, "mtime": hit.mtime}
            for hit in result.top_files
        ],
        "junk_rules": [
            {
                "id": rule_result.rule.id,
                "name": rule_result.rule.name,
                "category": rule_result.rule.category,
                "risk": rule_result.rule.risk,
                "mode": rule_result.rule.mode,
                "requires_admin": rule_result.rule.requires_admin,
                "total_bytes": rule_result.total_size,
                "files": rule_result.file_count,
                "error": rule_result.error,
                "items": [
                    {
                        "path": item.path,
                        "kind": item.kind,
                        "size": item.size,
                        "files": item.file_count,
                        "special": item.special,
                    }
                    for item in rule_result.items
                ],
            }
            for rule_result in result.junk_results
        ],
        "junk_total_bytes": result.junk_total_size,
        "junk_sizes_by_risk": result.sizes_by_risk(),
        "warnings": [
            {"code": warning.code, "message": warning.message, "path": warning.path}
            for warning in result.warnings
        ],
    }


def export_space_json(path: str | Path, result: SpaceScanResult) -> tuple[bool, str]:
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(build_space_export(result), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return True, f"已写入 {target}"
    except (OSError, TypeError, ValueError) as exc:
        return False, f"写入 JSON 失败：{exc}"


__all__ = [
    "build_junk_rows",
    "build_large_file_rows",
    "build_overview_rows",
    "build_space_export",
    "export_junk_csv",
    "export_overview_csv",
    "export_space_json",
]
