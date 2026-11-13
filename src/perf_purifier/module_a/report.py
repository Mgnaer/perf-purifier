"""模块 A 的导出内容构建（CSV / JSON / HTML）。

所有导出文件写入用户选择的位置；默认对命令行脱敏（``AppConfig.cmdline_redact``）。
HTML 报告自包含、所有动态内容经 ``html.escape`` 转义。
"""

from __future__ import annotations

import html
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from ..core.config import APP_VERSION
from ..core.fmt import format_status, format_timestamp, human_bytes, redact_cmdline
from ..core.models import (
    SCHEMA_VERSION,
    ConnectionInfo,
    ProcessScanResult,
    RemoteClass,
    Severity,
    TempEntry,
    completeness_label,
    occupancy_label,
    remote_class_label,
    severity_label,
    signature_label,
)
from ..exporters.csv_writer import write_csv
from ..exporters.html_writer import build_html_document, write_html
from ..exporters.json_writer import write_json

PROCESS_CSV_HEADERS: tuple[str, ...] = (
    "PID",
    "父PID",
    "层级",
    "进程名",
    "用户名",
    "状态",
    "内存(RSS)",
    "创建时间",
    "数字签名",
    "可执行文件路径",
    "风险等级",
    "风险分",
    "命中规则",
    "命令行(脱敏/截断)",
    "数据完整度",
)

NETWORK_CSV_HEADERS: tuple[str, ...] = (
    "进程",
    "PID",
    "协议",
    "IP版本",
    "本地地址",
    "远端地址",
    "连接状态",
    "远端分类",
    "需人工核实",
    "说明",
    "进程路径",
    "进程签名",
)

TEMP_CSV_HEADERS: tuple[str, ...] = (
    "扫描根",
    "条目路径",
    "类型",
    "大小",
    "文件数",
    "最后修改",
    "占用状态",
    "探测说明",
)


# ---------------------------------------------------------------- CSV / JSON
def _cmdline_for_export(info: Any, config: Any) -> str:
    return redact_cmdline(
        info.cmdline,
        enabled=bool(getattr(config, "cmdline_redact", True)),
        max_chars=int(getattr(config, "cmdline_max_chars", 200)),
    )


def build_process_rows(result: ProcessScanResult, config: Any) -> list[list[str]]:
    """按树的先序产出 CSV 行（层级可读）。"""

    tree = result.tree
    rows: list[list[str]] = []
    for node in tree.iter_preorder():
        info = node.info
        rows.append(
            [
                str(info.pid),
                "" if info.ppid < 0 else str(info.ppid),
                str(node.depth),
                info.display_name,
                info.username or "",
                format_status(info.status),
                human_bytes(info.rss),
                format_timestamp(info.create_time),
                signature_label(info.sig_status),
                info.exe or "",
                severity_label(node.risk) if node.flags else "—",
                str(node.score),
                ",".join(node.flag_ids()),
                _cmdline_for_export(info, config),
                completeness_label(tree.completeness),
            ]
        )
    return rows


def export_process_csv(path: str, result: ProcessScanResult, config: Any) -> tuple[bool, str]:
    return write_csv(path, PROCESS_CSV_HEADERS, build_process_rows(result, config))


def _connection_row(connection: ConnectionInfo) -> list[str]:
    return [
        connection.process_label,
        "" if connection.pid is None else str(connection.pid),
        connection.protocol,
        connection.family,
        connection.laddr.text if connection.laddr else "",
        connection.raddr.text if connection.raddr else "",
        connection.status or "—",
        remote_class_label(connection.remote_class),
        "是" if connection.needs_review else "",
        connection.explanation,
        connection.process_exe or "",
        signature_label(connection.process_sig),
    ]


def build_network_rows(result: ProcessScanResult) -> list[list[str]]:
    if result.connections is None:
        return []
    return [_connection_row(connection) for connection in result.connections.connections]


def export_network_csv(path: str, result: ProcessScanResult) -> tuple[bool, str]:
    return write_csv(path, NETWORK_CSV_HEADERS, build_network_rows(result))


def _temp_entry_row(entry: TempEntry) -> list[str]:
    return [
        entry.root,
        entry.path,
        "目录" if entry.is_dir else "文件",
        human_bytes(entry.size),
        str(entry.file_count),
        format_timestamp(entry.mtime),
        occupancy_label(entry.occupancy),
        entry.occupancy_detail,
    ]


def build_temp_rows(result: ProcessScanResult) -> list[list[str]]:
    if result.temp is None:
        return []
    return [_temp_entry_row(entry) for entry in result.temp.entries]


def export_temp_csv(path: str, result: ProcessScanResult) -> tuple[bool, str]:
    return write_csv(path, TEMP_CSV_HEADERS, build_temp_rows(result))


def build_process_export(result: ProcessScanResult, config: Any) -> dict[str, Any]:
    """构建 JSON 导出结构（带 schema_version，便于后续版本兼容）。"""

    tree = result.tree
    by_risk: dict[str, int] = {severity_label(level): 0 for level in Severity}
    for node in tree.nodes.values():
        by_risk[severity_label(node.risk)] = by_risk.get(severity_label(node.risk), 0) + 1

    processes: list[dict[str, Any]] = []
    for node in tree.iter_preorder():
        info = node.info
        processes.append(
            {
                "pid": info.pid,
                "ppid": info.ppid if info.ppid >= 0 else None,
                "depth": node.depth,
                "name": info.display_name,
                "exe": info.exe,
                "cmdline": _cmdline_for_export(info, config),
                "cmdline_redacted": bool(getattr(config, "cmdline_redact", True)),
                "username": info.username,
                "status": info.status,
                "create_time": info.create_time,
                "create_time_text": format_timestamp(info.create_time),
                "rss": info.rss,
                "vms": info.vms,
                "signature": info.sig_status.value,
                "signature_text": signature_label(info.sig_status),
                "signature_publisher": info.sig_publisher,
                "risk": node.risk.value,
                "risk_text": severity_label(node.risk),
                "score": node.score,
                "orphaned": node.orphaned,
                "parent_pid_reused": node.parent_pid_reused,
                "access_errors": list(info.access_errors),
                "flags": [
                    {
                        "rule_id": flag.rule_id,
                        "severity": flag.severity.value,
                        "weight": flag.weight,
                        "title": flag.title,
                        "evidence": flag.evidence,
                    }
                    for flag in node.flags
                ],
            }
        )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "read_only": True,
        "scan": {
            "started_at": format_timestamp(result.started_at),
            "finished_at": format_timestamp(result.finished_at),
            "duration_ms": result.duration_ms,
            "is_admin": result.is_admin,
            "completeness": tree.completeness.value,
            "completeness_text": completeness_label(tree.completeness),
            "total_processes": tree.total_processes,
            "total_in_tree": len(tree.nodes),
            "orphans": len(tree.orphans),
        },
        "counts": {
            "by_risk": by_risk,
            "flagged": len(tree.flagged_nodes()),
            "noticed_or_higher": tree.count_at_least(Severity.NOTICE),
            "suspicious_or_higher": tree.count_at_least(Severity.SUSPICIOUS),
            "high": tree.count_at_least(Severity.HIGH),
        },
        "warnings": [
            {"code": warning.code, "message": warning.message, "path": warning.path, "phase": warning.phase}
            for warning in tree.warnings
        ],
        "processes": processes,
    }

    if result.connections is not None:
        network = result.connections
        payload["network"] = {
            "completeness": network.completeness.value,
            "completeness_text": completeness_label(network.completeness),
            "elapsed_ms": network.elapsed_ms,
            "counts": {
                "total": len(network.connections),
                "public": network.public_count,
                "needs_review": network.review_count,
                "kernel_public": network.kernel_public_count,
                "listen": network.listen_count,
                "established": network.established_count,
            },
            "warnings": [
                {"code": warning.code, "message": warning.message, "phase": warning.phase}
                for warning in network.warnings
            ],
            "connections": [
                {
                    "pid": connection.pid,
                    "process_name": connection.process_name,
                    "process_label": connection.process_label,
                    "process_exe": connection.process_exe,
                    "process_trusted": connection.process_trusted,
                    "process_signature": connection.process_sig.value,
                    "protocol": connection.protocol,
                    "family": connection.family,
                    "laddr": connection.laddr.text if connection.laddr else None,
                    "raddr": connection.raddr.text if connection.raddr else None,
                    "status": connection.status,
                    "remote_class": connection.remote_class.value,
                    "remote_class_text": remote_class_label(connection.remote_class),
                    "is_listen": connection.is_listen,
                    "is_kernel": connection.is_kernel,
                    "needs_review": connection.needs_review,
                    "review_reason": connection.review_reason,
                    "note": connection.note,
                }
                for connection in network.connections
            ],
        }
    else:
        payload["network"] = None

    if result.temp is not None:
        temp = result.temp
        payload["temp"] = {
            "completeness": temp.completeness.value,
            "completeness_text": completeness_label(temp.completeness),
            "elapsed_ms": temp.elapsed_ms,
            "total_size": temp.total_size,
            "total_files": temp.total_files,
            "probed_files": temp.probed_files,
            "probe_candidates": temp.probe_candidates,
            "skipped_reparse": temp.skipped_reparse,
            "unreadable": temp.unreadable,
            "probe_note": temp.probe_note,
            "roots": [
                {"path": root.path, "kind": root.kind, "exists": root.exists} for root in temp.roots
            ],
            "entries": [
                {
                    "root": entry.root,
                    "path": entry.path,
                    "is_dir": entry.is_dir,
                    "size": entry.size,
                    "file_count": entry.file_count,
                    "mtime": entry.mtime,
                    "mtime_text": format_timestamp(entry.mtime),
                    "occupancy": entry.occupancy.value,
                    "occupancy_text": occupancy_label(entry.occupancy),
                    "occupancy_detail": entry.occupancy_detail,
                }
                for entry in temp.entries
            ],
            "warnings": [
                {"code": warning.code, "message": warning.message, "phase": warning.phase}
                for warning in temp.warnings
            ],
        }
    else:
        payload["temp"] = None

    return payload


def export_process_json(path: str, result: ProcessScanResult, config: Any) -> tuple[bool, str]:
    return write_json(path, build_process_export(result, config))


# --------------------------------------------------------------------- HTML
def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _risk_class(level: Severity) -> str:
    return {
        Severity.INFO: "s-info",
        Severity.NOTICE: "s-notice",
        Severity.SUSPICIOUS: "s-suspicious",
        Severity.HIGH: "s-high",
    }.get(level, "s-info")


def _table(headers: Iterable[str], rows: Iterable[Iterable[str]], *, css_class: str = "") -> str:
    head = "".join(f"<th>{_e(header)}</th>" for header in headers)
    body_rows: list[str] = []
    for row in rows:
        cells = "".join(f"<td>{cell}</td>" for cell in row)
        body_rows.append(f"<tr>{cells}</tr>")
    class_attr = f' class="{css_class}"' if css_class else ""
    return f"<table{class_attr}><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def build_report_html(result: ProcessScanResult, config: Any) -> str:
    """构建自包含 HTML 报告正文。"""

    tree = result.tree
    connections = result.connections
    temp = result.temp
    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    badges = [
        '<span class="badge readonly">只读检查模式</span>',
        f'<span class="badge{" admin" if result.is_admin else " warn"}">'
        f'{"管理员权限" if result.is_admin else "普通用户权限（数据可能不完整）"}</span>',
        f'<span class="badge">数据完整度：{_e(completeness_label(tree.completeness))}</span>',
        f'<span class="badge">生成时间：{_e(generated_at)}</span>',
        f'<span class="badge">版本 v{_e(APP_VERSION)}</span>',
    ]

    cards = [
        (tree.total_processes, "进程总数"),
        (tree.count_at_least(Severity.NOTICE), "关注及以上"),
        (tree.count_at_least(Severity.SUSPICIOUS), "可疑及以上"),
        (tree.count_at_least(Severity.HIGH), "高风险"),
        (len(tree.orphans), "孤儿进程"),
    ]
    if connections is not None:
        cards.append((len(connections.connections), "网络连接"))
        cards.append((connections.review_count, "需人工核实连接"))
    if temp is not None:
        cards.append((human_bytes(temp.total_size), "临时文件估算"))
        cards.append((temp.total_files, "临时文件数"))
    cards_html = "".join(
        f'<div class="card"><div class="num">{_e(value)}</div><div class="label">{_e(label)}</div></div>'
        for value, label in cards
    )

    parts: list[str] = [
        f'<div class="meta">{_e("扫描时间")}：{_e(format_timestamp(result.started_at))}　'
        f'耗时：{_e(result.duration_ms)} ms　扫描根目录：本机</div>',
        f'<div class="badges">{"".join(badges)}</div>',
        f'<div class="cards">{cards_html}</div>',
    ]

    if tree.warnings:
        rows = [
            [_e(warning.phase or "—"), _e(warning.code), _e(warning.message), _e(warning.path or "")]
            for warning in tree.warnings
        ]
        parts.append("<h2>扫描提示</h2>")
        parts.append(_table(("阶段", "代码", "说明", "路径"), rows))

    # ---- 风险进程 ----
    flagged = sorted(
        (node for node in tree.flagged_nodes() if node.risk >= Severity.NOTICE),
        key=lambda node: (-int(node.risk), -node.score, node.pid),
    )
    parts.append(f"<h2>风险进程（关注及以上，共 {len(flagged)} 个）</h2>")
    if not flagged:
        parts.append('<p class="muted">本次扫描没有“关注及以上”级别的规则命中。</p>')
    else:
        rows = []
        for node in flagged:
            info = node.info
            flags_html = "<br>".join(
                f'<span class="{_risk_class(flag.severity)}">[{_e(flag.rule_id)}]</span> '
                f"{_e(flag.title)}<br><span class=\"muted\">{_e(flag.evidence)}</span>"
                for flag in node.flags
            )
            rows.append(
                [
                    f'<span class="{_risk_class(node.risk)}">{_e(severity_label(node.risk))}</span>',
                    _e(f"{info.display_name} (PID {info.pid})"),
                    _e(signature_label(info.sig_status)),
                    f'<span class="mono">{_e(info.exe or "不可读")}</span>',
                    flags_html,
                ]
            )
        parts.append(_table(("等级", "进程", "签名", "路径", "命中规则与证据"), rows))

    # ---- 需人工核实的网络连接 ----
    if connections is not None:
        review = [connection for connection in connections.connections if connection.needs_review]
        parts.append(f"<h2>网络连接：需人工核实（共 {len(review)} 条）</h2>")
        parts.append(
            '<p class="muted">判定标准：公网远端，且进程不在受信路径（Windows/Program Files）'
            "且签名非有效签名，或无法关联到进程。这只是提示，不是恶意判定；"
            "离线环境无法可靠识别 CDN，请结合业务自行核实。</p>"
        )
        if connections.kernel_public_count:
            parts.append(
                f'<p class="muted">另有 {connections.kernel_public_count} 条 PID 0 内核/系统公网连接'
                "（无法归因到用户进程，常见于系统服务/代理），未列入需核实清单，"
                "可在下方“全部公网连接”中查看。</p>"
            )
        if not review:
            parts.append('<p class="muted">本次扫描没有需要人工核实的公网连接。</p>')
        else:
            rows = [
                [
                    _e(connection.process_label),
                    _e(connection.pid if connection.pid is not None else "—"),
                    _e(connection.raddr.text if connection.raddr else "—"),
                    _e(connection.laddr.text if connection.laddr else "—"),
                    _e(connection.status or "—"),
                    f'<span class="mono">{_e(connection.process_exe or "不可读")}</span>',
                    _e(connection.explanation),
                ]
                for connection in review
            ]
            parts.append(_table(("进程", "PID", "远端", "本地", "状态", "进程路径", "说明"), rows))

        public = [
            connection
            for connection in connections.connections
            if connection.remote_class is RemoteClass.PUBLIC and not connection.needs_review
        ]
        parts.append("<details>")
        parts.append(f"<summary>查看全部公网连接（{len(public)} 条，已排除需核实项）</summary>")
        rows = [
            [
                _e(connection.process_label),
                _e(connection.pid if connection.pid is not None else "—"),
                _e(connection.raddr.text if connection.raddr else "—"),
                _e(connection.laddr.text if connection.laddr else "—"),
                _e(connection.status or "—"),
                _e(signature_label(connection.process_sig)),
                f'<span class="mono">{_e(connection.process_exe or "")}</span>',
                _e(connection.explanation),
            ]
            for connection in public
        ]
        parts.append(_table(("进程", "PID", "远端", "本地", "状态", "签名", "进程路径", "说明"), rows))
        parts.append("</details>")

    # ---- 临时文件占用 ----
    if temp is not None:
        parts.append("<h2>临时文件占用（估算）</h2>")
        parts.append(
            f'<p class="muted">口径：文件逻辑大小之和；{_e(temp.probe_note)}；'
            "“可能被占用”来自只读探测，杀毒软件等干扰可能造成误判，未探测≠未占用。</p>"
        )
        root_rows = [
            [
                f'<span class="mono">{_e(root.path)}</span>',
                _e(root.kind),
                _e("存在" if root.exists else "不存在"),
                _e(human_bytes(temp.size_for_root(root.path))),
                _e(temp.files_for_root(root.path)),
            ]
            for root in temp.roots
        ]
        parts.append(_table(("临时目录", "类型", "状态", "大小", "文件数"), root_rows))
        entries = temp.entries[:200]
        entry_rows = [
            [
                f'<span class="mono">{_e(entry.path)}</span>',
                _e("目录" if entry.is_dir else "文件"),
                _e(human_bytes(entry.size)),
                _e(entry.file_count),
                _e(format_timestamp(entry.mtime)),
                _e(occupancy_label(entry.occupancy)),
                _e(entry.occupancy_detail),
            ]
            for entry in entries
        ]
        parts.append(f"<h3>占用最大的条目（前 {len(entries)} / 共 {len(temp.entries)} 条）</h3>")
        parts.append(_table(("路径", "类型", "大小", "文件数", "最后修改", "占用状态", "探测说明"), entry_rows))

    # ---- 全部进程 ----
    parts.append("<details>")
    parts.append(f"<summary>查看全部进程（{tree.total_processes} 个）</summary>")
    rows = []
    for node in tree.iter_preorder():
        info = node.info
        rule_ids = ",".join(node.flag_ids()) or "—"
        rows.append(
            [
                f'<span class="{_risk_class(node.risk)}">{_e(severity_label(node.risk) if node.flags else "—")}</span>',
                _e(info.display_name),
                _e(info.pid),
                _e(info.ppid if info.ppid >= 0 else "—"),
                _e(info.username or "不可读"),
                _e(human_bytes(info.rss)),
                _e(signature_label(info.sig_status)),
                f'<span class="mono">{_e(info.exe or "不可读")}</span>',
                _e(rule_ids),
            ]
        )
    parts.append(
        _table(("等级", "进程", "PID", "父PID", "用户", "内存", "签名", "路径", "命中规则"), rows)
    )
    parts.append("</details>")

    parts.append(
        '<div class="notice">安全说明：本报告由只读扫描生成，未结束任何进程、未删除任何文件、'
        "未建立硬链接。所有“可疑/高风险”均为启发式提示，可能误报，请结合业务核实。</div>"
    )

    return build_html_document(
        title="性能与净化 · 只读检查报告",
        subtitle="进程血缘 / 网络连接 / 临时文件占用",
        body_html="\n".join(parts),
    )


def export_report_html(path: str, result: ProcessScanResult, config: Any) -> tuple[bool, str]:
    return write_html(path, build_report_html(result, config))
