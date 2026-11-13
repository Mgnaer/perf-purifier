"""网络连接采集与远端地址分类（只读）。

关联逻辑：
* 通过 ``psutil.net_connections(kind='inet')`` 读取全机连接（失败时降级为逐进程读取）；
* 用 PID 关联进程快照（名称/路径/签名/是否受信路径）；
* 远端地址分类：回环 / 内网 / 运营商 NAT / 链路本地 / 组播 / 保留 / 公网；
* "未知外网连接（需人工核实）" = 公网远端 且 进程不在受信路径 且 签名不是有效签名，
  或无法关联到进程。**这只是需要人工核实的提示，不是恶意判定。**

免责与限制：
* 离线无法可靠识别 CDN/云厂商，因此不做此类判定；
* 反向 DNS 会阻塞/联网，默认不做；
* 非管理员时个别连接可能不可读，结果标注数据完整度。
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from collections.abc import Callable, Mapping
from typing import Any

import psutil

from ..core.cancel import CancelToken
from ..core.models import (
    Completeness,
    ConnectionInfo,
    Endpoint,
    NetworkScanResult,
    ProcessInfo,
    RemoteClass,
    ScanWarning,
    SigStatus,
    signature_label,
)
from ..core.whitelist import Whitelist

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int, int], None]

_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def classify_address(address: str | None) -> RemoteClass:
    """把 IP 字符串分类（纯函数，便于单测）。"""

    if not address:
        return RemoteClass.UNKNOWN
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return RemoteClass.UNKNOWN

    if parsed.is_unspecified:
        return RemoteClass.RESERVED
    if parsed.is_loopback:
        return RemoteClass.LOOPBACK
    if parsed.is_link_local:
        return RemoteClass.LINK_LOCAL
    if parsed.is_multicast:
        return RemoteClass.MULTICAST
    if isinstance(parsed, ipaddress.IPv4Address) and parsed in _CGNAT_NETWORK:
        return RemoteClass.CGNAT
    if parsed.is_private:
        return RemoteClass.PRIVATE
    if parsed.is_reserved:
        return RemoteClass.RESERVED
    if parsed.is_global:
        return RemoteClass.PUBLIC
    return RemoteClass.UNKNOWN


def _parse_endpoint(raw: Any) -> Endpoint | None:
    if not raw:
        return None
    address = str(getattr(raw, "ip", "") or "")
    if not address:
        return None
    try:
        port = int(getattr(raw, "port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    return Endpoint(address, port)


def _protocol_name(raw_type: Any) -> str:
    try:
        value = int(raw_type)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if value == int(socket.SOCK_STREAM):
        return "TCP"
    if value == int(socket.SOCK_DGRAM):
        return "UDP"
    return "UNKNOWN"


def _family_name(raw_family: Any) -> str:
    try:
        value = int(raw_family)
    except (TypeError, ValueError):
        return "未知"
    if value == int(socket.AF_INET6):
        return "IPv6"
    if value == int(socket.AF_INET):
        return "IPv4"
    return "未知"


def should_review_connection(
    *,
    remote_class: RemoteClass,
    pid_known: bool,
    process_name: str | None,
    process_trusted: bool,
    process_sig: SigStatus,
    whitelisted: bool,
    pid: int | None = None,
) -> tuple[bool, str]:
    """判断一条连接是否需要人工核实，返回 ``(需要核实, 原因)``（纯函数）。"""

    if remote_class is not RemoteClass.PUBLIC:
        return False, ""
    if whitelisted:
        return False, ""
    if not pid_known:
        if pid == 0:
            # PID 0 是内核/系统连接，无用户进程可归因；由调用方单独标注，不列入"需核实"
            return False, ""
        return True, "公网远端，但无法关联到进程（PID 缺失或进程已退出）"
    if not process_name:
        return True, "公网远端，进程信息不可读（权限不足）"
    if process_trusted:
        return False, ""
    if process_sig is SigStatus.VALID:
        return False, ""
    return (
        True,
        "公网远端；进程位于非受信路径（非 Windows / Program Files）；签名状态："
        + signature_label(process_sig),
    )


def _collect_raw(
    token: CancelToken,
) -> tuple[list[tuple[int | None, Any, Any, Any, Any, str]], str, list[ScanWarning]]:
    """读取原始连接列表，返回 ``(原始项, 模式, 警告)``；模式 ∈ full/partial/failed。"""

    warnings: list[ScanWarning] = []
    try:
        raw_connections = psutil.net_connections(kind="inet")
        items = [
            (
                getattr(connection, "pid", None),
                connection.family,
                connection.type,
                connection.laddr,
                connection.raddr,
                str(getattr(connection, "status", "") or ""),
            )
            for connection in raw_connections
        ]
        return items, "full", warnings
    except (psutil.AccessDenied, OSError) as exc:
        warnings.append(
            ScanWarning(
                "network_denied",
                f"无法读取全机网络连接（{type(exc).__name__}），已降级为逐进程读取，数据可能不完整",
                phase="network",
            )
        )
    except Exception as exc:  # noqa: BLE001 - psutil 版本差异兜底
        warnings.append(
            ScanWarning(
                "network_error",
                f"读取网络连接失败（{type(exc).__name__}: {exc}），已降级为逐进程读取",
                phase="network",
            )
        )

    # 降级：逐进程读取（部分进程仍可能 AccessDenied）
    items = []
    denied = 0
    try:
        pids = psutil.pids()
    except Exception as exc:  # noqa: BLE001
        warnings.append(ScanWarning("network_enum_failed", f"无法枚举进程：{exc}", phase="network"))
        return [], "failed", warnings

    for pid in pids:
        token.raise_if_cancelled("网络连接采集")
        try:
            process = psutil.Process(pid)
            process_connections = process.net_connections(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            denied += 1
            continue
        except Exception:  # noqa: BLE001 - 单进程失败不影响整体
            denied += 1
            continue
        for connection in process_connections:
            items.append(
                (
                    pid,
                    connection.family,
                    connection.type,
                    connection.laddr,
                    connection.raddr,
                    str(getattr(connection, "status", "") or ""),
                )
            )
    if denied:
        warnings.append(
            ScanWarning(
                "network_partial",
                f"{denied} 个进程的连接不可读（可能因权限不足），数据可能不完整",
                phase="network",
            )
        )
    return items, "partial", warnings


def collect_connections(
    *,
    process_index: Mapping[int, ProcessInfo],
    whitelist: Whitelist,
    token: CancelToken,
    progress: ProgressCallback | None = None,
) -> NetworkScanResult:
    """采集网络连接并关联进程信息。"""

    started_at = time.monotonic()
    raw_items, mode, warnings = _collect_raw(token)

    connections: list[ConnectionInfo] = []
    total = len(raw_items)
    for index, (pid, family, type_, laddr, raddr, status) in enumerate(raw_items, start=1):
        if index % 50 == 0:
            token.raise_if_cancelled("网络连接采集")
        local = _parse_endpoint(laddr)
        remote = _parse_endpoint(raddr)
        remote_class = classify_address(remote.address if remote else None)
        protocol = _protocol_name(type_)
        # PID 0 表示"内核/系统连接"，不代表 System Idle Process 进程，不能做进程归因
        pid_known = pid is not None and pid > 0
        is_kernel = pid is not None and pid == 0
        process = process_index.get(pid) if pid_known else None
        connection_pid: int | None = pid if pid_known else None
        process_name = process.name if process is not None else None
        process_exe = process.exe if process is not None else None
        process_trusted = bool(process_exe and whitelist.is_trusted_path(process_exe))
        process_sig = process.sig_status if process is not None else SigStatus.NOT_CHECKED
        needs_review, review_reason = should_review_connection(
            remote_class=remote_class,
            pid_known=pid_known,
            process_name=process_name,
            process_trusted=process_trusted,
            process_sig=process_sig,
            whitelisted=whitelist.is_extra_name(process_name),
            pid=pid,
        )
        note = ""
        if is_kernel:
            note = "内核/系统连接（PID 0），无法归因到用户进程；常见于系统服务/代理"
        connections.append(
            ConnectionInfo(
                pid=connection_pid,
                family=_family_name(family),
                protocol=protocol,
                status=status.upper() if status else ("LISTEN" if remote is None and protocol == "TCP" else ""),
                laddr=local,
                raddr=remote,
                remote_class=remote_class,
                is_listen=status.upper() == "LISTEN",
                is_kernel=is_kernel,
                process_name=process_name,
                process_exe=process_exe,
                process_trusted=process_trusted,
                process_sig=process_sig,
                needs_review=needs_review,
                review_reason=review_reason,
                note=note,
            )
        )
        if progress is not None and (index % 25 == 0 or index == total):
            progress(index, total)

    # 需人工核实优先，其次公网连接，再按进程排序
    connections.sort(
        key=lambda item: (
            not item.needs_review,
            item.remote_class is not RemoteClass.PUBLIC,
            item.is_listen,
            item.pid if item.pid is not None else 1 << 30,
            item.raddr.text if item.raddr else "",
        )
    )

    if mode == "failed":
        completeness = Completeness.DEGRADED
    elif mode == "partial" or any(warning.code in ("network_partial", "network_denied") for warning in warnings):
        completeness = Completeness.PARTIAL
    else:
        completeness = Completeness.FULL

    elapsed_ms = int((time.monotonic() - started_at) * 1000)
    logger.info(
        "网络连接采集完成：%d 条（公网 %d，需核实 %d），完整度=%s",
        len(connections),
        sum(1 for item in connections if item.remote_class is RemoteClass.PUBLIC),
        sum(1 for item in connections if item.needs_review),
        completeness.value,
    )
    return NetworkScanResult(
        connections=connections,
        completeness=completeness,
        elapsed_ms=elapsed_ms,
        warnings=warnings,
    )
