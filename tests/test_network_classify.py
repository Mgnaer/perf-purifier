"""网络地址分类与"未知外网连接"判定测试（纯函数 + 在线冒烟）。"""

from __future__ import annotations

import pytest

from perf_purifier.core.cancel import CancelToken
from perf_purifier.core.models import Completeness, RemoteClass, SigStatus
from perf_purifier.core.whitelist import Whitelist
from perf_purifier.module_a.network_scan import (
    classify_address,
    collect_connections,
    should_review_connection,
)


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        (None, RemoteClass.UNKNOWN),
        ("", RemoteClass.UNKNOWN),
        ("not-an-ip", RemoteClass.UNKNOWN),
        ("127.0.0.1", RemoteClass.LOOPBACK),
        ("::1", RemoteClass.LOOPBACK),
        ("10.0.0.5", RemoteClass.PRIVATE),
        ("192.168.1.10", RemoteClass.PRIVATE),
        ("172.16.3.4", RemoteClass.PRIVATE),
        ("100.64.0.1", RemoteClass.CGNAT),
        ("169.254.1.1", RemoteClass.LINK_LOCAL),
        ("fe80::1", RemoteClass.LINK_LOCAL),
        ("224.0.0.1", RemoteClass.MULTICAST),
        ("0.0.0.0", RemoteClass.RESERVED),
        ("8.8.8.8", RemoteClass.PUBLIC),
        ("1.1.1.1", RemoteClass.PUBLIC),
        ("2606:4700:4700::1111", RemoteClass.PUBLIC),
    ],
)
def test_classify_address(address: str | None, expected: RemoteClass) -> None:
    assert classify_address(address) is expected


def test_private_remote_never_needs_review() -> None:
    needs_review, _ = should_review_connection(
        remote_class=RemoteClass.PRIVATE,
        pid_known=True,
        process_name="a.exe",
        process_trusted=False,
        process_sig=SigStatus.UNSIGNED,
        whitelisted=False,
    )
    assert needs_review is False


def test_unsigned_untrusted_public_connection_needs_review() -> None:
    needs_review, reason = should_review_connection(
        remote_class=RemoteClass.PUBLIC,
        pid_known=True,
        process_name="suspicious.exe",
        process_trusted=False,
        process_sig=SigStatus.UNSIGNED,
        whitelisted=False,
    )
    assert needs_review is True
    assert "非受信路径" in reason
    assert "无签名" in reason


def test_trusted_path_or_valid_signature_not_reviewed() -> None:
    for trusted, sig in (
        (True, SigStatus.CATALOG_OR_UNKNOWN),
        (True, SigStatus.NOT_CHECKED),
        (False, SigStatus.VALID),
    ):
        needs_review, _ = should_review_connection(
            remote_class=RemoteClass.PUBLIC,
            pid_known=True,
            process_name="chrome.exe",
            process_trusted=trusted,
            process_sig=sig,
            whitelisted=False,
        )
        assert needs_review is False, (trusted, sig)


def test_whitelisted_process_not_reviewed() -> None:
    needs_review, _ = should_review_connection(
        remote_class=RemoteClass.PUBLIC,
        pid_known=True,
        process_name="myapp.exe",
        process_trusted=False,
        process_sig=SigStatus.UNSIGNED,
        whitelisted=True,
    )
    assert needs_review is False


def test_missing_process_information_needs_review() -> None:
    needs_review, reason = should_review_connection(
        remote_class=RemoteClass.PUBLIC,
        pid_known=False,
        process_name=None,
        process_trusted=False,
        process_sig=SigStatus.NOT_CHECKED,
        whitelisted=False,
    )
    assert needs_review is True
    assert "无法关联" in reason


def test_pid_zero_is_not_counted_as_review() -> None:
    """PID 0 是内核/系统连接，单独标注 note，不列入"需人工核实"。"""

    needs_review, reason = should_review_connection(
        remote_class=RemoteClass.PUBLIC,
        pid_known=False,
        process_name=None,
        process_trusted=False,
        process_sig=SigStatus.NOT_CHECKED,
        whitelisted=False,
        pid=0,
    )
    assert needs_review is False
    assert reason == ""


def test_collect_connections_live_smoke() -> None:
    """真实调用一次（结果依赖机器，不断言数量，只要求不抛异常且分类字段合法）。"""

    result = collect_connections(process_index={}, whitelist=Whitelist(), token=CancelToken())
    assert result.completeness in (Completeness.FULL, Completeness.PARTIAL, Completeness.DEGRADED)
    for connection in result.connections:
        assert connection.protocol in ("TCP", "UDP", "UNKNOWN")
        assert connection.family in ("IPv4", "IPv6", "未知")
        assert isinstance(connection.needs_review, bool)
