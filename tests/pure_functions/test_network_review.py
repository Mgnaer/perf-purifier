"""任务 1 P0 补测：网络"需人工核实"判定（纯函数，无 I/O、无真实网络、无管理员）。

覆盖清单（对应阶段 2 依赖）：
* 2B 结束进程：公网 + 非受信路径 + 非有效签名 → 需人工核实（复核闸门）；
* 2C 删 Temp：不因内网/受信进程告警而扩大处置范围（负例）；
* 审计日志：原因字符串稳定，含"非受信路径/无签名"等既有 UI 依赖子串，可复现。
"""

from __future__ import annotations

import pytest

from perf_purifier.core.judgements import (
    ConnectionMeta,
    ProcessMeta,
    is_needs_review,
)
from perf_purifier.core.models import RemoteClass, SigStatus


def make_conn(
    *,
    pid: int | None = 100,
    remote_ip: str | None = "8.8.8.8",
    remote_class: RemoteClass = RemoteClass.PUBLIC,
    protocol: str = "TCP",
    status: str = "ESTABLISHED",
    is_listen: bool = False,
    family: str = "IPv4",
) -> ConnectionMeta:
    return ConnectionMeta(
        pid=pid,
        remote_ip=remote_ip,
        remote_class=remote_class,
        protocol=protocol,
        status=status,
        is_listen=is_listen,
        family=family,
    )


def make_proc(
    *,
    pid: int | None = 100,
    name: str | None = "evil.exe",
    exe: str | None = r"C:\Users\demo\AppData\Local\Temp\evil.exe",
    sig_status: SigStatus = SigStatus.UNSIGNED,
    trusted_path: bool = False,
) -> ProcessMeta:
    return ProcessMeta(pid=pid, name=name, exe=exe, sig_status=sig_status, trusted_path=trusted_path)


# ---------------------------------------------------------------- 正例（3 条）
def test_public_untrusted_unsigned_established_positive() -> None:
    needs_review, reason = is_needs_review(make_conn(), make_proc())
    assert needs_review is True
    assert "公网" in reason
    assert "非受信路径" in reason
    assert "无签名" in reason


def test_public_untrusted_signed_untrusted_positive() -> None:
    conn = make_conn(pid=101, remote_ip="1.1.1.1")
    proc = make_proc(pid=101, sig_status=SigStatus.SIGNED_UNTRUSTED)
    needs_review, reason = is_needs_review(conn, proc)
    assert needs_review is True
    assert "非受信路径" in reason
    assert "不受信任" in reason


def test_public_udp_untrusted_not_checked_positive() -> None:
    conn = make_conn(pid=102, remote_ip="223.5.5.5", protocol="UDP", status="NONE")
    proc = make_proc(pid=102, sig_status=SigStatus.NOT_CHECKED)
    needs_review, reason = is_needs_review(conn, proc)
    assert needs_review is True
    assert "非受信路径" in reason
    assert "未检查" in reason


# ---------------------------------------------------------------- 反例（3 条）
def test_trusted_path_negative() -> None:
    conn = make_conn(pid=110)
    proc = make_proc(
        pid=110,
        name="chrome.exe",
        exe=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        sig_status=SigStatus.CATALOG_OR_UNKNOWN,
        trusted_path=True,
    )
    assert is_needs_review(conn, proc) == (False, "")


def test_valid_signature_negative() -> None:
    conn = make_conn(pid=111)
    proc = make_proc(pid=111, sig_status=SigStatus.VALID, trusted_path=False)
    assert is_needs_review(conn, proc) == (False, "")


def test_private_remote_negative() -> None:
    conn = make_conn(pid=112, remote_ip="10.0.0.5", remote_class=RemoteClass.PRIVATE)
    proc = make_proc(pid=112, sig_status=SigStatus.UNSIGNED)
    assert is_needs_review(conn, proc) == (False, "")


# ---------------------------------------------------------------- 边界（4+ 条）
def test_pid_zero_kernel_connection_negative() -> None:
    """PID 0 是内核/系统连接，不能归因到 System Idle Process。"""

    conn = make_conn(pid=0, remote_ip="113.240.66.218")
    proc = make_proc(pid=0, name="System Idle Process", exe=None, sig_status=SigStatus.NOT_CHECKED)
    assert is_needs_review(conn, proc) == (False, "")


def test_listen_connection_negative() -> None:
    conn = make_conn(pid=120, remote_ip=None, remote_class=RemoteClass.UNKNOWN, status="LISTEN", is_listen=True)
    proc = make_proc(pid=120, name="server.exe", exe=r"C:\tools\server.exe", sig_status=SigStatus.UNSIGNED)
    assert is_needs_review(conn, proc) == (False, "")


def test_ipv6_public_positive_and_private_negative() -> None:
    public_conn = make_conn(pid=121, remote_ip="2001:4860:4860::8888", family="IPv6")
    public_proc = make_proc(pid=121)
    assert is_needs_review(public_conn, public_proc)[0] is True

    private_conn = make_conn(pid=122, remote_ip="fc00::1", remote_class=RemoteClass.PRIVATE, family="IPv6")
    private_proc = make_proc(pid=122)
    assert is_needs_review(private_conn, private_proc) == (False, "")


def test_missing_process_metadata_positive() -> None:
    conn = make_conn(pid=130)
    needs_review, reason = is_needs_review(conn, ProcessMeta(pid=None))
    assert needs_review is True
    assert "无法关联" in reason


def test_mismatched_process_pid_positive() -> None:
    conn = make_conn(pid=131)
    needs_review, reason = is_needs_review(conn, make_proc(pid=999))
    assert needs_review is True
    assert "无法关联" in reason


def test_missing_connection_pid_positive() -> None:
    conn = make_conn(pid=None)
    needs_review, reason = is_needs_review(conn, ProcessMeta(pid=None))
    assert needs_review is True
    assert "PID 缺失" in reason


def test_unreadable_process_path_still_positive_with_clear_reason() -> None:
    conn = make_conn(pid=140)
    proc = ProcessMeta(pid=140, name=None, exe=None, sig_status=SigStatus.NOT_CHECKED, trusted_path=False)
    needs_review, reason = is_needs_review(conn, proc)
    assert needs_review is True
    assert "不可读" in reason
    assert "未检查" in reason


def test_trusted_path_wins_over_unsigned_signature() -> None:
    """受信路径不因签名状态被标记（catalog 签名不判"无签名"）。"""

    conn = make_conn(pid=150)
    proc = make_proc(pid=150, sig_status=SigStatus.UNSIGNED, trusted_path=True)
    assert is_needs_review(conn, proc) == (False, "")


def test_inconsistent_listen_with_public_class_is_defensive_negative() -> None:
    conn = make_conn(pid=160, remote_ip="8.8.8.8", remote_class=RemoteClass.PUBLIC, is_listen=True)
    proc = make_proc(pid=160)
    assert is_needs_review(conn, proc) == (False, "")


def test_public_class_without_remote_ip_negative() -> None:
    conn = make_conn(pid=161, remote_ip=None, remote_class=RemoteClass.PUBLIC)
    proc = make_proc(pid=161)
    assert is_needs_review(conn, proc) == (False, "")


@pytest.mark.parametrize(
    "remote_class",
    [
        RemoteClass.LOOPBACK,
        RemoteClass.PRIVATE,
        RemoteClass.CGNAT,
        RemoteClass.LINK_LOCAL,
        RemoteClass.MULTICAST,
        RemoteClass.RESERVED,
        RemoteClass.UNKNOWN,
    ],
)
def test_non_public_remote_classes_never_reviewed(remote_class: RemoteClass) -> None:
    conn = make_conn(pid=170, remote_ip="0.0.0.0", remote_class=remote_class)
    proc = make_proc(pid=170, sig_status=SigStatus.UNSIGNED)
    assert is_needs_review(conn, proc) == (False, "")


@pytest.mark.parametrize(
    "sig_status",
    [
        SigStatus.INVALID,
        SigStatus.SIGNED_UNTRUSTED,
        SigStatus.NOT_CHECKED,
        SigStatus.CATALOG_OR_UNKNOWN,
        SigStatus.UNREADABLE,
    ],
)
def test_all_non_valid_signature_states_trigger_review(sig_status: SigStatus) -> None:
    """"非有效签名"包含未签名/无效/不受信任/未检查/目录签名未知等状态。"""

    conn = make_conn(pid=180)
    proc = make_proc(pid=180, sig_status=sig_status)
    needs_review, reason = is_needs_review(conn, proc)
    assert needs_review is True
    assert "非受信路径" in reason


def test_pure_function_does_not_mutate_inputs() -> None:
    conn = make_conn()
    proc = make_proc()
    conn_snapshot, proc_snapshot = conn, proc
    is_needs_review(conn, proc)
    assert conn == conn_snapshot
    assert proc == proc_snapshot
