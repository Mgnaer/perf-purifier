"""数字签名校验测试（WinVerifyTrust）。

覆盖：有效签名 / 无签名伪 PE / 文件不存在 / 结果缓存 / 受信路径不校验。
"""

from __future__ import annotations

import os
import sys

import pytest

from perf_purifier.core.cancel import CancelToken
from perf_purifier.core.models import ProcessInfo, SigStatus
from perf_purifier.core.whitelist import Whitelist
from perf_purifier.module_a.signature import enrich_process_signatures, verify_file_signature

pytestmark = pytest.mark.skipif(os.name != "nt", reason="WinVerifyTrust 仅 Windows 可用")


def test_running_interpreter_has_valid_signature() -> None:
    result = verify_file_signature(sys.executable)
    # 正常 CPython/venv 解释器由 Python Software Foundation 签名；
    # 个别环境证书链异常时可能映射为"不受信任"，但绝不应是"无签名/无法读取"。
    assert result.status in (SigStatus.VALID, SigStatus.SIGNED_UNTRUSTED)


def test_signature_result_is_cached() -> None:
    first = verify_file_signature(sys.executable)
    second = verify_file_signature(sys.executable)
    assert first is second


def test_fake_pe_is_unsigned(tmp_path) -> None:
    fake = tmp_path / "fake.exe"
    fake.write_bytes(b"MZ this is not a real PE file")
    result = verify_file_signature(str(fake))
    assert result.status is SigStatus.UNSIGNED


def test_missing_file_is_unreadable(tmp_path) -> None:
    result = verify_file_signature(str(tmp_path / "does-not-exist.exe"))
    assert result.status is SigStatus.UNREADABLE


def test_enrich_marks_trusted_path_and_verifies_others(tmp_path) -> None:
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    fake = tmp_path / "unsigned.exe"
    fake.write_bytes(b"MZ not really a PE")
    processes = [
        ProcessInfo(
            pid=100,
            ppid=4,
            name="notepad.exe",
            exe=os.path.join(system_root, "System32", "notepad.exe"),
        ),
        ProcessInfo(pid=200, ppid=4, name="unsigned.exe", exe=str(fake)),
        ProcessInfo(pid=300, ppid=4, name="nopath.exe", exe=None),
    ]
    enriched, warnings = enrich_process_signatures(
        processes,
        Whitelist(),
        token=CancelToken(),
        max_files=10,
        budget_s=5.0,
    )
    assert warnings == [] or all(warning.phase == "signature" for warning in warnings)
    by_pid = {process.pid: process for process in enriched}
    assert by_pid[100].sig_status is SigStatus.CATALOG_OR_UNKNOWN
    assert by_pid[200].sig_status is SigStatus.UNSIGNED
    assert by_pid[300].sig_status is SigStatus.NOT_CHECKED
