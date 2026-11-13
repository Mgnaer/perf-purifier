"""pytest 公共配置：把 ``src`` 加入路径、设置无头 Qt 平台、提供测试数据工厂。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# 无显示环境也能构建 Qt 控件（CI / 远程会话）
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

from perf_purifier.core.models import ProcessInfo  # noqa: E402


@pytest.fixture()
def make_info():
    """构造 ProcessInfo 的工厂，未指定字段使用合理默认值。"""

    def factory(pid: int, ppid: int, name: str, **overrides) -> ProcessInfo:
        defaults: dict = {
            "exe": None,
            "cmdline": (),
            "username": "TEST\\user",
            "create_time": 1_700_000_000.0,
            "status": "running",
            "rss": 1024 * 1024,
            "vms": 4 * 1024 * 1024,
        }
        defaults.update(overrides)
        return ProcessInfo(pid=pid, ppid=ppid, name=name, **defaults)

    return factory


@pytest.fixture(scope="session")
def qapp():
    """会话级 QApplication（无头模式），供 QObject/控件类测试使用。"""

    from PySide6.QtWidgets import QApplication

    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture()
def system_root() -> str:
    return os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"


@pytest.fixture()
def synthetic_file_result(tmp_path):
    """构造模块 B 结果（含普通重复组 + 硬链接组），不触碰真实文件系统。"""

    from perf_purifier.core.models import (
        Completeness,
        DuplicateGroup,
        FileRecord,
        FileScanOptions,
        FileScanResult,
        LargeFile,
    )

    one = FileRecord(path=str(tmp_path / "data" / "a" / "one.bin"), size=5000, mtime=1_700_000_000.0, dev=1, ino=111)
    two = FileRecord(path=str(tmp_path / "data" / "b" / "two.bin"), size=5000, mtime=1_700_000_010.0, dev=1, ino=222)
    link_one = FileRecord(path=str(tmp_path / "data" / "c" / "orig.bin"), size=8000, mtime=1_700_000_020.0, dev=1, ino=333)
    link_two = FileRecord(path=str(tmp_path / "data" / "c" / "copy.bin"), size=8000, mtime=1_700_000_020.0, dev=1, ino=333)
    groups = [
        DuplicateGroup(
            group_id=1,
            size=5000,
            full_sha256="a" * 64,
            files=(one, two),
            distinct_inodes=2,
            suggested_keep_path=one.path,
        ),
        DuplicateGroup(
            group_id=2,
            size=8000,
            full_sha256="b" * 64,
            files=(link_one, link_two),
            distinct_inodes=1,
            has_hardlinks=True,
            already_hardlinked=True,
            suggested_keep_path=link_one.path,
        ),
    ]
    large_files = [
        LargeFile(path=str(tmp_path / "data" / "big" / "huge.bin"), size=3 * 1024 * 1024, mtime=1_700_000_030.0),
        LargeFile(path=str(tmp_path / "data" / "big" / "mid.bin"), size=1024 * 1024, mtime=1_700_000_040.0),
    ]
    return FileScanResult(
        root=str(tmp_path / "data"),
        options=FileScanOptions(root=str(tmp_path / "data"), min_size=1024),
        started_at=1_700_000_000.0,
        finished_at=1_700_000_001.5,
        duplicate_groups=groups,
        large_files=large_files,
        files_scanned=42,
        dirs_scanned=8,
        total_bytes=13_000,
        partial_hashed=6,
        full_hashed=4,
        hash_bytes=13_000,
        completeness=Completeness.FULL,
        elapsed_ms=1500,
    )


@pytest.fixture()
def synthetic_result(make_info, tmp_path):
    """构造一个包含可疑进程/网络连接/临时占用的完整扫描结果（不触碰真实系统）。"""

    from perf_purifier.core.models import (
        Completeness,
        ConnectionInfo,
        Endpoint,
        NetworkScanResult,
        Occupancy,
        ProcessScanResult,
        RemoteClass,
        SigStatus,
        TempEntry,
        TempRoot,
        TempScanResult,
    )
    from perf_purifier.core.whitelist import Whitelist
    from perf_purifier.module_a.heuristics import analyze_tree
    from perf_purifier.module_a.tree_builder import build_tree

    temp_dir = os.environ.get("TEMP") or str(tmp_path)
    suspicious_exe = os.path.join(temp_dir, "evil.exe")
    infos = [
        make_info(4, 0, "System", exe=None, username=None),
        make_info(
            100,
            4,
            "evil.exe",
            exe=suspicious_exe,
            cmdline=("evil.exe", "-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
            create_time=1_700_000_100.0,
        ),
        make_info(200, 4, "notepad.exe", exe=os.path.join(tmp_path, "notepad.exe")),
    ]
    tree = build_tree(infos)
    analyze_tree(tree, Whitelist())

    connections = NetworkScanResult(
        connections=[
            ConnectionInfo(
                pid=100,
                family="IPv4",
                protocol="TCP",
                status="ESTABLISHED",
                laddr=Endpoint("10.0.0.2", 51888),
                raddr=Endpoint("8.8.8.8", 443),
                remote_class=RemoteClass.PUBLIC,
                process_name="evil.exe",
                process_exe=suspicious_exe,
                process_sig=SigStatus.UNSIGNED,
                needs_review=True,
                review_reason="公网远端；进程位于非受信路径；签名状态：无签名",
            ),
            ConnectionInfo(
                pid=100,
                family="IPv4",
                protocol="TCP",
                status="LISTEN",
                laddr=Endpoint("0.0.0.0", 9999),
                raddr=None,
                remote_class=RemoteClass.RESERVED,
                is_listen=True,
                process_name="evil.exe",
                process_exe=suspicious_exe,
            ),
        ],
        completeness=Completeness.PARTIAL,
        elapsed_ms=12,
        warnings=[],
    )
    temp_root = TempRoot(path=str(tmp_path / "Temp"), kind="temp", exists=True)
    temp = TempScanResult(
        roots=[temp_root],
        entries=[
            TempEntry(
                root=temp_root.path,
                path=str(tmp_path / "Temp" / "cache.tmp"),
                is_dir=False,
                size=2 * 1024 * 1024,
                file_count=1,
                mtime=1_700_000_000.0,
                occupancy=Occupancy.LOCKED,
                occupancy_detail="探测 1 个文件中 1 个被占用",
            )
        ],
        total_size=2 * 1024 * 1024,
        total_files=1,
        probed_files=1,
        probe_candidates=1,
        elapsed_ms=5,
        completeness=Completeness.PARTIAL,
        probe_note="占用探测：1/1 个文件；未探测 ≠ 未占用",
    )
    return ProcessScanResult(
        tree=tree,
        started_at=1_700_000_000.0,
        finished_at=1_700_000_003.0,
        is_admin=False,
        connections=connections,
        temp=temp,
    )


# ---------------------------------------------------------------------------
# 模块 C（磁盘空间）测试辅助
# ---------------------------------------------------------------------------
def make_junction(link: Path, target: Path) -> bool:
    """创建目录 junction；失败返回 False（调用方据此 skip）。"""

    import subprocess

    try:
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        )
        return result.returncode == 0 and os.path.isdir(link)
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - 环境限制
        return False


def write_file(path: Path, size: int, *, mtime: float | None = None) -> Path:
    """写入指定字节数的文件（内容用重复字符填充）。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


@pytest.fixture()
def synthetic_space_result(tmp_path):
    """构造模块 C 扫描结果（不触碰真实文件系统），供页面与策略测试使用。"""

    from perf_purifier.core.judgements import ScanStats, compute_completeness
    from perf_purifier.core.models import Completeness
    from perf_purifier.module_c.models import (
        JunkItem,
        JunkRuleResult,
        LargeFileHit,
        OverviewEntry,
        SpaceScanResult,
    )
    from perf_purifier.module_c.rules import RULES_BY_ID

    def junk_item(rule_id: str, name: str, size: int, *, kind: str = "file", special: str = "") -> JunkItem:
        rule = RULES_BY_ID[rule_id]
        return JunkItem(
            rule_id=rule.id,
            rule_name=rule.name,
            category=rule.category,
            risk=rule.risk,
            path=str(tmp_path / rule_id / name),
            size=size,
            file_count=1,
            mtime=1_700_000_000.0,
            kind=kind,
            allowed_root=str(tmp_path / rule_id),
            requires_admin=rule.requires_admin,
            note=rule.note,
            special=special,
        )

    safe_items = [junk_item("temp_user", "a.tmp", 2048), junk_item("temp_user", "b.tmp", 1024)]
    caution_items = [junk_item("gpu_shader_caches", "dx.bin", 4096, kind="dir")]
    system_items = [junk_item("win_mrt", "MRT.exe", 8192)]
    results = [
        JunkRuleResult(rule=RULES_BY_ID["temp_user"], items=safe_items),
        JunkRuleResult(rule=RULES_BY_ID["gpu_shader_caches"], items=caution_items),
        JunkRuleResult(rule=RULES_BY_ID["win_mrt"], items=system_items),
    ]
    verdict = compute_completeness(ScanStats(total_items=4, permission_limited=False))
    return SpaceScanResult(
        drive="C:\\",
        total_bytes=80 * 1024**3,
        free_bytes=30 * 1024**3,
        overview_entries=[
            OverviewEntry(name="Windows", path="C:\\Windows", is_dir=True, size=25 * 1024**3, file_count=1000, mtime=0.0),
            OverviewEntry(name="Users", path="C:\\Users", is_dir=True, size=10 * 1024**3, file_count=500, mtime=0.0),
            OverviewEntry(name="pagefile.sys", path="C:\\pagefile.sys", is_dir=False, size=1024**3, file_count=1, mtime=0.0),
        ],
        top_files=[
            LargeFileHit(path=str(tmp_path / "big.bin"), size=1024**3, mtime=1_700_000_000.0),
            LargeFileHit(path=str(tmp_path / "mid.bin"), size=512 * 1024**2, mtime=1_700_000_100.0),
        ],
        junk_results=results,
        warnings=[],
        completeness=Completeness.FULL,
        verdict=verdict,
        elapsed_ms=1500,
    )
