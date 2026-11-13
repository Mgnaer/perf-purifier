"""阶段 4A：只读扫描快照与基线对比。

设计（docs/07 S4-4）：
* 手动"保存基线"→ 稍后重新扫描 → "对比基线"：新增/消失进程、新增远端端点、Temp 总量变化；
* 单份本地基线（``%LOCALAPPDATA%\\PerfPurifier\\snapshots\\baseline.json``），有上限、可删除；
* **不做后台定时、不自动写入**；纯函数 diff，读取损坏文件降级而不崩溃；
* 进程用 ``pid+create_time`` 作为身份，避免 PID 复用导致误报"相同进程"。
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import app_data_dir
from .models import ProcessScanResult

SNAPSHOT_SCHEMA_VERSION = "1.0"
MAX_PROCESSES = 4000
MAX_ENDPOINTS = 4000
SNAPSHOT_FILENAME = "baseline.json"


def snapshot_path() -> Path:
    return app_data_dir() / "snapshots" / SNAPSHOT_FILENAME


@dataclass(frozen=True, slots=True)
class ProcessEntry:
    pid: int
    ppid: int
    name: str
    exe: str
    create_time: float

    @property
    def identity(self) -> str:
        return f"{self.pid}|{int(self.create_time)}"

    def label(self) -> str:
        exe = self.exe or "路径未知"
        return f"PID {self.pid} {self.name}（{exe}）"


@dataclass(frozen=True, slots=True)
class Snapshot:
    created_at: float
    total_processes: int
    completeness: str
    processes: tuple[ProcessEntry, ...] = ()
    remote_endpoints: tuple[str, ...] = ()
    temp_total_size: int = 0
    temp_total_files: int = 0
    schema_version: str = SNAPSHOT_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class SnapshotDiff:
    baseline_created_at: float
    new_processes: tuple[ProcessEntry, ...] = ()
    gone_processes: tuple[ProcessEntry, ...] = ()
    new_remote_endpoints: tuple[str, ...] = ()
    gone_remote_endpoints: tuple[str, ...] = ()
    temp_size_delta: int = 0
    temp_files_delta: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_processes
            or self.gone_processes
            or self.new_remote_endpoints
            or self.gone_remote_endpoints
            or self.temp_size_delta
            or self.temp_files_delta
        )


def build_snapshot(result: ProcessScanResult) -> Snapshot:
    """从进程扫描结果构建只读快照（不上传、不写盘）。"""

    entries = [
        ProcessEntry(
            pid=node.info.pid,
            ppid=node.info.ppid,
            name=node.info.name,
            exe=node.info.exe or "",
            create_time=float(node.info.create_time or 0.0),
        )
        for node in result.tree.nodes.values()
    ][:MAX_PROCESSES]
    endpoints: list[str] = []
    seen: set[str] = set()
    network = result.connections
    if network is not None:
        for connection in network.connections:
            remote = connection.raddr.text if connection.raddr else ""
            if not remote:
                continue
            key = f"{connection.protocol}|{remote}"
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(key)
            if len(endpoints) >= MAX_ENDPOINTS:
                break
    temp_size = result.temp.total_size if result.temp is not None else 0
    temp_files = result.temp.total_files if result.temp is not None else 0
    return Snapshot(
        created_at=float(result.finished_at or 0.0),
        total_processes=result.tree.total_processes,
        completeness=result.tree.completeness.value,
        processes=tuple(entries),
        remote_endpoints=tuple(endpoints),
        temp_total_size=temp_size,
        temp_total_files=temp_files,
    )


def compare_snapshot(snapshot: Snapshot, result: ProcessScanResult) -> SnapshotDiff:
    """当前扫描结果 vs 基线快照（纯函数，只读）。"""

    current = build_snapshot(result)
    baseline_by_identity = {entry.identity: entry for entry in snapshot.processes}
    current_by_identity = {entry.identity: entry for entry in current.processes}
    new_processes = tuple(
        entry
        for identity, entry in current_by_identity.items()
        if identity not in baseline_by_identity
    )
    gone_processes = tuple(
        entry
        for identity, entry in baseline_by_identity.items()
        if identity not in current_by_identity
    )
    baseline_endpoints = set(snapshot.remote_endpoints)
    current_endpoints = set(current.remote_endpoints)
    return SnapshotDiff(
        baseline_created_at=snapshot.created_at,
        new_processes=new_processes,
        gone_processes=gone_processes,
        new_remote_endpoints=tuple(sorted(current_endpoints - baseline_endpoints)),
        gone_remote_endpoints=tuple(sorted(baseline_endpoints - current_endpoints)),
        temp_size_delta=current.temp_total_size - snapshot.temp_total_size,
        temp_files_delta=current.temp_total_files - snapshot.temp_total_files,
    )


def save_snapshot(snapshot: Snapshot, path: Path | None = None) -> tuple[bool, str]:
    target = path or snapshot_path()
    payload = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "created_at": snapshot.created_at,
        "total_processes": snapshot.total_processes,
        "completeness": snapshot.completeness,
        "processes": [
            {
                "pid": entry.pid,
                "ppid": entry.ppid,
                "name": entry.name,
                "exe": entry.exe,
                "create_time": entry.create_time,
            }
            for entry in snapshot.processes
        ],
        "remote_endpoints": list(snapshot.remote_endpoints),
        "temp_total_size": snapshot.temp_total_size,
        "temp_total_files": snapshot.temp_total_files,
    }
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return True, ""
    except (OSError, TypeError, ValueError) as exc:
        return False, f"保存基线失败：{exc}"


def load_snapshot(path: Path | None = None) -> tuple[Snapshot | None, str]:
    """读取基线；文件缺失/损坏/类型不对时降级返回错误消息，不抛异常。"""

    target = path or snapshot_path()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, f"尚未保存基线（{target}）"
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return None, f"基线文件不可读：{exc}"
    if not isinstance(raw, dict):
        return None, "基线文件格式不正确（根节点不是对象）"
    try:
        processes = tuple(
            ProcessEntry(
                pid=int(item["pid"]),
                ppid=int(item.get("ppid", 0)),
                name=str(item.get("name", "")),
                exe=str(item.get("exe", "")),
                create_time=float(item.get("create_time", 0.0)),
            )
            for item in raw.get("processes", [])
            if isinstance(item, dict) and "pid" in item
        )
        snapshot = Snapshot(
            created_at=float(raw.get("created_at", 0.0)),
            total_processes=int(raw.get("total_processes", len(processes))),
            completeness=str(raw.get("completeness", "unknown")),
            processes=processes,
            remote_endpoints=tuple(
                str(item) for item in raw.get("remote_endpoints", []) if isinstance(item, str)
            ),
            temp_total_size=max(0, int(raw.get("temp_total_size", 0))),
            temp_total_files=max(0, int(raw.get("temp_total_files", 0))),
        )
    except (TypeError, ValueError, KeyError) as exc:
        return None, f"基线文件内容损坏：{exc}"
    return snapshot, ""


def delete_snapshot(path: Path | None = None) -> tuple[bool, str]:
    target = path or snapshot_path()
    try:
        target.unlink()
        return True, ""
    except FileNotFoundError:
        return True, "基线不存在"
    except OSError as exc:
        return False, f"删除基线失败：{exc}"


def snapshot_summary(snapshot: Snapshot) -> str:
    temp_size = snapshot.temp_total_size
    temp_text = f"{temp_size / (1024 * 1024):.1f} MB" if temp_size else "0 B"
    return (
        f"基线时间：{_format_ts(snapshot.created_at)}\n"
        f"进程数：{snapshot.total_processes}（记录 {len(snapshot.processes)} 项）\n"
        f"远端端点：{len(snapshot.remote_endpoints)} 个\n"
        f"临时占用总量：{temp_text} / {snapshot.temp_total_files} 个文件\n"
        f"数据完整度：{snapshot.completeness}"
    )


def diff_summary(diff: SnapshotDiff) -> str:
    lines = [
        f"对比基线：{_format_ts(diff.baseline_created_at)}（只读对比，不会修改任何内容）",
        f"新增进程：{len(diff.new_processes)} 个；消失进程：{len(diff.gone_processes)} 个",
        f"新增远端端点：{len(diff.new_remote_endpoints)} 个；消失远端端点：{len(diff.gone_remote_endpoints)} 个",
        f"临时占用变化：{diff.temp_size_delta:+,} 字节 / {diff.temp_files_delta:+d} 个文件",
    ]
    if diff.new_processes:
        lines.append("")
        lines.append("新增进程（最多显示 30 个）：")
        lines.extend(f"  + {entry.label()}" for entry in diff.new_processes[:30])
    if diff.new_remote_endpoints:
        lines.append("")
        lines.append("新增远端端点（最多显示 30 个）：")
        lines.extend(f"  + {endpoint}" for endpoint in diff.new_remote_endpoints[:30])
    if not diff.has_changes:
        lines.append("")
        lines.append("未发现差异。")
    return "\n".join(lines)


def _format_ts(value: float) -> str:
    import time

    if value <= 0:
        return "未知"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def default_snapshot_dir() -> Path:
    """基线目录（用于设置页/测试注入）。"""

    return app_data_dir() / "snapshots"


def _temp_dir_placeholder() -> Path:  # pragma: no cover - 保留导入形态
    return Path(tempfile.gettempdir())


__all__ = [
    "ProcessEntry",
    "Snapshot",
    "SnapshotDiff",
    "build_snapshot",
    "compare_snapshot",
    "save_snapshot",
    "load_snapshot",
    "delete_snapshot",
    "snapshot_path",
    "snapshot_summary",
    "diff_summary",
    "default_snapshot_dir",
]
