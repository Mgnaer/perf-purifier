"""进程快照采集（psutil，只读）。

纪律：
* 逐字段捕获异常：某些受保护进程只能拿到 pid/ppid，不能因此中断整个扫描；
* 每个字段失败都记录在 ``ProcessInfo.access_errors``，UI 显示"不可读"而不是 0；
* 采集阶段不做任何风险判断，保持纯数据。
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import psutil

from ..core.cancel import CancelToken
from ..core.models import Completeness, ProcessInfo, ScanWarning, SigStatus

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int, int, str], None]
"""进度回调：``(done, total, current_name)``。"""

# 复用 psutil.Process 对象：psutil 的 Process 会缓存部分系统查询结果，
# 复用时"重新扫描"可比每次新建对象快约一倍。安全性由官方 is_running()
# 保证——它会比较 (pid, create_time) 以识别 PID 复用，复用发生时返回 False。
_PROCESS_CACHE: dict[int, psutil.Process] = {}


def _cached_process(pid: int) -> psutil.Process | None:
    """获取（或创建）进程对象；已退出返回 ``None``，权限不足向上抛 AccessDenied。"""

    cached = _PROCESS_CACHE.get(pid)
    if cached is not None:
        try:
            if cached.is_running():
                return cached
        except (psutil.Error, OSError):
            pass
        _PROCESS_CACHE.pop(pid, None)
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return None
    _PROCESS_CACHE[pid] = process
    return process


def reset_process_cache() -> None:
    """清空进程对象缓存（测试或需要完全重新采集时使用）。"""

    _PROCESS_CACHE.clear()


def _collect_one(process: psutil.Process) -> ProcessInfo:
    """采集单个进程字段；进程已退出时抛 ``psutil.NoSuchProcess`` 由调用方跳过。"""

    pid = process.pid
    errors: list[str] = []

    with process.oneshot():

        def read(field: str, getter: Callable[[], object], default: object) -> object:
            try:
                return getter()
            except psutil.NoSuchProcess:
                raise
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError, ValueError) as exc:
                errors.append(f"{field}:{type(exc).__name__}")
                return default
            except Exception:  # noqa: BLE001 - 单字段异常不应中断整体扫描
                logger.debug("读取进程 %s 的字段 %s 失败", pid, field, exc_info=True)
                errors.append(f"{field}:unexpected")
                return default

        name = str(read("name", process.name, "") or "")
        exe_value = read("exe", process.exe, None)
        cmdline_value = read("cmdline", process.cmdline, [])
        username_value = read("username", process.username, None)
        status_value = read("status", process.status, "")
        create_time_value = read("create_time", process.create_time, 0.0)
        ppid_value = read("ppid", process.ppid, -1)
        memory_value = read("memory_info", process.memory_info, None)

    exe = str(exe_value) if exe_value else None
    cmdline = tuple(str(part) for part in (cmdline_value or []))
    username = str(username_value) if username_value else None
    status = str(status_value or "")
    try:
        create_time = float(create_time_value) if create_time_value else 0.0
    except (TypeError, ValueError):
        create_time = 0.0
    ppid = int(ppid_value) if isinstance(ppid_value, int) else -1
    rss = int(getattr(memory_value, "rss", 0) or 0)
    vms = int(getattr(memory_value, "vms", 0) or 0)

    return ProcessInfo(
        pid=pid,
        ppid=ppid,
        name=name,
        exe=exe,
        cmdline=cmdline,
        username=username,
        create_time=create_time,
        status=status,
        rss=rss,
        vms=vms,
        sig_status=SigStatus.NOT_CHECKED,
        access_errors=tuple(errors),
    )


def collect_processes(
    token: CancelToken,
    *,
    progress: ProgressCallback | None = None,
    max_processes: int = 4000,
) -> tuple[list[ProcessInfo], list[ScanWarning], Completeness]:
    """采集全机进程快照。

    返回 ``(进程列表, 警告列表, 数据完整度)``；用户取消时抛 ``ScanCancelled``。
    """

    warnings: list[ScanWarning] = []
    try:
        pids = [int(pid) for pid in psutil.pids()]
    except Exception as exc:  # noqa: BLE001 - psutil 底层异常类型随版本变化
        logger.exception("枚举进程失败")
        return (
            [],
            [ScanWarning("pid_enum_failed", f"无法枚举进程列表：{exc}", phase="snapshot")],
            Completeness.DEGRADED,
        )

    if not pids:
        return (
            [],
            [ScanWarning("no_process", "系统未返回任何进程", phase="snapshot")],
            Completeness.DEGRADED,
        )

    if len(pids) > max_processes:
        pids = pids[:max_processes]
        warnings.append(
            ScanWarning(
                "process_limit",
                f"进程数超过安全上限 {max_processes}，仅扫描前 {max_processes} 个",
                phase="snapshot",
            )
        )

    total = len(pids)
    collected: list[ProcessInfo] = []
    skipped = 0
    partial = 0
    for index, pid in enumerate(pids):
        token.raise_if_cancelled("采集进程快照")
        try:
            process = _cached_process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError, ValueError):
            skipped += 1
            continue
        except Exception:  # noqa: BLE001 - 单进程失败不影响整体扫描
            logger.exception("打开进程 %s 失败", pid)
            skipped += 1
            continue
        if process is None:
            skipped += 1
            continue
        try:
            info = _collect_one(process)
        except psutil.NoSuchProcess:
            _PROCESS_CACHE.pop(pid, None)
            skipped += 1
            continue
        except (psutil.AccessDenied, psutil.ZombieProcess, OSError, ValueError):
            skipped += 1
            continue
        except Exception:  # noqa: BLE001 - 单进程失败不影响整体扫描
            logger.exception("采集进程 %s 失败", pid)
            skipped += 1
            continue
        if info.access_errors:
            partial += 1
        collected.append(info)
        if progress is not None and (index % 25 == 0 or index + 1 == total):
            progress(index + 1, total, info.display_name)

    collected.sort(key=lambda item: item.pid)
    if skipped:
        warnings.append(
            ScanWarning("process_skipped", f"{skipped} 个进程已退出或无权读取，已跳过", phase="snapshot")
        )
    if partial:
        warnings.append(
            ScanWarning(
                "process_partial",
                f"{partial} 个进程的部分字段不可读（权限不足），建议以管理员身份运行",
                phase="snapshot",
            )
        )

    completeness = Completeness.PARTIAL if warnings else Completeness.FULL
    logger.info("进程快照完成：%d 个进程，%d 个跳过，完整度=%s", len(collected), skipped, completeness.value)
    return collected, warnings, completeness
