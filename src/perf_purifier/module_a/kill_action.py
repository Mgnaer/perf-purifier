"""阶段 2B：结束进程（目标构建 / 完整度适配 / 执行器）。

安全边界（S2/S3/S5/S6）：
* 默认关闭（``stage2_enabled`` + ``allow_kill_process``），确认框必须输入确认词「结束进程」；
* PID 0/4、动作黑名单、本程序自身/祖先进程、身份变化（PID 复用）一律拒绝；
* Windows 上 ``psutil.Process.terminate()`` 等价 TerminateProcess：**无优雅退出**，
  未保存数据会丢失，确认框必须明示；不提供"强制结束"升级；
* 审计日志记录脱敏后的命令行与进程身份。
"""

from __future__ import annotations

import os
from collections.abc import Sequence

import psutil

from ..core.action_policy import (
    ActionKind,
    ActionPolicy,
    KillTarget,
    PolicyDecision,
    PreviewToken,
    build_preview_token,
    evaluate_kill_targets,
    target_signature,
)
from ..core.judgements import CompletenessVerdict, ScanStats, compute_completeness
from ..core.models import Completeness, NetworkScanResult, ProcessScanResult
from ..core.whitelist import NEVER_TERMINATE_NAMES, normalize_path
from ..jobs.action_job import ActionExecutionResult

PROTECTED_PIDS = frozenset({0, 4})
IDENTITY_TOLERANCE_S = 0.5
TERMINATE_WAIT_S = 2.0


def process_scan_verdict(result: ProcessScanResult, *, is_admin: bool) -> CompletenessVerdict:
    """进程扫描结果 → 完整度闸门（limited 时禁止结束进程）。"""

    tree = result.tree
    unreadable_items = sum(1 for node in tree.nodes.values() if node.info.access_errors)
    budget_truncated = any(warning.code == "process_limit" for warning in tree.warnings)
    stats = ScanStats(
        total_items=tree.total_processes,
        unreadable_items=unreadable_items,
        permission_limited=(not is_admin and tree.completeness is not Completeness.FULL),
        budget_truncated=budget_truncated,
        core_enumeration_failed=(tree.completeness is Completeness.DEGRADED and not tree.nodes),
    )
    return compute_completeness(stats)


def ancestor_pids(processes: Sequence[object], pid: int) -> set[int]:
    """沿 ppid 链向上收集 pid 及其所有祖先（含自身；防御环）。"""

    by_pid = {int(info.pid): info for info in processes}
    result: set[int] = set()
    current = pid
    for _ in range(256):
        if current <= 0 or current in result:
            break
        result.add(current)
        info = by_pid.get(current)
        if info is None:
            break
        current = int(getattr(info, "ppid", -1))
    return result


def network_review_by_pid(network: NetworkScanResult | None) -> dict[int, str]:
    """进程 → 需人工核实的公网连接原因（P0 is_needs_review 结果上游计算）。"""

    reviews: dict[int, str] = {}
    if network is None:
        return reviews
    for connection in network.connections:
        if not connection.needs_review or connection.pid is None:
            continue
        reviews.setdefault(connection.pid, connection.review_reason or "需人工核实")
    return reviews


def kill_targets_from_pids(
    result: ProcessScanResult,
    pids: Sequence[int],
) -> list[KillTarget]:
    """按进程快照构建结束目标（不改系统；执行前由 executor 重验身份）。"""

    tree = result.tree
    self_ancestors = ancestor_pids([node.info for node in tree.nodes.values()], os.getpid())
    reviews = network_review_by_pid(result.connections)
    targets: list[KillTarget] = []
    seen: set[int] = set()
    for pid in pids:
        if pid in seen:
            continue
        seen.add(pid)
        node = tree.nodes.get(int(pid))
        if node is None:
            continue
        info = node.info
        name = info.name or ""
        targets.append(
            KillTarget(
                pid=int(pid),
                name=name,
                create_time=float(info.create_time or 0.0),
                exe=info.exe,
                is_protected_pid=int(pid) in PROTECTED_PIDS,
                never_terminate=name.casefold() in NEVER_TERMINATE_NAMES,
                is_self_or_ancestor=int(pid) in self_ancestors,
                identity_matches_snapshot=True,
                needs_review_network=int(pid) in reviews,
                needs_review_reason=reviews.get(int(pid), ""),
            )
        )
    return targets


def build_kill_preview(
    result: ProcessScanResult,
    pids: Sequence[int],
    *,
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
    now: float,
    token_id: str,
) -> tuple[list[KillTarget], PolicyDecision, PreviewToken | None]:
    """构建目标 + 策略判定 + 预览 token。"""

    targets = kill_targets_from_pids(result, pids)
    decision = evaluate_kill_targets(targets, policy, verdict)
    if not decision.allowed:
        return targets, decision, None
    allowed = [targets[index] for index in decision.allowed_indices]
    signature = target_signature(
        [f"{target.pid}|{int(target.create_time)}|{target.exe or ''}" for target in allowed]
    )
    token = build_preview_token(
        action=ActionKind.KILL_PROCESS,
        target_signature_value=signature,
        item_count=len(allowed),
        total_bytes=0,
        token_id=token_id,
        now=now,
        ttl_s=policy.preview_ttl_s,
    )
    return targets, decision, token


class KillExecutor:
    """逐项执行：重验身份/黑名单/自身祖先 → terminate → 等待退出。"""

    def __call__(self, target: object) -> ActionExecutionResult:
        if not isinstance(target, KillTarget):
            return ActionExecutionResult("failed", "invalid_target", "目标类型不是 KillTarget")
        pid = target.pid
        if pid <= 0 or pid in PROTECTED_PIDS:
            return ActionExecutionResult("refused", "protected_pid", "PID 0/4 等系统进程禁止结束")
        if pid in live_ancestor_pids():
            return ActionExecutionResult("refused", "self_protected", "本程序自身或其祖先进程禁止结束")
        if target.never_terminate:
            return ActionExecutionResult("refused", "protected_process", "进程在动作黑名单中")

        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return ActionExecutionResult("refused", "stale", "进程已不存在（可能已退出）")
        except psutil.AccessDenied:
            return ActionExecutionResult("failed", "access_denied", "无权限访问该进程")
        except (psutil.Error, OSError) as exc:
            return ActionExecutionResult("failed", "open_failed", f"{type(exc).__name__}: {exc}")

        try:
            live_name = process.name()
        except (psutil.Error, OSError):
            live_name = ""
        if live_name and live_name.casefold() in NEVER_TERMINATE_NAMES:
            return ActionExecutionResult("refused", "protected_process", "进程名在动作黑名单中")

        try:
            live_create_time = float(process.create_time())
        except (psutil.Error, OSError):
            return ActionExecutionResult("refused", "unreadable", "无法读取进程创建时间（权限不足）")
        if target.create_time > 0 and abs(live_create_time - target.create_time) > IDENTITY_TOLERANCE_S:
            return ActionExecutionResult(
                "refused", "identity_changed", "进程身份与扫描快照不一致（已退出或 PID 被复用）"
            )

        try:
            live_exe = process.exe()
        except (psutil.Error, OSError):
            live_exe = None
        if target.exe and live_exe and normalize_path(target.exe) != normalize_path(live_exe):
            return ActionExecutionResult("refused", "identity_changed", "进程可执行文件路径已变化")

        try:
            process.terminate()
        except psutil.NoSuchProcess:
            return ActionExecutionResult("success", detail="进程已退出（无需终止）")
        except psutil.AccessDenied:
            return ActionExecutionResult("failed", "access_denied", "权限不足，无法结束该进程")
        except (psutil.Error, OSError) as exc:
            return ActionExecutionResult("failed", "terminate_failed", f"{type(exc).__name__}: {exc}")

        try:
            process.wait(timeout=TERMINATE_WAIT_S)
        except psutil.TimeoutExpired:
            return ActionExecutionResult(
                "failed", "still_alive", f"已发送终止但进程 {TERMINATE_WAIT_S:.0f}s 内仍在运行（可能受保护）"
            )
        except psutil.NoSuchProcess:
            pass
        except (psutil.Error, OSError):
            pass
        return ActionExecutionResult(
            "success", detail="已结束进程（Windows 强制终止，未保存数据可能丢失）"
        )


def live_ancestor_pids() -> set[int]:
    """从当前进程沿 live ppid 链收集自身与祖先 PID（用于执行前自保护复验）。"""

    result: set[int] = set()
    try:
        current = os.getpid()
        for _ in range(256):
            if current <= 0 or current in result:
                break
            result.add(current)
            try:
                current = psutil.Process(current).ppid()
            except (psutil.Error, OSError):
                break
    except Exception:  # noqa: BLE001 - 自保护失败时保守返回自身 PID
        return {os.getpid()}
    return result
