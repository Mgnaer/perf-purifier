"""阶段 2D：硬链接去重（目标构建 / 完整度适配 / 安全替换执行器）。

安全边界（S3/S6/S7）：
* 只对"内容完全相同的重复组"操作；组内已有硬链接（P0 判定）默认拒绝；
* 同卷 + NTFS 校验；执行前对两份文件重算全量 SHA-256 复验；
* 安全替换：``os.link(canonical → 临时名)`` → ``os.replace(临时名 → redundant)`` →
  校验 ``(dev, ino)``；失败清理临时文件，冗余文件保持原样（不丢数据）；
* 替换后冗余路径的 mtime/ACL 会变为保留文件的（事实，UI 必须告知）；
* 默认关闭，需 ``stage2_enabled`` + ``allow_hardlink_dedupe`` 双开关。
"""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from collections.abc import Sequence

from ..core.action_policy import (
    ActionKind,
    ActionPolicy,
    HardlinkDetachTarget,
    HardlinkTarget,
    PolicyDecision,
    PreviewToken,
    build_preview_token,
    evaluate_detach_targets,
    evaluate_hardlink_targets,
    target_signature,
)
from ..core.cancel import CancelToken
from ..core.judgements import CompletenessVerdict, FileMeta, ScanStats, compute_completeness
from ..core.models import Completeness, DuplicateGroup, FileRecord, FileScanResult
from ..core.winapi import is_ntfs_volume, is_reparse_point
from ..jobs.action_job import ActionExecutionResult

CHUNK_BYTES = 1024 * 1024


def file_scan_verdict(result: FileScanResult, *, is_admin: bool) -> CompletenessVerdict:
    """文件扫描结果 → 完整度闸门（limited 时禁止硬链接去重）。"""

    stats = ScanStats(
        total_items=result.files_scanned,
        unreadable_items=result.skipped_unreadable + result.failed_reads,
        permission_limited=(not is_admin and result.completeness is not Completeness.FULL),
        budget_truncated=result.truncated,
    )
    return compute_completeness(stats)


def group_selectable(group: DuplicateGroup) -> bool:
    """UI 默认是否允许勾选该重复组（已含硬链接的组不再自动建链接）。"""

    return (
        len(group.files) >= 2
        and not group.already_hardlinked
        and not group.has_hardlinks
    )


def canonical_for_group(group: DuplicateGroup) -> FileRecord | None:
    """保留文件：优先"建议保留"，否则组内第一个。"""

    suggested = group.suggested_keep
    if suggested is not None:
        return suggested
    return group.files[0] if group.files else None


def _file_meta(record: FileRecord) -> FileMeta:
    return FileMeta(
        path=record.path,
        st_dev=record.dev,
        st_ino=record.ino,
        st_nlink=0,
        size=record.size,
    )


def hardlink_targets_from_groups(groups: Sequence[DuplicateGroup]) -> list[HardlinkTarget]:
    """把勾选的重复组展开为"保留文件 → 冗余文件"对（不触碰文件系统，仅 stat 判断存在性）。"""

    targets: list[HardlinkTarget] = []
    for group in groups:
        canonical = canonical_for_group(group)
        if canonical is None:
            continue
        group_metas = tuple(_file_meta(record) for record in group.files)
        ntfs = is_ntfs_volume(canonical.path) is True
        for record in group.files:
            if record.path == canonical.path:
                continue
            same_volume = bool(canonical.dev) and canonical.dev == record.dev
            targets.append(
                HardlinkTarget(
                    canonical=_file_meta(canonical),
                    redundant=_file_meta(record),
                    group=group_metas,
                    content_sha256=group.full_sha256,
                    same_volume=same_volume,
                    ntfs=ntfs,
                    rehash_matches=True,  # 预览时只信任扫描哈希；执行器会重算
                    paths_exist=os.path.exists(canonical.path) and os.path.exists(record.path),
                )
            )
    return targets


def build_hardlink_preview(
    groups: Sequence[DuplicateGroup],
    *,
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
    now: float,
    token_id: str,
) -> tuple[list[HardlinkTarget], PolicyDecision, PreviewToken | None]:
    """构建目标 + 策略判定 + 预览 token（不允许时返回 ``None`` token）。"""

    targets = hardlink_targets_from_groups(groups)
    decision = evaluate_hardlink_targets(targets, policy, verdict)
    if not decision.allowed:
        return targets, decision, None
    allowed_targets = [targets[index] for index in decision.allowed_indices]
    signature = target_signature(
        [
            f"{target.canonical.path}|{target.redundant.path}|{target.redundant.size or 0}"
            for target in allowed_targets
        ]
    )
    token = build_preview_token(
        action=ActionKind.HARDLINK_DEDUPE,
        target_signature_value=signature,
        item_count=len(allowed_targets),
        total_bytes=sum(target.redundant.size or 0 for target in allowed_targets),
        token_id=token_id,
        now=now,
        ttl_s=policy.preview_ttl_s,
    )
    return targets, decision, token


class HardlinkExecutor:
    """逐项执行：重验同卷/NTFS/哈希身份 → 安全替换 → 校验；失败清理临时文件。"""

    def __init__(self, *, token: CancelToken | None = None) -> None:
        self._token = token or CancelToken()

    def __call__(self, target: object) -> ActionExecutionResult:
        if not isinstance(target, HardlinkTarget):
            return ActionExecutionResult("failed", "invalid_target", "目标类型不是 HardlinkTarget")
        canonical_path = target.canonical.path
        redundant_path = target.redundant.path
        if not canonical_path or not redundant_path or canonical_path == redundant_path:
            return ActionExecutionResult("refused", "invalid_path", "保留/冗余路径无效或相同")

        try:
            canonical_stat = os.stat(canonical_path, follow_symlinks=False)
            redundant_stat = os.stat(redundant_path, follow_symlinks=False)
        except FileNotFoundError:
            return ActionExecutionResult("refused", "stale", "文件已不存在（扫描后发生变化）")
        except OSError as exc:
            return ActionExecutionResult("failed", "stat_failed", f"{type(exc).__name__}: {exc}")

        if os.path.isdir(canonical_path) or os.path.isdir(redundant_path):
            return ActionExecutionResult("refused", "dir_not_supported", "目录不支持硬链接去重")
        for path in (canonical_path, redundant_path):
            reparse = is_reparse_point(path)
            if reparse is True:
                return ActionExecutionResult("refused", "reparse_point", "符号链接/junction 不参与去重")
            if reparse is None:
                return ActionExecutionResult("refused", "unreadable", "无法确认文件属性（权限不足）")

        if int(canonical_stat.st_dev) != int(redundant_stat.st_dev):
            return ActionExecutionResult("refused", "cross_volume", "不同卷之间不能建立硬链接")
        ntfs = is_ntfs_volume(canonical_path)
        if ntfs is not True:
            return ActionExecutionResult(
                "refused", "non_ntfs", "目标卷不是 NTFS（或无法确认文件系统）"
            )
        if int(canonical_stat.st_size) != int(redundant_stat.st_size):
            return ActionExecutionResult("refused", "size_mismatch", "两个文件大小不一致")
        canonical_identity = (int(canonical_stat.st_dev), int(canonical_stat.st_ino))
        redundant_identity = (int(redundant_stat.st_dev), int(redundant_stat.st_ino))
        if canonical_identity == redundant_identity:
            return ActionExecutionResult("refused", "already_hardlinked", "两个路径已指向同一份数据")

        try:
            canonical_digest = self._digest(canonical_path)
            redundant_digest = self._digest(redundant_path)
        except FileNotFoundError:
            return ActionExecutionResult("refused", "stale", "复验哈希时文件已消失")
        except OSError as exc:
            return ActionExecutionResult("failed", "hash_failed", f"{type(exc).__name__}: {exc}")
        if canonical_digest != redundant_digest or canonical_digest != target.content_sha256:
            return ActionExecutionResult(
                "refused", "content_changed", "执行前内容哈希复验不一致，拒绝去重"
            )

        temp_path = f"{redundant_path}.pp-link-{uuid.uuid4().hex[:10]}"
        try:
            os.link(canonical_path, temp_path)
        except OSError as exc:
            return ActionExecutionResult("failed", "link_failed", f"{type(exc).__name__}: {exc}")
        try:
            temp_stat = os.stat(temp_path, follow_symlinks=False)
            if (int(temp_stat.st_dev), int(temp_stat.st_ino)) != canonical_identity:
                return ActionExecutionResult("failed", "verify_failed", "临时链接身份校验失败")
            os.replace(temp_path, redundant_path)
        except OSError as exc:
            self._cleanup(temp_path)
            return ActionExecutionResult("failed", "replace_failed", f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 - 清理并报告，不中断其它项
            self._cleanup(temp_path)
            return ActionExecutionResult("failed", "replace_failed", f"{type(exc).__name__}: {exc}")

        try:
            final_stat = os.stat(redundant_path, follow_symlinks=False)
        except OSError:
            return ActionExecutionResult("failed", "verify_failed", "替换后无法校验冗余路径")
        if (int(final_stat.st_dev), int(final_stat.st_ino)) != canonical_identity:
            return ActionExecutionResult("failed", "verify_failed", "替换后身份校验失败")
        return ActionExecutionResult(
            "success",
            detail="已替换为硬链接（mtime/ACL 已继承保留文件；修改一个会影响另一个）",
        )

    def _digest(self, path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                self._token.raise_if_cancelled("硬链接去重复验哈希")
                chunk = handle.read(CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _cleanup(path: str) -> None:
        try:
            if os.path.exists(path):
                os.unlink(path)
        except OSError:
            pass


# ---------------------------------------------------------------- 4B 硬链接独立化
DETACH_TEMP_PREFIX = ".pp-detach-"


def detach_targets_from_records(records: Sequence[FileRecord]) -> list[HardlinkDetachTarget]:
    """按实时 stat 构建独立化目标（仅 nlink>1 的普通文件；不改文件）。"""

    targets: list[HardlinkDetachTarget] = []
    for record in records:
        try:
            stat_result = os.stat(record.path, follow_symlinks=False)
        except OSError:
            targets.append(HardlinkDetachTarget(path=record.path, size=record.size, mtime=0.0, nlink=0, exists=False))
            continue
        targets.append(
            HardlinkDetachTarget(
                path=record.path,
                size=int(stat_result.st_size),
                mtime=float(stat_result.st_mtime),
                nlink=int(stat_result.st_nlink),
                dev=int(stat_result.st_dev),
                ino=int(stat_result.st_ino),
                exists=True,
                is_dir=os.path.isdir(record.path),
                is_reparse=is_reparse_point(record.path) is True,
            )
        )
    return targets


def build_detach_preview(
    records: Sequence[FileRecord],
    *,
    policy: ActionPolicy,
    verdict: CompletenessVerdict | None,
    now: float,
    token_id: str,
) -> tuple[list[HardlinkDetachTarget], PolicyDecision, PreviewToken | None]:
    targets = detach_targets_from_records(records)
    decision = evaluate_detach_targets(targets, policy, verdict)
    if not decision.allowed:
        return targets, decision, None
    allowed = [targets[index] for index in decision.allowed_indices]
    token = build_preview_token(
        action=ActionKind.HARDLINK_DETACH,
        target_signature_value=target_signature(
            [f"{t.path}|{t.size}|{int(t.mtime)}|{t.nlink}" for t in allowed]
        ),
        item_count=len(allowed),
        total_bytes=sum(t.size for t in allowed),
        token_id=token_id,
        now=now,
        ttl_s=policy.preview_ttl_s,
    )
    return targets, decision, token


class HardlinkDetachExecutor:
    """复制 → 哈希校验 → os.replace：把硬链接文件恢复为独立文件；失败保留原文件。"""

    def __init__(self, *, token: object | None = None) -> None:
        self._token = token

    def _check_cancel(self) -> None:
        token = self._token
        if token is not None and hasattr(token, "raise_if_cancelled"):
            token.raise_if_cancelled("硬链接独立化")

    def __call__(self, target: object) -> ActionExecutionResult:
        if not isinstance(target, HardlinkDetachTarget):
            return ActionExecutionResult("failed", "invalid_target", "目标类型不是 HardlinkDetachTarget")
        path = target.path
        if not path:
            return ActionExecutionResult("refused", "invalid_path", "路径为空")
        try:
            stat_result = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            return ActionExecutionResult("refused", "stale", "文件已不存在")
        except OSError as exc:
            return ActionExecutionResult("failed", "stat_failed", f"{type(exc).__name__}: {exc}")
        if os.path.isdir(path):
            return ActionExecutionResult("refused", "dir_not_supported", "目录不支持")
        if is_reparse_point(path) is True:
            return ActionExecutionResult("refused", "reparse_point", "符号链接/junction 不支持")
        if int(stat_result.st_nlink) <= 1:
            return ActionExecutionResult("refused", "not_hardlinked", "该文件已不是硬链接（nlink<=1）")
        if int(stat_result.st_size) != target.size:
            return ActionExecutionResult("refused", "identity_changed", "文件大小已变化，请重新扫描")
        if target.mtime > 0 and int(stat_result.st_mtime) != int(target.mtime):
            return ActionExecutionResult("refused", "identity_changed", "文件修改时间已变化，请重新扫描")
        try:
            free = shutil.disk_usage(os.path.dirname(path) or ".").free
        except OSError as exc:
            return ActionExecutionResult("failed", "space_check_failed", f"{type(exc).__name__}: {exc}")
        if free < int(stat_result.st_size) + 1024 * 1024:
            return ActionExecutionResult(
                "refused", "no_space", "同卷剩余空间不足（需 ≥ 文件大小 + 1MB 余量）"
            )
        temp_path = path + DETACH_TEMP_PREFIX + uuid.uuid4().hex[:8]
        try:
            self._copy_with_hash(path, temp_path)
            if int(os.stat(temp_path).st_size) != int(stat_result.st_size):
                raise OSError("副本大小不一致")
            if os.stat(temp_path).st_nlink != 1:
                raise OSError("副本链接数异常")
            os.replace(temp_path, path)
        except BaseException as exc:  # noqa: BLE001 - 失败必须清理副本且保留原文件
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except OSError:
                pass
            return ActionExecutionResult("failed", "copy_or_replace_failed", f"{type(exc).__name__}: {exc}")
        try:
            final = os.stat(path)
        except OSError:
            return ActionExecutionResult("failed", "verify_failed", "替换后无法校验文件")
        if int(final.st_nlink) != 1 or int(final.st_ino) == target.ino:
            return ActionExecutionResult("failed", "verify_failed", "替换后文件仍不是独立文件")
        return ActionExecutionResult("success", detail="已复制并原子替换为独立文件（原硬链接已解除）")

    def _copy_with_hash(self, source: str, destination: str) -> None:
        digest_source = hashlib.sha256()
        digest_copy = hashlib.sha256()
        with open(source, "rb") as src, open(destination, "wb") as dst:
            while True:
                self._check_cancel()
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                digest_source.update(chunk)
                dst.write(chunk)
                digest_copy.update(chunk)
        if digest_source.hexdigest() != digest_copy.hexdigest():
            raise OSError("复制后哈希校验不一致")
