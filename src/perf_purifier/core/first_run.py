"""阶段 3A：首次使用强制预演（dry-run）标记。

设计（docs/05）：
* 首次真正执行某动作前，必须先完成一次该动作的"预演（不执行）"；
* 预演完成（产生结果）后写入 config 标记并持久化；
* 标记只增不减；如需重置可手工删除 config.json 中对应字段。
"""

from __future__ import annotations

from .action_policy import ActionKind

PREVIEW_DONE_FIELDS: dict[ActionKind, str] = {
    ActionKind.DELETE_TEMP: "delete_temp_preview_done",
    ActionKind.HARDLINK_DEDUPE: "hardlink_preview_done",
    ActionKind.KILL_PROCESS: "kill_preview_done",
    ActionKind.HARDLINK_DETACH: "hardlink_detach_preview_done",
    ActionKind.CLEAN_SPACE: "clean_space_preview_done",
}


def is_preview_required(kind: ActionKind, config: object) -> bool:
    """该动作是否仍需要先完成一次预演（标记缺失/false 时返回 True）。"""

    field_name = PREVIEW_DONE_FIELDS.get(kind)
    if field_name is None:
        return True
    return not bool(getattr(config, field_name, False))


def mark_preview_done(config: object, kind: ActionKind) -> bool:
    """标记预演完成；返回是否发生变化（未变化时不需写盘）。"""

    field_name = PREVIEW_DONE_FIELDS.get(kind)
    if field_name is None:
        return False
    if bool(getattr(config, field_name, False)):
        return False
    setattr(config, field_name, True)
    return True


def reset_preview_flags(config: object) -> bool:
    """重置全部预演标记（调试/重新验收用）；返回是否有变化。"""

    changed = False
    for field_name in PREVIEW_DONE_FIELDS.values():
        if bool(getattr(config, field_name, False)):
            setattr(config, field_name, False)
            changed = True
    return changed
