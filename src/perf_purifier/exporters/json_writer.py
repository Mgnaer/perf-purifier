"""JSON 导出原语（UTF-8，无 BOM，``ensure_ascii=False`` 保留中文）。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json(path: str | Path, payload: Any) -> tuple[bool, str]:
    """写入 JSON，返回 ``(是否成功, 说明)``；失败不抛异常。"""

    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        target.write_text(text, encoding="utf-8")
        return True, f"已写入 JSON（{len(text)} 字节）"
    except (OSError, TypeError, ValueError) as exc:
        return False, f"写入 JSON 失败：{exc}"
