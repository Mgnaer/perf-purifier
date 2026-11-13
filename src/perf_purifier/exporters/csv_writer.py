"""CSV 导出原语。

统一使用 ``utf-8-sig``（带 BOM）：Excel 双击打开中文不乱码；
行尾用 CRLF 兼容 Excel。
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any


def write_csv(
    path: str | Path,
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
) -> tuple[bool, str]:
    """写入 CSV，返回 ``(是否成功, 说明)``；失败不抛异常。"""

    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with target.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle, lineterminator="\r\n")
            writer.writerow(list(headers))
            for row in rows:
                writer.writerow(["" if value is None else value for value in row])
                count += 1
        return True, f"已写入 {count} 行"
    except (OSError, csv.Error) as exc:
        return False, f"写入 CSV 失败：{exc}"
