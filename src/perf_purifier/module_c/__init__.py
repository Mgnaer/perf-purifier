"""模块 C：磁盘空间（C 盘瘦身）。

分两块能力，全部只读扫描 + 回收站删除：

1. **空间盘点**：分区用量、卷根顶层目录占用、最大文件排行（单遍遍历）；
2. **垃圾清理**：按「规则库」扫描临时文件 / 应用缓存 / 更新包残留 / 系统缓存等，
   经预演与二次确认后移入回收站（失败不永久删除）。

安全边界与模块 A/B 一致：默认只读；执行层默认关闭；受保护路径（系统卷影、
WinSxS、System32\\config、用户数据目录等）永不触碰；不跟随符号链接/junction。
"""

from __future__ import annotations

__all__ = ["models", "safety", "rules", "scanner", "executor", "report", "win_trash"]
