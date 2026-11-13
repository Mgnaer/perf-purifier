"""性能与净化（Perf Purifier）—— 本地系统检查与安全清理工具集。

默认只读扫描 + 可视化 + 导出；执行层（回收站删除 / 硬链接 / 结束进程 / 磁盘垃圾清理）
默认关闭，需手工开启并逐次二次确认。不联网、不上传数据、不自动提权。
"""

from __future__ import annotations

__version__ = "1.2.0"
__app_name__ = "性能与净化"
__app_id__ = "PerfPurifier"

__all__ = ["__version__", "__app_name__", "__app_id__"]
