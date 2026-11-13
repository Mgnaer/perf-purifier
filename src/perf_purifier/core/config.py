"""应用配置：路径约定 + 持久化参数。

配置文件位置：``%LOCALAPPDATA%\\PerfPurifier\\config.json``。
读取时对每个字段做类型校验，损坏/被手工改坏的配置不会导致启动失败。
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

APP_NAME = "性能与净化"
APP_ID = "PerfPurifier"
APP_VERSION = "1.2.0"
REPORT_PREFIX = "PerfPurifier报告"


def app_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or tempfile.gettempdir()
    return Path(base) / APP_ID


def log_dir() -> Path:
    return app_data_dir() / "logs"


def config_path() -> Path:
    return app_data_dir() / "config.json"


def default_export_dir() -> Path:
    home = Path.home()
    desktop = home / "Desktop"
    base = desktop if desktop.is_dir() else home
    return base / REPORT_PREFIX


@dataclass(slots=True)
class AppConfig:
    """可持久化的用户配置。字段保持向后兼容，只增不改语义。"""

    # 是否已确认免责声明
    disclaimer_ack: bool = False
    # 导出/界面中的命令行是否脱敏（风险判定始终使用原文）
    cmdline_redact: bool = True
    cmdline_max_chars: int = 200
    # 单次扫描的进程数安全上限（防止异常环境拖死 UI）
    max_processes: int = 4000
    # 网络连接采集
    network_scan_enabled: bool = True
    # 数字签名校验（只校验非受信路径的 exe；禁止在线吊销查询）
    signature_check_enabled: bool = True
    signature_max_files: int = 250
    signature_budget_s: float = 8.0
    # 临时文件占用扫描（有文件数/时间预算，避免长时间占用磁盘）
    temp_scan_enabled: bool = True
    temp_max_files: int = 200_000
    temp_budget_s: float = 8.0
    temp_probe_max_files: int = 300
    temp_probe_budget_s: float = 2.0
    # 模块 B：重复文件/大文件扫描（只读；遍历有上限，哈希可随时取消）
    file_scan_max_files: int = 300_000
    file_scan_walk_budget_s: float = 120.0
    file_scan_large_limit: int = 100
    # 阶段 1C 增强：排除规则 / 哈希并发（0=按介质自动）/ SQLite 哈希缓存
    file_scan_exclude_patterns: list[str] = field(default_factory=list)
    file_scan_hash_workers: int = 0
    file_scan_cache_enabled: bool = True
    file_scan_cache_ttl_days: int = 30
    # 阶段 2：执行层（全部默认关闭；开启后仍需预览 token + 二次确认 + 审计日志）
    stage2_enabled: bool = False
    allow_delete_temp: bool = False
    allow_hardlink_dedupe: bool = False
    allow_kill_process: bool = False
    allow_hardlink_detach: bool = False
    action_preview_ttl_s: float = 120.0
    action_max_delete_items: int = 200
    action_max_delete_bytes: int = 5 * 1024**3
    action_max_hardlink_items: int = 100
    action_max_kill_items: int = 20
    action_max_detach_items: int = 20
    # 阶段 3A：首次使用某动作前必须完成一次"预演（不执行）"；完成预演后置 true
    delete_temp_preview_done: bool = False
    hardlink_preview_done: bool = False
    kill_preview_done: bool = False
    hardlink_detach_preview_done: bool = False
    clean_space_preview_done: bool = False
    # 模块 C（磁盘空间）：执行层默认关闭；批量上限；扫描预算；默认风险等级
    allow_clean_space: bool = False
    action_max_clean_items: int = 500
    action_max_clean_bytes: int = 10 * 1024**3
    slim_include_caution: bool = False
    slim_include_system: bool = False
    slim_exclude_paths: list[str] = field(default_factory=list)
    slim_overview_budget_s: float = 60.0
    slim_junk_budget_s: float = 60.0
    slim_large_file_limit: int = 20
    # 分析白名单（用户自定义，抑制误报；与"动作黑名单"无关）
    analysis_whitelist_paths: list[str] = field(default_factory=list)
    analysis_whitelist_names: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None = None) -> AppConfig:
        target = path or config_path()
        try:
            raw: Any = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        if not isinstance(raw, dict):
            return cls()
        config = cls()
        for config_field in fields(cls):
            if config_field.name not in raw:
                continue
            default = getattr(config, config_field.name)
            value = raw[config_field.name]
            if isinstance(default, bool):
                if isinstance(value, bool):
                    setattr(config, config_field.name, value)
            elif isinstance(default, float):
                if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                    setattr(config, config_field.name, float(value))
            elif isinstance(default, int):
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    setattr(config, config_field.name, value)
            elif isinstance(default, str):
                if isinstance(value, str):
                    setattr(config, config_field.name, value)
            elif isinstance(default, list):
                if isinstance(value, list):
                    setattr(
                        config,
                        config_field.name,
                        [str(item) for item in value if isinstance(item, (str, int, float))],
                    )
        return config

    def save(self, path: Path | None = None) -> tuple[bool, str]:
        target = path or config_path()
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(asdict(self), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return True, ""
        except OSError as exc:
            return False, f"写入配置失败：{exc}"
