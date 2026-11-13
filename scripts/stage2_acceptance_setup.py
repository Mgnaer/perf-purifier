"""阶段 2 手工验收辅助脚本。

安全边界：本脚本**只创建和删除自己命名的测试文件**（目录名/前缀固定为 ``pp_stage2_``），
不会扫描/删除其它文件，不会修改配置，不会调用回收站或结束任何进程。

用法：
    python scripts/stage2_acceptance_setup.py prepare          # 创建验收样本并打印步骤
    python scripts/stage2_acceptance_setup.py verify-hardlink # 校验 2D 硬链接是否生效
    python scripts/stage2_acceptance_setup.py cleanup         # 删除本脚本创建的样本

验收完成后请按提示关闭 config.json 中的阶段 2 开关。
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

MARKER = "pp_stage2_"
TEMP_ROOT = Path(os.environ.get("TEMP") or tempfile.gettempdir()) / "pp_stage2_acceptance"
HARDLINK_DIR = TEMP_ROOT / "hardlink"
TEMP_DIR = TEMP_ROOT / "temp"
HARDLINK_KEEP = HARDLINK_DIR / "keep.bin"
HARDLINK_DUP = HARDLINK_DIR / "dup.bin"
TEMP_FILES = [TEMP_DIR / f"{MARKER}tmp_{index}.tmp" for index in (1, 2, 3)]


def _config_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(local_app_data) / "PerfPurifier" / "config.json"


def prepare() -> int:
    if HARDLINK_DIR.exists() or TEMP_DIR.exists():
        cleanup(dry_run=False)
    HARDLINK_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)

    content = hashlib.sha256(b"perf-purifier stage2 acceptance").digest() * 4096  # 128 KiB
    HARDLINK_KEEP.write_bytes(content)
    HARDLINK_DUP.write_bytes(content)

    for index, path in enumerate(TEMP_FILES, start=1):
        path.write_bytes(os.urandom(8 * 1024 + index))
    # 一个 2D 干扰项：内容相同大小但哈希不同（不应被硬链接去重）
    (HARDLINK_DIR / "same_size_different.bin").write_bytes(bytes(len(content)))

    print("=" * 72)
    print("阶段 2 验收样本已创建（均为测试文件，可随时用 cleanup 删除）")
    print(f"  2D 硬链接样本：{HARDLINK_DIR}")
    print(f"    - keep.bin / dup.bin（内容相同，预期可去重）")
    print(f"    - same_size_different.bin（同大小不同内容，预期被拒绝/不处理）")
    print(f"  2C 删除样本：{TEMP_DIR}")
    for path in TEMP_FILES:
        print(f"    - {path}")
    print()
    print("1) 修改配置后重启程序（执行层默认关闭，需显式开启）：")
    print(f"   {_config_path()}")
    print('   "stage2_enabled": true,')
    print('   "allow_delete_temp": true,')
    print('   "allow_hardlink_dedupe": true,')
    print('   "allow_kill_process": true')
    print()
    print("2) 2C：临时占用页扫描 → 勾选 pp_stage2_tmp_*.tmp → 删除选中项（回收站）→ 确认")
    print("   期望：成功 3 项；回收站可还原；操作前若先手动删一个文件，该项应拒绝(stale)。")
    print()
    print("3) 2D：重复文件页扫描路径 " + str(HARDLINK_DIR))
    print("   勾选 keep/dup 组 → 硬链接去重 → 确认；随后运行：")
    print("   .\\.venv\\Scripts\\python.exe scripts\\stage2_acceptance_setup.py verify-hardlink")
    print("   期望：OK（keep.bin 与 dup.bin 同 (dev,ino)、nlink>=2）；干扰项不被处理。")
    print()
    print("4) 2B：进程血缘页扫描 → 多选一个测试进程（如 notepad.exe）→ 结束选中进程")
    print("   确认框必须输入「结束进程」；系统进程应提示受保护；审计日志应有记录。")
    print()
    print("5) 检查审计：%LOCALAPPDATA%\\PerfPurifier\\logs\\operations.jsonl（header + item）")
    print("6) 完成后：cleanup，并把上述 4 个开关改回 false 后重启。")
    print("=" * 72)
    return 0


def verify_hardlink() -> int:
    if not HARDLINK_KEEP.exists() or not HARDLINK_DUP.exists():
        print("FAIL：硬链接样本不存在，请先运行 prepare 并完成 2D 动作")
        return 1
    keep = os.stat(HARDLINK_KEEP)
    dup = os.stat(HARDLINK_DUP)
    same_identity = (keep.st_dev, keep.st_ino) == (dup.st_dev, dup.st_ino)
    print(f"keep: dev={keep.st_dev} ino={keep.st_ino} nlink={keep.st_nlink}")
    print(f"dup : dev={dup.st_dev} ino={dup.st_ino} nlink={dup.st_nlink}")
    if same_identity and keep.st_nlink >= 2:
        print("OK：硬链接去重已生效（两个路径指向同一份数据）")
        return 0
    print("FAIL：两个路径不是硬链接；请确认已勾选正确的重复组并完成动作")
    return 1


def cleanup(dry_run: bool = False) -> int:
    root = TEMP_ROOT.resolve()
    expected_parent = Path(tempfile.gettempdir()).resolve()
    if root.name != "pp_stage2_acceptance" or root.parent != expected_parent:
        print(f"拒绝删除：路径不符合预期（{root}）")
        return 1
    if not root.exists():
        print(f"无需清理：{root} 不存在")
        return 0
    if dry_run:
        print(f"[dry-run] 将删除 {root}")
        return 0
    shutil.rmtree(root)
    print(f"已清理验收样本：{root}")
    print("提示：2C 已移动到回收站的文件需在回收站手动还原/清空；本脚本不操作回收站。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="阶段 2 手工验收辅助脚本")
    parser.add_argument(
        "command",
        choices=("prepare", "verify-hardlink", "cleanup"),
        help="prepare=创建样本；verify-hardlink=校验硬链接；cleanup=删除样本",
    )
    args = parser.parse_args()
    if args.command == "prepare":
        return prepare()
    if args.command == "verify-hardlink":
        return verify_hardlink()
    return cleanup()


if __name__ == "__main__":
    sys.exit(main())
