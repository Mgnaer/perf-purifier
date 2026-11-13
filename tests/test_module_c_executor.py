"""模块 C 清理执行器测试（记录型回收站后端，不污染真实回收站）。"""

from __future__ import annotations

from pathlib import Path

import pytest

from perf_purifier.core.trash import RecordingTrashBackend
from perf_purifier.module_c import executor as executor_module
from perf_purifier.module_c.executor import SlimDeleteExecutor
from perf_purifier.module_c.models import JunkItem


def _file_item(tmp_path: Path, *, name: str = "a.tmp", **overrides) -> JunkItem:
    path = tmp_path / name
    path.write_bytes(b"x" * 8)
    defaults = {
        "rule_id": "temp_user",
        "rule_name": "用户临时文件",
        "category": "临时文件",
        "risk": "safe",
        "path": str(path),
        "size": 8,
        "file_count": 1,
        "mtime": path.stat().st_mtime,
        "kind": "file",
        "allowed_root": str(tmp_path),
    }
    defaults.update(overrides)
    return JunkItem(**defaults)


def test_executor_moves_file_to_trash(tmp_path: Path) -> None:
    item = _file_item(tmp_path)
    backend = RecordingTrashBackend()
    result = SlimDeleteExecutor(backend)(item)
    assert result.result == "success"
    assert backend.sent == [item.path]


def test_executor_moves_directory_to_trash(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    directory.mkdir()
    (directory / "x.bin").write_bytes(b"x" * 4)
    item = JunkItem(
        rule_id="game_forza_scratch",
        rule_name="极限竞速地平线图形缓存",
        category="游戏缓存",
        risk="caution",
        path=str(directory),
        size=4,
        file_count=1,
        mtime=0.0,
        kind="dir",
        allowed_root=str(tmp_path),
    )
    backend = RecordingTrashBackend()
    assert SlimDeleteExecutor(backend)(item).result == "success"
    assert backend.sent == [str(directory)]


def test_executor_refuses_admin_required(tmp_path: Path) -> None:
    item = _file_item(tmp_path, requires_admin=True)
    result = SlimDeleteExecutor(RecordingTrashBackend(), is_admin=False)(item)
    assert result.result == "refused"
    assert result.error_code == "admin_required"


def test_executor_refuses_stale(tmp_path: Path) -> None:
    item = _file_item(tmp_path, path=str(tmp_path / "missing.tmp"))
    result = SlimDeleteExecutor(RecordingTrashBackend())(item)
    assert result.result == "refused"
    assert result.error_code == "stale"


def test_executor_refuses_outside_root(tmp_path: Path) -> None:
    item = _file_item(tmp_path, allowed_root=str(tmp_path / "other"))
    result = SlimDeleteExecutor(RecordingTrashBackend())(item)
    assert result.result == "refused"
    assert result.error_code == "outside_root"


def test_executor_rejects_invalid_target() -> None:
    result = SlimDeleteExecutor(RecordingTrashBackend())("not-an-item")
    assert result.result == "refused"
    assert result.error_code == "invalid_target"


def test_executor_recycle_bin_special(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor_module.safety, "empty_recycle_bin", lambda drive: (True, "回收站已清空"))
    item = JunkItem(
        rule_id="recycle_bin",
        rule_name="回收站",
        category="回收站",
        risk="caution",
        path="C:\\$Recycle.Bin",
        size=1024,
        file_count=3,
        mtime=0.0,
        kind="special",
        allowed_root="C:\\",
        special="recycle_bin",
    )
    result = SlimDeleteExecutor(RecordingTrashBackend())(item)
    assert result.result == "success"
    assert "回收站" in result.detail


def test_executor_recycle_bin_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor_module.safety, "empty_recycle_bin", lambda drive: (False, "失败"))
    item = JunkItem(
        rule_id="recycle_bin",
        rule_name="回收站",
        category="回收站",
        risk="caution",
        path="C:\\$Recycle.Bin",
        size=0,
        file_count=0,
        mtime=0.0,
        kind="special",
        allowed_root="C:\\",
        special="recycle_bin",
    )
    result = SlimDeleteExecutor(RecordingTrashBackend())(item)
    assert result.result == "failed"
    assert result.error_code == "empty_trash_failed"


def test_executor_defender_requires_admin(tmp_path: Path) -> None:
    platform = tmp_path / "Platform"
    old = platform / "4.18.100.1-0"
    old.mkdir(parents=True)
    item = JunkItem(
        rule_id="defender_old_platforms",
        rule_name="Defender 旧平台版本",
        category="系统组件",
        risk="system",
        path=str(old),
        size=0,
        file_count=0,
        mtime=0.0,
        kind="dir",
        allowed_root=str(platform),
        requires_admin=True,
        special="defender_platforms",
    )
    result = SlimDeleteExecutor(RecordingTrashBackend(), is_admin=False)(item)
    assert result.result == "refused"
    assert result.error_code == "admin_required"


def test_executor_defender_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    platform = tmp_path / "Platform"
    old = platform / "4.18.100.1-0"
    old.mkdir(parents=True)
    monkeypatch.setattr(executor_module.safety, "is_defender_platform_old_version", lambda path: True)
    item = JunkItem(
        rule_id="defender_old_platforms",
        rule_name="Defender 旧平台版本",
        category="系统组件",
        risk="system",
        path=str(old),
        size=0,
        file_count=0,
        mtime=0.0,
        kind="dir",
        allowed_root=str(platform),
        requires_admin=True,
        special="defender_platforms",
    )
    backend = RecordingTrashBackend()
    result = SlimDeleteExecutor(backend, is_admin=True)(item)
    assert result.result == "success"
    assert backend.sent == [str(old)]


def test_executor_unknown_special() -> None:
    item = JunkItem(
        rule_id="x",
        rule_name="x",
        category="x",
        risk="safe",
        path="C:\\x",
        size=0,
        file_count=0,
        mtime=0.0,
        kind="special",
        allowed_root="C:\\",
        special="mystery",
    )
    result = SlimDeleteExecutor(RecordingTrashBackend())(item)
    assert result.result == "refused"
    assert result.error_code == "unknown_special"


def test_executor_backend_exception(tmp_path: Path) -> None:
    class RaisingBackend:
        def send(self, path: str):
            raise OSError("boom")

    item = _file_item(tmp_path)
    result = SlimDeleteExecutor(RaisingBackend())(item)
    assert result.result == "failed"
    assert result.error_code == "trash_exception"
