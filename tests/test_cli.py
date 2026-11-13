"""CLI 冒烟测试：参数解析、只读命令、预演不执行、apply 走回收站 + 审计。"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from perf_purifier import cli
from perf_purifier.core.config import AppConfig
from perf_purifier.module_c.models import JunkItem, JunkRuleResult
from perf_purifier.module_c.rules import RULES_BY_ID


def _fake_results(tmp_path: Path) -> list[JunkRuleResult]:
    rule = RULES_BY_ID["temp_user"]
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    item = JunkItem(
        rule_id=rule.id,
        rule_name=rule.name,
        category=rule.category,
        risk=rule.risk,
        path=str(cache / "a.tmp"),
        size=1024,
        file_count=1,
        mtime=0.0,
        kind="file",
        allowed_root=str(cache),
    )
    return [JunkRuleResult(rule=rule, items=[item])]


def _patch_common(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    results: list[JunkRuleResult] | None = None,
) -> list[JunkRuleResult]:
    payload = results if results is not None else _fake_results(tmp_path)
    monkeypatch.setattr(cli, "_load_config", lambda: AppConfig())
    monkeypatch.setattr(cli, "_scan_junk", lambda *args, **kwargs: (payload, [], False, []))
    monkeypatch.setattr(cli, "log_dir", lambda: tmp_path / "logs")
    return payload


def _executor_factory(*, outcome_result: str = "success"):
    class FakeExecutor:
        def __init__(self, *args, **kwargs) -> None:
            self.args = args

        def __call__(self, item):
            return SimpleNamespace(
                result=outcome_result,
                error_code="" if outcome_result == "success" else "trash_failed",
                detail="" if outcome_result == "success" else "注入失败",
            )

    return FakeExecutor


# --------------------------------------------------------------------------- 基础
def test_version_exits() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0


def test_help_exits(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    assert "perfpurifier-cli" in capsys.readouterr().out


def test_no_args_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 0
    assert "perfpurifier-cli" in capsys.readouterr().out


def test_rules_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["rules"]) == 0
    output = capsys.readouterr().out
    assert "规则库" in output
    assert "temp_user" in output


def test_config_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["config"]) == 0
    output = capsys.readouterr().out
    assert "配置文件" in output
    assert "1.2.0" in output


def test_split_ids() -> None:
    assert cli._split_ids("a,b; c") == ["a", "b", "c"]
    assert cli._split_ids(None) == []


def test_write_json_stdout(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert cli._write_json("-", {"ok": True}) == 0
    assert '"ok": true' in capsys.readouterr().out
    target = tmp_path / "out.json"
    assert cli._write_json(str(target), {"a": 1}) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["a"] == 1


# --------------------------------------------------------------------------- 扫描
def test_scan_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_common(monkeypatch, tmp_path)
    assert cli.main(["scan"]) == 0
    output = capsys.readouterr().out
    assert "可清理汇总" in output
    assert "下一步" in output


def test_scan_json_export(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_common(monkeypatch, tmp_path)
    target = tmp_path / "scan.json"
    assert cli.main(["scan", "--json", str(target)]) == 0
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["app"] == "性能与净化"
    assert payload["total_bytes"] == 1024
    assert len(payload["items"]) == 1


# --------------------------------------------------------------------------- 清理
def test_clean_dry_run_never_executes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_common(monkeypatch, tmp_path)
    monkeypatch.setattr(
        cli, "SlimDeleteExecutor", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError())
    )
    assert cli.main(["clean"]) == 0
    output = capsys.readouterr().out
    assert "预演结束" in output
    assert "未做任何修改" in output


def test_clean_apply_yes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_common(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "SlimDeleteExecutor", _executor_factory())
    assert cli.main(["clean", "--apply", "--yes"]) == 0
    output = capsys.readouterr().out
    assert "清理结果" in output
    assert "成功" in output
    audit_file = tmp_path / "logs" / "operations.jsonl"
    assert audit_file.exists()
    text = audit_file.read_text(encoding="utf-8")
    assert '"record_type": "action_header"' in text
    assert '"record_type": "action_item"' in text
    assert '"record_type": "action_end"' in text


def test_clean_apply_with_empty_trash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_common(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "SlimDeleteExecutor", _executor_factory())
    monkeypatch.setattr(cli.safety, "empty_recycle_bin", lambda drive: (True, "回收站已清空"))
    assert cli.main(["clean", "--apply", "--yes", "--empty-trash"]) == 0
    assert "已真正释放空间" in capsys.readouterr().out


def test_clean_apply_reports_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_common(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "SlimDeleteExecutor", _executor_factory(outcome_result="failed"))
    assert cli.main(["clean", "--apply", "--yes"]) == 2
    output = capsys.readouterr().out
    assert "失败明细" in output


def test_clean_confirm_declined(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_common(monkeypatch, tmp_path)
    monkeypatch.setattr(
        cli, "SlimDeleteExecutor", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError())
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    assert cli.main(["clean", "--apply"]) == 0
    assert "已取消" in capsys.readouterr().out


def test_clean_no_items(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_common(monkeypatch, tmp_path, results=[])
    assert cli.main(["clean"]) == 0
    assert "没有符合" in capsys.readouterr().out


def test_clean_only_filter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_common(monkeypatch, tmp_path)
    assert cli.main(["clean", "--only", "edge_cache"]) == 0
    assert "没有符合" in capsys.readouterr().out


# --------------------------------------------------------------------------- 其他命令
def test_history_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda: AppConfig())
    monkeypatch.setattr(cli, "_read_audit_records", lambda limit: ([], 0))
    monkeypatch.setattr(cli, "log_dir", lambda: tmp_path / "logs")
    assert cli.main(["history"]) == 0
    assert "还没有任何动作记录" in capsys.readouterr().out


def test_large_command_min_size_invalid(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda: AppConfig())
    assert cli.main(["large", "--min-size", "不是尺寸"]) == 2
    assert "无法解析" in capsys.readouterr().out


def test_forced_menu(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PERFPURIFIER_FORCE_MENU", "1")
    monkeypatch.setattr(cli, "run_menu", lambda: 7)
    assert cli.main([]) == 7
    monkeypatch.delenv("PERFPURIFIER_FORCE_MENU", raising=False)
