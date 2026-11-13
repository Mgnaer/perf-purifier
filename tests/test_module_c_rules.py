"""模块 C 规则库测试：自检、环境变量展开、通配解析、风险筛选。"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import make_junction

from perf_purifier.module_c import rules as rules_module
from perf_purifier.module_c.models import (
    MODE_FILES,
    RISK_CAUTION,
    RISK_SAFE,
    RISK_SYSTEM,
    JunkRule,
)
from perf_purifier.module_c.rules import (
    RULES,
    RULES_BY_ID,
    expand_root_template,
    resolve_roots,
    rules_by_category,
    select_rules,
    validate_rules,
)
from perf_purifier.module_c.safety import is_under, known_user_data_roots, normalize_path


def test_validate_rules_passes() -> None:
    assert validate_rules() == []


def test_rule_ids_unique() -> None:
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids))


def test_rules_by_category_covers_all() -> None:
    grouped = rules_by_category()
    assert sum(len(items) for items in grouped.values()) == len(RULES)
    assert "临时文件" in grouped


def test_system_rules_all_require_admin() -> None:
    for rule in RULES:
        if rule.risk == RISK_SYSTEM:
            assert rule.requires_admin is True, f"{rule.id} 系统级规则必须标注需要管理员"


def test_files_mode_rules_have_globs() -> None:
    for rule in RULES:
        if rule.mode == MODE_FILES:
            assert rule.file_globs, f"{rule.id} files 模式必须声明 file_globs"


def test_rule_roots_not_in_user_data() -> None:
    user_data = known_user_data_roots()
    for rule in RULES:
        for template in rule.roots:
            expanded = expand_root_template(template)
            if expanded:
                assert not is_under(expanded, user_data), f"{rule.id} 根目录落在用户数据区"


def test_expand_unresolvable_env_returns_empty() -> None:
    assert expand_root_template(r"%CSLIM_NOT_EXIST_VAR_XYZ%\x") == ""
    assert expand_root_template("") == ""


def test_resolve_temp_dedupes_short_and_long_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    temp = tmp_path / "Temp"
    temp.mkdir()
    (temp / "a.tmp").write_bytes(b"x")
    monkeypatch.setenv("TEMP", str(temp))
    monkeypatch.setenv("TMP", str(temp))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    roots = resolve_roots(RULES_BY_ID["temp_user"])
    keys = {normalize_path(root) for root in roots}
    assert len(roots) == len(keys), "同一个物理目录不应解析出多个根"
    assert any(normalize_path(str(temp)) == key for key in keys)


def test_resolve_updater_glob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app_cache = tmp_path / "someapp-updater"
    app_cache.mkdir()
    roots = resolve_roots(RULES_BY_ID["updater_caches"])
    assert any(Path(root).name == "someapp-updater" for root in roots)


def test_resolve_skips_reparse_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    real = tmp_path / "real-updater"
    real.mkdir()
    link = tmp_path / "linked-updater"
    if not make_junction(link, real):
        pytest.skip("当前环境无法创建 junction")
    try:
        roots = resolve_roots(RULES_BY_ID["updater_caches"])
        names = {Path(root).name for root in roots}
        assert "linked-updater" not in names
    finally:
        os.rmdir(link)


def test_resolve_missing_root_returns_empty(tmp_path: Path) -> None:
    rule = JunkRule(
        id="t_missing",
        name="测试",
        category="测试",
        risk=RISK_SAFE,
        mode="children",
        roots=(str(tmp_path / "不存在"),),
    )
    assert resolve_roots(rule) == []


def test_select_rules_by_risk() -> None:
    safe = select_rules()
    assert safe and all(rule.risk == RISK_SAFE for rule in safe)
    caution = select_rules(include_caution=True)
    assert any(rule.risk == RISK_CAUTION for rule in caution)
    assert all(rule.risk != RISK_SYSTEM for rule in caution)
    everything = select_rules(include_caution=True, include_system=True)
    assert len(everything) == len(RULES)


def test_validate_rules_detects_bad_root(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = JunkRule(
        id="bad_root",
        name="坏规则",
        category="测试",
        risk=RISK_SAFE,
        mode="children",
        roots=(r"C:\Windows",),
    )
    monkeypatch.setattr(rules_module, "RULES", (bad,))
    monkeypatch.setattr(rules_module, "RULES_BY_ID", {bad.id: bad})
    problems = validate_rules()
    assert any("系统白名单" in problem for problem in problems)
