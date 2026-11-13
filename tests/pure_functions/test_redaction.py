"""任务 3 P0 补测：命令行敏感字段遮蔽（纯函数，无 I/O、无日志副作用）。

覆盖清单（对应阶段 2 依赖）：
* 审计日志：落盘/展示前统一遮蔽，``***`` 不泄漏原值；
* 2B/2C/2D 确认弹窗：命令行可读但不含密码/令牌；
* 兼容性：旧 ``fmt.redact_cmdline(Sequence)`` 行为保持不变（阶段 1 测试锁定）。

规则表映射（实现为 10 条正则，覆盖清单的 15 语义行）：
password/passwd、pwd、token/secret/api_key/apikey、--api-key 空格/等号、
Authorization、Bearer、Cookie、URL userinfo、遗留 -p、遗留 -enc。
"""

from __future__ import annotations

import pytest

from perf_purifier.core.fmt import redact_cmdline
from perf_purifier.core.redaction import (
    MASK_TEXT,
    SECRET_RULE_NAMES,
    redact_cmdline_text,
)


# ---------------------------------------------------------------- 规则正例
@pytest.mark.parametrize(
    ("label", "text", "must_hide"),
    [
        ("password_eq", "tool.exe --password=hunter2", "hunter2"),
        ("passwd_eq", "tool.exe passwd=abc123", "abc123"),
        ("pwd_eq", "tool.exe pwd=s3cr3t", "s3cr3t"),
        ("token_eq", "tool.exe token=ghp_abc123", "ghp_abc123"),
        ("secret_eq", "tool.exe secret=topsecret", "topsecret"),
        ("api_key_eq", "tool.exe api_key=abcd1234", "abcd1234"),
        ("apikey_eq", "tool.exe apikey=abcd1234", "abcd1234"),
        ("api_key_colon", "tool.exe --api-key=abcd1234", "abcd1234"),
        ("dash_api_key_space", "tool.exe --api-key abcd1234", "abcd1234"),
        ("dash_token_space", "tool.exe --token abc12345", "abc12345"),
        ("authorization_header", "curl Authorization: Bearer eyJhbGciOiJIUzI1", "eyJhbGciOiJIUzI1"),
        ("bearer_token", "tool --header X: Bearer eyJhbGciOiJIUzI1", "eyJhbGciOiJIUzI1"),
        ("cookie_header", "curl Cookie: sessionid=abc123xyz", "abc123xyz"),
        ("url_userinfo", "curl https://alice:s3cr3t@example.com/x", "s3cr3t"),
        ("legacy_short_p", "tool.exe -p hunter2", "hunter2"),
        ("legacy_encoded_command", "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
    ],
)
def test_rule_positive_masks_value(label: str, text: str, must_hide: str) -> None:
    redacted = redact_cmdline_text(text)
    assert MASK_TEXT in redacted, label
    assert must_hide not in redacted, label


# ---------------------------------------------------------------- 规则反例
@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("password_policy_not_key", "tool.exe --password-policy=strict"),
        ("password_file_not_key", "tool.exe password_file=C:\\secrets.txt"),
        ("passwd_command", "passwd"),
        ("pwd_command", "pwd"),
        ("tokenizer_word", "tokenizer.exe --engine=fast"),
        ("tokens_not_token", "tool.exe tokens=10"),
        ("secretary_word", "secretary.exe --mode=fast"),
        ("api_key_file_not_key", "tool.exe api_key_file=C:\\x"),
        ("apikeys_not_apikey", "tool.exe apikeys=2"),
        ("authorization_mode_flag", "kube-apiserver --authorization-mode=RBAC"),
        ("bearer_filename", "C:\\tools\\bearer-scan.exe --run"),
        ("cookie_policy_flag", "tool.exe --cookie-policy=accept"),
        ("url_without_userinfo", "curl https://example.com/path?q=1"),
        ("legacy_short_p_no_value", "tool.exe -p"),
        ("encoding_not_enc", "tool.exe --encoding utf-8"),
    ],
)
def test_rule_negative_does_not_mask(label: str, text: str) -> None:
    assert redact_cmdline_text(text) == text, label


# ---------------------------------------------------------------- 组合/边界
def test_multiple_secrets_in_one_command() -> None:
    text = (
        "tool.exe --password=hunter2 --token abc123 api_key=key123 "
        "https://alice:s3cr3t@host/x Authorization: Bearer eyJabcdef"
    )
    redacted = redact_cmdline_text(text)
    for secret in ("hunter2", "abc123", "key123", "s3cr3t", "eyJabcdef"):
        assert secret not in redacted


def test_empty_string() -> None:
    assert redact_cmdline_text("") == ""


def test_command_only_no_args() -> None:
    assert redact_cmdline_text("cmd.exe") == "cmd.exe"


def test_non_ascii_path_and_value() -> None:
    redacted = redact_cmdline_text(r"C:\用户\工具.exe --password=秘密")
    assert "秘密" not in redacted
    assert r"C:\用户\工具.exe" in redacted


def test_empty_value_is_left_untouched() -> None:
    for text in ("tool.exe --api-key=", "tool.exe --token=", "tool.exe --password="):
        assert redact_cmdline_text(text) == text


def test_idempotent_reapply() -> None:
    text = "tool.exe --password=hunter2 https://u:pw@h/x Cookie: sid=abc"
    once = redact_cmdline_text(text)
    twice = redact_cmdline_text(once)
    assert once == twice


def test_url_keeps_username_masks_password_only() -> None:
    redacted = redact_cmdline_text("curl https://alice:s3cr3t@example.com/x")
    assert "alice" in redacted
    assert "s3cr3t" not in redacted
    assert "@example.com" in redacted


def test_rule_table_is_complete_and_stable() -> None:
    assert SECRET_RULE_NAMES == (
        "authorization_header",
        "cookie_header",
        "bearer_token",
        "url_userinfo",
        "password_key",
        "pwd_key",
        "token_key",
        "dash_key_space",
        "legacy_short_p",
        "legacy_encoded_command",
    )


# ---------------------------------------------------------------- 旧接口兼容
def test_legacy_fmt_wrapper_still_masks() -> None:
    text = redact_cmdline(("tool.exe", "--password=hunter2", "--token", "abc123"))
    assert "hunter2" not in text
    assert "abc123" not in text
    assert MASK_TEXT in text


def test_legacy_fmt_wrapper_disabled_keeps_original() -> None:
    text = redact_cmdline(("tool.exe", "--password=hunter2"), enabled=False)
    assert "hunter2" in text
    assert MASK_TEXT not in text


def test_legacy_fmt_wrapper_truncates_after_masking() -> None:
    text = redact_cmdline(("tool.exe", "--password=hunter2", "tail"), max_chars=12)
    assert len(text) <= 12
    assert "hunter2" not in text


def test_fmt_wrapper_normalises_newlines_before_redaction() -> None:
    text = redact_cmdline(("tool.exe", "line1\n--token abc123"))
    assert "\n" not in text
    assert "abc123" not in text
