"""命令行敏感字段遮蔽（阶段 2 审计日志 / 确认弹窗脱敏，纯函数）。

本模块只做"给定字符串 → 遮蔽后字符串"的纯替换：无 I/O、无日志、无配置读取。
遮蔽目标仅限"值"，保留键名、分隔符、引号与结构，便于人工核对。

规则顺序固定（Header / URL 优先，其次通用键值，最后兼容遗留规则），
对已遮蔽文本重复执行结果不变（幂等）。
"""

from __future__ import annotations

import re

MASK_TEXT = "***"

# 规则表：(规则名, 正则, 替换)。规则名供测试与审计引用，不随文案变化。
_SECRET_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    # 1) 授权头：整段值遮蔽（避免 "Bearer xxx" 只遮 Bearer 留 token）
    ("authorization_header", re.compile(r"(?i)(authorization\s*:\s*)([^\"'\r\n;]+)"), r"\1***"),
    # 2) Cookie 头：整段值遮蔽
    ("cookie_header", re.compile(r"(?i)(cookie\s*:\s*)([^\"'\r\n;]+)"), r"\1***"),
    # 3) Bearer token
    ("bearer_token", re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._\-]{8,})"), r"\1***"),
    # 4) URL userinfo：只遮密码，保留用户名便于排查
    (
        "url_userinfo",
        re.compile(r"(?i)(\b[a-z][a-z0-9+.\-]*://[^:/@\s]+:)([^@/\s]+)(@)"),
        r"\1***\3",
    ),
    # 5) password= / passwd= / password:
    (
        "password_key",
        re.compile(r"(?i)(?<![A-Za-z0-9_])(password|passwd)(\s*[=:]\s*)(\S+)"),
        r"\1\2***",
    ),
    # 6) pwd=
    ("pwd_key", re.compile(r"(?i)(?<![A-Za-z0-9_])pwd(\s*[=:]\s*)(\S+)"), r"\1***"),
    # 7) token= / secret= / api_key= / apikey= / api-key=
    (
        "token_key",
        re.compile(r"(?i)(?<![A-Za-z0-9_])(token|secret|api[_-]?key)(\s*[=:]\s*)(\S+)"),
        r"\1\2***",
    ),
    # 8) 空格形式：--token xxx / --secret xxx / --api-key xxx
    (
        "dash_key_space",
        re.compile(r"(?i)(--?(?:token|secret|api[_-]?key))(\s+)(\S+)"),
        r"\1\2***",
    ),
    # 9) 遗留短选项：-p / -password / -passwd / -pwd（含空格/等号形式）
    ("legacy_short_p", re.compile(r"(?i)(--?p(?:assword|asswd|wd)?)([= ]+)(\S+)"), r"\1\2***"),
    # 10) 遗留编码命令：-enc / -encodedcommand 的 base64 载荷
    (
        "legacy_encoded_command",
        re.compile(r"(?i)(-e(?:nc(?:odedcommand)?)?)(\s+)([A-Za-z0-9+/=]{16,})"),
        r"\1\2***",
    ),
)

SECRET_RULE_NAMES: tuple[str, ...] = tuple(name for name, _pattern, _replacement in _SECRET_RULES)
"""规则名清单（测试与审计日志引用；新增规则时必须同步补测试）。"""


def redact_cmdline_text(text: str) -> str:
    """遮蔽命令行文本中的敏感字段值，返回遮蔽后的字符串（阶段 2 审计/确认弹窗）。

    判定依据（固定顺序执行，规则见模块内 ``_SECRET_RULES``）：
    * 键名必须完整（键名前不能是字母/数字/下划线），例如 ``tokenizer.exe`` 不会命中
      ``token`` 规则，``--password-policy=strict`` 不会命中 ``password`` 规则；
    * 只替换"值"：键名、``=``/``:``/空格分隔符、URL 的 ``://user:`` 与 ``@`` 保留；
    * 空值不插入遮蔽占位：``--api-key=``、``--token=`` 保持原样（没有秘密可遮）；
    * URL userinfo 只遮密码（``https://user:***@host``），用户名保留；
    * 幂等：对已遮蔽文本再次执行结果不变。

    已知局限：
    * 不解析 shell 转义/引号嵌套；带空格的密码只会遮到第一个空白处；
    * 不处理多行命令行（调用方应先把 CR/LF 规范为空格）；
    * 不覆盖自定义键名/配置文件内的密钥；不是完整的秘密扫描器；
    * URL 密码段不能包含 ``/``、``?``、``#``、空白（否则只遮到这些字符前）；
    * 遗留 ``-p <value>`` 会把 ``-p 443`` 这类端口误遮（保守，历史行为保留）；
    * 纯函数：无 I/O、无日志、无配置，同一输入永远得到同一输出。

    安全边界：遮蔽仅用于展示与日志可读性，**不能**把未遮蔽文本当作安全凭据存储；
    阶段 2 审计日志仍应避免主动记录原始命令行。
    """

    if not text:
        return text
    result = text
    for _name, pattern, replacement in _SECRET_RULES:
        result = pattern.sub(replacement, result)
    return result
