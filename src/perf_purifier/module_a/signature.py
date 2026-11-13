"""数字签名验证（WinVerifyTrust，ctypes 封装）。

策略与安全说明：
* **只校验"非受信路径"的 exe**：System32 下大量文件是 catalog 签名，直接校验
  会得到 TRUST_E_NOSIGNATURE，若映射为"无签名"会大面积误报；
* 禁止在线吊销查询（``WTD_CACHE_ONLY_URL_RETRIEVAL``），不联网、不弹窗、不卡 UI；
* 结果按 ``(路径, 大小, mtime)`` 缓存，同一 exe 的多个进程只校验一次；
* 任何异常/未知 HRESULT 一律降级为 ``CATALOG_OR_UNKNOWN`` / ``UNREADABLE``，不伪造结论。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import logging
import os
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from ..core.cancel import CancelToken
from ..core.models import ProcessInfo, ScanWarning, SigStatus
from ..core.whitelist import Whitelist, normalize_path
from ..core.winapi import IS_WINDOWS

logger = logging.getLogger(__name__)

# ---- WinTrust 常量（windef.h / wintrust.h）----
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_SAFER_FLAG = 0x00000100
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000

# ---- HRESULT（winerror.h）----
S_OK = 0x00000000
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_BAD_DIGEST = 0x80096010
CERT_E_EXPIRED = 0x800B0101
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_CHAINING = 0x800B010A
CERT_E_REVOKED = 0x800B010C
CERT_E_REVOCATION_FAILURE = 0x800B010E
CERT_E_WRONG_USAGE = 0x800B0110

_UNSIGNED_CODES = frozenset({TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN})
_INVALID_CODES = frozenset({TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST, CERT_E_REVOKED})
_UNTRUSTED_CODES = frozenset(
    {
        TRUST_E_SUBJECT_NOT_TRUSTED,
        CERT_E_EXPIRED,
        CERT_E_UNTRUSTEDROOT,
        CERT_E_CHAINING,
        CERT_E_REVOCATION_FAILURE,
        CERT_E_WRONG_USAGE,
    }
)

_CACHE_MAX_ENTRIES = 2000
_cache: dict[tuple[str, int, int], SignatureResult] = {}


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_GUID)),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


_ACTION_GUID = _GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

_verify_trust_fn: Callable[..., int] | None = None
_verify_trust_init_done = False


@dataclass(frozen=True, slots=True)
class SignatureResult:
    status: SigStatus
    error_code: int = 0


def _get_verify_trust() -> Callable[..., int] | None:
    """懒加载 wintrust.WinVerifyTrust（非 Windows/加载失败返回 None）。"""

    global _verify_trust_fn, _verify_trust_init_done
    if _verify_trust_init_done:
        return _verify_trust_fn
    _verify_trust_init_done = True
    if not IS_WINDOWS:
        return None
    try:
        library = ctypes.WinDLL("wintrust")
        function = library.WinVerifyTrust
        function.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p]
        function.restype = ctypes.c_long
        _verify_trust_fn = function
    except (AttributeError, OSError, ValueError):
        logger.warning("WinVerifyTrust 不可用，签名状态将降级为未知", exc_info=True)
        _verify_trust_fn = None
    return _verify_trust_fn


def _map_hresult(code: int) -> SigStatus:
    if code == S_OK:
        return SigStatus.VALID
    if code in _UNSIGNED_CODES:
        return SigStatus.UNSIGNED
    if code in _INVALID_CODES:
        return SigStatus.INVALID
    if code in _UNTRUSTED_CODES:
        return SigStatus.SIGNED_UNTRUSTED
    # 未知 HRESULT（可能来自目录签名等场景）：不做结论性映射
    return SigStatus.CATALOG_OR_UNKNOWN


def verify_file_signature(path: str) -> SignatureResult:
    """校验单个 PE 文件的 Authenticode 签名（带缓存，失败不抛异常）。"""

    if not path:
        return SignatureResult(SigStatus.UNREADABLE, 0)
    if not IS_WINDOWS:
        return SignatureResult(SigStatus.NOT_CHECKED, 0)

    normalized = normalize_path(path)
    try:
        stat_result = os.stat(path)
        size = int(stat_result.st_size)
        mtime = int(stat_result.st_mtime)
    except OSError:
        return SignatureResult(SigStatus.UNREADABLE, 0)

    cache_key = (normalized, size, mtime)
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    result = _verify_with_wintrust(path)
    if len(_cache) >= _CACHE_MAX_ENTRIES:
        _cache.clear()
    _cache[cache_key] = result
    logger.debug("签名校验 %s -> %s (0x%08X)", path, result.status.value, result.error_code)
    return result


def _verify_with_wintrust(path: str) -> SignatureResult:
    function = _get_verify_trust()
    if function is None:
        return SignatureResult(SigStatus.UNREADABLE, 0)

    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    trust_data = _WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    trust_data.dwUIChoice = WTD_UI_NONE
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    trust_data.dwUnionChoice = WTD_CHOICE_FILE
    trust_data.pFile = ctypes.pointer(file_info)
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG

    try:
        raw_code = function(
            None,
            ctypes.byref(_ACTION_GUID),
            ctypes.cast(ctypes.byref(trust_data), ctypes.c_void_p),
        )
    except (OSError, ValueError):
        logger.warning("WinVerifyTrust 调用失败：%s", path, exc_info=True)
        return SignatureResult(SigStatus.UNREADABLE, 0)

    # 释放 WinTrust 状态，避免句柄泄漏
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE
    try:
        function(None, ctypes.byref(_ACTION_GUID), ctypes.cast(ctypes.byref(trust_data), ctypes.c_void_p))
    except (OSError, ValueError):
        pass

    code = int(raw_code) & 0xFFFFFFFF
    return SignatureResult(_map_hresult(code), code)


def enrich_process_signatures(
    processes: Sequence[ProcessInfo],
    whitelist: Whitelist,
    *,
    token: CancelToken | None = None,
    max_files: int = 250,
    budget_s: float = 8.0,
    progress: Callable[[int, int], None] | None = None,
) -> tuple[list[ProcessInfo], list[ScanWarning]]:
    """为进程快照补充签名状态。

    * 受信路径（Windows/Program Files/ProgramData）→ ``CATALOG_OR_UNKNOWN``，不校验；
    * 其它路径按 exe 去重后校验，受 ``max_files`` / ``budget_s`` 预算约束；
    * 返回新的 ``ProcessInfo`` 列表（frozen dataclass 用 ``replace`` 派生）。

    ``progress(done, total)`` 用于 UI 进度。
    """

    warnings: list[ScanWarning] = []
    token = token or CancelToken()

    # 需要校验的唯一 exe：规范化路径 -> 原始路径
    candidates: dict[str, str] = {}
    for process in processes:
        if not process.exe:
            continue
        if whitelist.is_trusted_path(process.exe):
            continue
        normalized = normalize_path(process.exe)
        if normalized and normalized not in candidates:
            candidates[normalized] = process.exe

    paths = list(candidates.items())
    if len(paths) > max_files:
        warnings.append(
            ScanWarning(
                "signature_limit",
                f"待校验的可执行文件超过上限 {max_files} 个，其余进程签名状态保持“未检查”",
                phase="signature",
            )
        )
        paths = paths[:max_files]

    status_by_path: dict[str, SigStatus] = {}
    started_at = time.monotonic()
    total = len(paths)
    for index, (normalized, original) in enumerate(paths, start=1):
        token.raise_if_cancelled("数字签名校验")
        if time.monotonic() - started_at > budget_s:
            warnings.append(
                ScanWarning(
                    "signature_budget",
                    f"签名校验超过时间预算 {budget_s:.0f}s，剩余 {total - index + 1} 个文件未检查",
                    phase="signature",
                )
            )
            break
        status_by_path[normalized] = verify_file_signature(original).status
        if progress is not None:
            progress(index, total)

    enriched: list[ProcessInfo] = []
    for process in processes:
        if not process.exe:
            enriched.append(process)
            continue
        if whitelist.is_trusted_path(process.exe):
            enriched.append(replace(process, sig_status=SigStatus.CATALOG_OR_UNKNOWN))
            continue
        normalized = normalize_path(process.exe)
        status = status_by_path.get(normalized)
        if status is None:
            enriched.append(process)
        else:
            enriched.append(replace(process, sig_status=status))
    return enriched, warnings
