# Security Policy

Perf Purifier (性能与净化) is a local Windows inspection and cleanup tool. It reads system
state, and — only when the user explicitly enables it — moves selected files to the
Recycle Bin, creates hard links, or terminates processes. This document describes the
security model, the guarantees you can rely on, and how to report a vulnerability.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.2.x | Yes (security fixes) |
| < 1.2 | No |

Security fixes are released for the latest 1.2.x release. Always reproduce issues on the
latest release before reporting unless the vulnerability makes that impossible.

## Security model

### Read-only by default

Scanning, display and export are read-only. On a fresh install, with default
configuration, Perf Purifier does not end processes, delete files, create or break hard
links, write to the registry, or modify startup entries. Execution-layer actions are
disabled unless the user edits `config.json` (`stage2_enabled=true` plus the individual
action switches), restarts, completes a dry run, selects targets, and confirms.

### Recycle Bin only

File deletion is implemented exclusively through `send2trash` behind an injectable
backend. If the Recycle Bin is unavailable (network share, quota, policy, permission
denied), the operation fails and the file is left untouched. There is **no fallback to
permanent deletion**, and the failure is reported per item. Hard links require the same
volume, NTFS, identical content, a freshly recomputed hash at execution time, and are
disabled by default. Process termination re-validates PID identity (PID plus creation
time) before acting.

### No network access

Perf Purifier does not contact the network at runtime:

- no telemetry, analytics, crash uploads or update checks;
- no reverse DNS lookups for remote addresses;
- no online certificate revocation retrieval (`WTD_CACHE_ONLY_URL_RETRIEVAL` is used for
  signature checks);
- reports, logs, audit trails and exports are written only to local paths chosen by the
  user or to `%LOCALAPPDATA%\PerfPurifier\`.

### No automatic elevation

The application runs with the privileges of the current user. An optional "restart as
administrator" action exists for users who need complete process/network data, but it is
triggered only by an explicit click, requires confirmation, and hands control to the
Windows UAC prompt. Perf Purifier never bypasses UAC, never adds an
`requireAdministrator` manifest, never elevates silently, and never loops prompts. If
elevation is declined, the scan continues with degraded but clearly labelled data.

### Protected paths

Deletion requests are rejected when the normalized target path (absolute, case-folded,
no trailing separator) falls under any of these markers, matched on directory boundaries:

| Marker | Notes |
| --- | --- |
| `\System Volume Information` | Volume shadow copy / restore metadata |
| `\$Recycle.Bin` | Recycle Bin storage itself |
| `\Windows\WinSxS` | Component store |
| `\Windows\System32` | Core system binaries |
| `\Windows\SysWOW64` | 32-bit system binaries |
| `\Windows\System32\config` | Registry hives |

The list is defined as `PROTECTED_PATH_MARKERS` in
`src/perf_purifier/core/whitelist.py` and is locked by tests. Prefix checks are
directory-boundary aware, so a sibling such as `C:\Windows\System32Foo` does not match
`C:\Windows\System32`. Symbolic links, junctions and reparse points are not followed
during scanning, and cloud placeholder files are skipped instead of being hydrated.

### Protected processes

Process termination refuses PID 0 and PID 4, the application itself and its ancestor
chain, and every name in `NEVER_TERMINATE_NAMES` (for example `System`,
`System Idle Process`, `Registry`, `Memory Compression`, `smss.exe`, `csrss.exe`,
`wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, `svchost.exe`,
`fontdrvhost.exe`, `dwm.exe`, `wudfhost.exe`, `TrustedInstaller.exe`, `MsMpEng.exe`).
Identity is re-checked immediately before the action.

### Local data and privacy

- Config: `%LOCALAPPDATA%\PerfPurifier\config.json`
- Logs and audit trail: `%LOCALAPPDATA%\PerfPurifier\logs\` (`operations.jsonl` is
  append-only and rotated by size)
- Snapshots: `%LOCALAPPDATA%\PerfPurifier\snapshots\`
- Exports go wherever the user saves them.

Logs and exports redact command-line secrets by default. Nothing is uploaded. Users
should still review logs before sharing them publicly, since they can contain local
paths, user names and process names.

## Out of scope

Perf Purifier is **not** an antivirus, firewall or sandbox, and its heuristic findings
are not security verdicts. The following are out of scope for this policy:

- false positives or false negatives from heuristic rules (report them as bugs);
- an attacker who already has administrator or kernel-level access on the machine;
- data already deleted to the Recycle Bin that the user later empties;
- modifications made by other software, or by the user editing scoring rules in
  configuration;
- unsupported platforms (Windows 8.1 and older, 32-bit Windows, Linux, macOS);
- vulnerabilities in third-party dependencies that have no exploitable path in this
  project (please still report them so we can pin or bump).

## Reporting a vulnerability

**Do not open a public issue, discussion, or PR for a security vulnerability.** Public
disclosure before a fix puts users at risk.

Report privately through GitHub Security Advisories:

1. Open the repository's **Security** tab.
2. Choose **Advisories** → **Report a vulnerability** (private vulnerability reporting).
3. If that is unavailable, contact the maintainers listed in the repository profile
   instead of posting details publicly.

Please include:

- affected version (from the About dialog or `perf_purifier.__version__`) and whether
  the build is source or PyInstaller-frozen;
- Windows edition, version and build (`Win + R` → `winver`), and whether the app ran
  elevated;
- prerequisite configuration, especially `stage2_enabled` and the individual action
  switches, plus a dry-run result if relevant;
- exact reproduction steps and the observed impact;
- relevant excerpts from `%LOCALAPPDATA%\PerfPurifier\logs\`, with tokens, user names,
  IP addresses and personal paths removed;
- any suggested fix or mitigation.

You can expect an initial acknowledgement on a best-effort basis, typically within five
business days. Confirmed issues are fixed on the supported 1.2.x line, and credit is
given in the release notes unless you ask to stay anonymous. Please allow a reasonable
coordinated-disclosure window before publishing details.

## Safe harbor

We welcome good-faith research on your own machine under this policy. We will not pursue
or support legal action for accidental, non-destructive research that respects this
document, avoids privacy violations and data loss, and gives us reasonable time to fix
the issue. Do not test against other people's systems, and do not use real user data.
