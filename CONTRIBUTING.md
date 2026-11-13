# Contributing to Perf Purifier

Thanks for your interest in **Perf Purifier (性能与净化)** — a local Windows system
inspection and cleanup tool. This document explains how to build, test and submit changes.

Perf Purifier targets **Windows 10/11 (64-bit)** only and is developed in Python 3.10+.
Linux, macOS and 32-bit Windows are out of scope.

## Code of Conduct

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Please also read [SECURITY.md](SECURITY.md) before touching anything that deletes,
terminates or modifies data.

## Development environment

Requirements:

- Windows 10/11 (64-bit)
- Python 3.10 or newer, 64-bit (3.12 is used in CI)
- PowerShell 7+ recommended (`pwsh`)

Create a virtual environment and install both runtime and development dependencies:

```powershell
cd perf-purifier
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
```

`scripts\setup_env.ps1` automates the same steps if you prefer.
`PyInstaller` is a **build-time** dependency only; install it separately with
`python -m pip install pyinstaller` when you need release builds.

Run the GUI:

```powershell
.\.venv\Scripts\python.exe run.py
```

Run the CLI:

```powershell
.\.venv\Scripts\python.exe run_cli.py --help
```

## Running tests

Tests are offline and must not require network access, administrator rights, real
deletion or a real Recycle Bin.

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
.\.venv\Scripts\python.exe -m pytest -q
```

`tests\conftest.py` defaults `QT_QPA_PLATFORM` to `offscreen`, but set it explicitly in
CI and in any headless shell to keep Qt from trying to open a window.

Useful variants:

```powershell
# One file or one test
.\.venv\Scripts\python.exe -m pytest tests\stage2\test_delete_temp.py -q
.\.venv\Scripts\python.exe -m pytest tests\test_smoke_offscreen.py -q -k smoke

# Stop at the first failure, show local variables
.\.venv\Scripts\python.exe -m pytest -q -x -l
```

Tests must stay deterministic and machine-independent: use temporary directories,
injected fake backends (Recycle Bin, process handles) and synthetic data instead of
touching the host's real files or processes.

## Code style

Lint configuration lives in `pyproject.toml` (`[tool.ruff]`):

- line length 110
- target Python 3.10
- selected rules: `E`, `F`, `W`, `I` (import order), `UP`, `B`; `E501` is ignored

Ruff is not pinned in `requirements-dev.txt`; CI installs it on demand. Install it once
locally:

```powershell
.\.venv\Scripts\python.exe -m pip install ruff
```

Run the linter before pushing:

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m ruff check --fix src tests   # auto-fixes where safe
```

Conventions used throughout the codebase:

- 4-space indentation, UTF-8, LF line endings (see `.editorconfig`)
- `from __future__ import annotations` at the top of Python modules
- public functions and non-trivial private helpers get docstrings
- user-facing strings are Chinese; code, identifiers, comments in tests and
  contributor-facing documentation are English
- pure logic (policy, heuristics, formatting) belongs in small functions that can be
  unit-tested without a GUI or `psutil`
- no new runtime dependency without prior discussion in an issue

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) in the form
`type(scope): summary`.

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.
Scope is optional and usually names the area, for example `feat(module-b): ...`.
Keep the subject imperative, lowercase and under ~72 characters; explain *why* in the
body. Mark breaking changes with `!` after the type/scope and a `BREAKING CHANGE:` footer.

Examples:

```text
feat(module-b): add large-file ranking page
fix(trash): keep file when Recycle Bin operation fails
docs(security): document protected path markers
```

## Pull request process

1. Open or comment on an issue first for larger changes so design and safety impact can
   be discussed before you invest time.
2. Fork the repository and branch from `main`
   (for example `feat/disk-space-module`, `fix/audit-rotation`).
3. Keep the change focused; separate refactors from behavior changes.
4. Add or update tests for the new behavior.
5. Run lint and the full test suite locally:
   `python -m ruff check src tests` and
   `$env:QT_QPA_PLATFORM = "offscreen"; python -m pytest -q`.
6. Fill in `.github/pull_request_template.md`, including the safety checklist.
7. Open the PR against `main` and link the issue (`Closes #123`). CI must be green.
8. Do not force-push after review has started unless a maintainer asks; reviewers read
   the incremental diff.

Maintainers may ask for changes, close PRs that weaken the safety model, or squash
commits on merge. Contributions are accepted under the MIT license.

## Security red lines

These are non-negotiable. A PR that violates them will not be merged:

- **Deletion goes to the Recycle Bin only.** Use the injected `send2trash`-based backend.
  Never fall back to `os.remove`, `shutil.rmtree`, `cmd /c del` or any permanent delete
  when the Recycle Bin fails — report the failure and keep the file.
- **No automatic elevation.** Never request or bypass UAC automatically, never add
  `requireAdministrator` manifests, never relaunch elevated without an explicit user
  action and confirmation. Never loop or spam UAC prompts.
- **No network access.** No telemetry, update checks, crash uploads, reverse DNS,
  online certificate revocation lookups, or remote rule/config downloads. Reports,
  logs and exports stay on the local machine.
- **Never weaken the protected lists.** `NEVER_TERMINATE_NAMES` and
  `PROTECTED_PATH_MARKERS` in `src/perf_purifier/core/whitelist.py` may only be extended
  (with tests), not bypassed or made configurable at runtime.
- **Keep destructive actions opt-in and off by default.** Execution-layer actions need
  `stage2_enabled=true`, a per-action switch, a preview, explicit item selection,
  confirmation (typed confirmation for process termination), pre-execution identity
  re-validation and append-only audit logging.
- **Do not log secrets.** Command lines and paths are redacted before they reach the UI,
  exports, logs or HTML reports; do not add raw credentials, tokens or personal paths.
- **Default behavior stays read-only.** Scanning, display and export must work without
  writing to system locations, the registry or startup entries.

If a feature cannot respect a red line, propose a read-only alternative instead.

## Adding a scan rule

Heuristic rules live in `src/perf_purifier/module_a/heuristics.py` (process module) and
in the file-scanning modules. To add one:

1. Give it a stable ID (`Rxx`, never renumber existing IDs — exports, UI and tests depend
   on them) and add a `Rule(...)` entry to the `RULES` mapping with severity, weight,
   title and description.
2. Implement the detection as a small, pure function over existing data structures where
   possible. Never call the network, spawn processes or touch the filesystem from a rule.
3. Emit **evidence, not verdicts**: the rule reports what matched and why. It must not
   label a file or process as malware. Keep evidence short (about 240 characters) and
   redact command lines with `redact_cmdline`.
4. Treat unknown or unreadable data as "unknown" and lower confidence; never turn missing
   permissions into a suspicious finding.
5. Respect the analysis whitelist so trusted system locations do not produce noise, but
   remember the whitelist must never authorize an action.
6. Add unit tests under `tests/` with synthetic inputs, covering both a positive match
   and at least one near-miss (false-positive guard).
7. Update user-facing documentation and `CHANGELOG.md` under `Unreleased` when the rule
   changes visible output; keep rule descriptions consistent with the UI.

If a rule needs new data (for example a new process field), extend the relevant model and
handle per-field read failures gracefully instead of aborting the whole scan.
