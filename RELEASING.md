# Release guide（发布指南）

This document explains how to publish **Perf Purifier** to GitHub and cut a release.
The repository is already prepared for publishing; only the steps below are left.

> Chinese version below / 中文说明见文末。

---

## 1. Prepare the repository (one time)

### 1.1 Install Git

The build machine may not have Git installed. Install it first:

```powershell
winget install --id Git.Git -e --source winget
# or download from https://git-scm.com/download/win
```

### 1.2 Replace the `OWNER` placeholder

Several files contain `OWNER` in URLs. Replace it with your GitHub user/org name:

| File | Where |
|---|---|
| `pyproject.toml` | `[project.urls]` |
| `.github/ISSUE_TEMPLATE/config.yml` | discussions / security advisory links |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | SECURITY.md link |
| `.github/ISSUE_TEMPLATE/feature_request.yml` | SECURITY.md link |
| `SECURITY.md` | advisory link |
| `CONTRIBUTING.md` | clone URL |

```powershell
# Example: OWNER -> myname
Get-ChildItem -Recurse -File -Include *.md,*.toml,*.yml,*.yaml |
  Where-Object { $_.FullName -notmatch '\\.venv\\|\\.git\\' } |
  ForEach-Object {
    $text = Get-Content $_.FullName -Raw -Encoding UTF8
    if ($text -match 'OWNER') {
      ($text -replace 'Mgnaer/perf-purifier', 'myname/perf-purifier') |
        Set-Content $_.FullName -Encoding UTF8 -NoNewline
    }
  }
```

### 1.3 Create the Git repository and push

```powershell
cd perf-purifier
git init -b main
git add .
git status                      # verify that .venv/, build/, dist/, *.log are NOT staged
git commit -m "feat: v1.2.0 - disk space module, CLI, GitHub-ready packaging"
git remote add origin https://github.com/<your-name>/perf-purifier.git
git push -u origin main
```

Create the empty repository on GitHub first (no README/license, to avoid conflicts).

### 1.4 Repository settings on GitHub

- **About**: description + topics: `windows`, `disk-cleanup`, `system-tools`, `pyside6`, `python`
- **Actions**: enabled (CI + Release workflows are included)
- **Security**: enable *Private vulnerability reporting* and *Dependabot alerts*
- **Releases**: nothing to configure; tags trigger the workflow
- Optional: *Discussions* enabled (referenced by the issue template)

---

## 2. Cut a release

```powershell
git tag -a v1.2.0 -m "Perf Purifier v1.2.0"
git push origin v1.2.0
```

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which:

1. builds the GUI (`PerfPurifier.exe`, one-folder) on `windows-latest`;
2. builds the CLI (`perfpurifier-cli.exe`, one-file);
3. zips the GUI folder and attaches `PerfPurifier-<tag>-windows-x64.zip` + the CLI exe
   to the GitHub Release (release notes auto-generated).

Verify the release page contains both assets, then edit the release notes if needed.

---

## 3. Local build (optional)

GUI (one-folder):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install pyinstaller
powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1
```

CLI (one-file):

```powershell
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --onefile --console `
  --name perfpurifier-cli --paths src --collect-submodules perf_purifier run_cli.py
```

Local artifacts are unsigned; Windows SmartScreen may warn on first run
(“More info → Run anyway”).

---

## 4. Pre-release checklist

- [ ] `python -m pytest -q` passes (offscreen Qt: `$env:QT_QPA_PLATFORM = "offscreen"`)
- [ ] `python -m ruff check src tests` passes
- [ ] `python run.py` opens the GUI; **磁盘空间** page scans and previews correctly
- [ ] `python run_cli.py scan` / `clean`（预演）on a real machine look sane
- [ ] No personal data in the repo: `git grep -n -E "C:\\\\Users\\\\<you>|<username>|DESKTOP-"` is empty
- [ ] `CHANGELOG.md` has an entry for the version being released
- [ ] `pyproject.toml` version == `src/perf_purifier/__init__.py:__version__`

---

## 中文说明

1. **安装 Git**（`winget install Git.Git`），把各文件里的 `OWNER` 换成你的 GitHub 用户名/组织名。
2. 在 GitHub 新建空仓库（不要勾选自动生成 README/LICENSE）。
3. `git init -b main` → `git add .` → 检查暂存区没有 `.venv/`、`build/`、`dist/`、日志文件 →
   `git commit` → `git remote add origin ...` → `git push -u origin main`。
4. 仓库设置里打开 Actions、Security（私密漏洞报告）、Dependabot，并填写 About/Topics。
5. 发版：`git tag -a v1.2.0 -m "..."` → `git push origin v1.2.0`，Release 工作流会自动
   构建 GUI 与 CLI、打包 zip 并创建 GitHub Release。
6. 本地构建方式与发版前检查清单见上方英文部分。
