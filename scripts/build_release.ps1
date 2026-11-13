# Release build script for Perf Purifier.
# Builds the GUI (one-folder) and the CLI (one-file) with PyInstaller.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1
#
# PyInstaller is a build-time dependency only; it is not required at runtime.
param(
    [string]$Python = ".\.venv\Scripts\python.exe",
    [string]$AppName = "PerfPurifier",
    [string]$CliName = "perfpurifier-cli",
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))

if (-not (Test-Path $Python)) {
    throw "Python not found: $Python (create .venv first, see README)."
}

& $Python -m pip show pyinstaller *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller is missing (build-time dependency only):"
    Write-Host "  $Python -m pip install pyinstaller"
    exit 2
}

Write-Host "Building GUI ($AppName, one-folder)..."
$guiArgs = @(
    "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--windowed",
    "--name", $AppName, "--paths", "src", "--collect-submodules", "perf_purifier",
    "--add-data", "README.md;.", "--add-data", "README_zh.md;.",
    "--add-data", "requirements.txt;.", "--add-data", "docs;docs",
    "--distpath", $OutDir, "run.py"
)
& $Python @guiArgs
if ($LASTEXITCODE -ne 0) { throw "GUI build failed (exit code $LASTEXITCODE)" }

Write-Host "Building CLI ($CliName, one-file)..."
# The CLI does not use Qt: skip --collect-submodules so PySide6 is not bundled.
$cliArgs = @(
    "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console",
    "--name", $CliName, "--paths", "src",
    "--exclude-module", "PySide6", "--exclude-module", "shiboken6",
    "--distpath", $OutDir, "run_cli.py"
)
& $Python @cliArgs
if ($LASTEXITCODE -ne 0) { throw "CLI build failed (exit code $LASTEXITCODE)" }

$guiExe = Join-Path (Join-Path $OutDir $AppName) "$AppName.exe"
$cliExe = Join-Path $OutDir "$CliName.exe"
if (-not (Test-Path $guiExe)) { throw "Build finished but $guiExe is missing." }
if (-not (Test-Path $cliExe)) { throw "Build finished but $cliExe is missing." }

Write-Host "Build finished:"
Write-Host "  GUI: $guiExe"
Write-Host "  CLI: $cliExe"
Write-Host ""
Write-Host "Notes:"
Write-Host "  - Artifacts are unsigned; Windows SmartScreen may warn on first run."
Write-Host "  - The execution layer is OFF by default (Recycle Bin only when enabled)."
Write-Host "  - GitHub Actions builds the same artifacts on tag push (.github/workflows/release.yml)."
exit 0
