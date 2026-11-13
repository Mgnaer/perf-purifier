# 创建/更新虚拟环境并安装依赖（Windows PowerShell）
# 用法: powershell -ExecutionPolicy Bypass -File scripts\setup_env.ps1
#       powershell -ExecutionPolicy Bypass -File scripts\setup_env.ps1 -Python "C:\Python312\python.exe"

param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$command = Get-Command $Python -ErrorAction SilentlyContinue
if (-not $command) {
    Write-Error "未找到 Python（$Python）。请安装 Python 3.10+ 64 位，或用 -Python 指定解释器完整路径。"
    exit 1
}

& $Python -c "import sys; print('使用解释器:', sys.executable); assert sys.version_info >= (3, 10), '需要 Python 3.10+'; assert sys.maxsize > 2**32, '需要 64 位 Python'"
if ($LASTEXITCODE -ne 0) { exit 1 }

if (-not (Test-Path ".venv")) {
    Write-Host "创建虚拟环境 .venv ..."
    & $Python -m venv .venv
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

$venvPython = Join-Path $root ".venv\Scripts\python.exe"
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r requirements.txt
& $venvPython -m pip install -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { exit 1 }

& $venvPython -c "import PySide6, psutil, pytest; print('依赖就绪: PySide6', PySide6.__version__, '| psutil', psutil.__version__, '| pytest', pytest.__version__)"
Write-Host ""
Write-Host "完成。运行: .\.venv\Scripts\python.exe run.py"
Write-Host "测试:     .\.venv\Scripts\python.exe -m pytest -q"
