# SentinelGraph AI - Windows setup.
# Creates .venv, installs backend deps, and builds the frontend bundle.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[1/3] virtualenv"
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { python -m venv .venv }

Write-Host "[2/3] backend dependencies"
& $py -m pip install --upgrade pip | Out-Null
& $py -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt

Write-Host "[3/3] frontend bundle"
Push-Location frontend
if (-not (Test-Path node_modules)) { npm install }
npm run build
Pop-Location

Write-Host ""
Write-Host "Setup complete. Next: scripts\start.ps1"
