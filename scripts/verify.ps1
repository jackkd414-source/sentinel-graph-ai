# Canonical verification (Windows): backend tests -> typecheck -> release PII gate.
# Exit 0 only if every stage passes.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$fail = 0

Write-Host "== pytest =="
& .\.venv\Scripts\python.exe -m pytest; if ($LASTEXITCODE -ne 0) { $fail = 1 }

Write-Host "== tsc =="
& node .\frontend\node_modules\typescript\bin\tsc -b .\frontend; if ($LASTEXITCODE -ne 0) { $fail = 1 }

Write-Host "== release gate =="
& .\.venv\Scripts\python.exe tools\make_release.py; if ($LASTEXITCODE -ne 0) { $fail = 1 }

Write-Host ""
if ($fail -eq 0) { Write-Host "VERIFY: PASS" } else { Write-Host "VERIFY: FAIL" }
exit $fail
