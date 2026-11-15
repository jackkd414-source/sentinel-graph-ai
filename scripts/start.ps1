# SentinelGraph AI - Windows startup (localhost-only by default).
# Override the port with:  $env:SG_PORT=9000 ; scripts\start.ps1
# Expose on the LAN ONLY with auth:  $env:SG_AUTH_TOKEN="<secret>" ; scripts\start.ps1 -BindHost 0.0.0.0
param([string]$BindHost = "127.0.0.1")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "Virtualenv missing. Run scripts\setup.ps1 first." }

$env:PYTHONPATH = Join-Path $root "backend"

# Master key: .env -> data\.master_key -> generate once and persist.
# A random key on every start would make already-stored provider credentials
# undecryptable ("master key changed?"), so it must be stable across runs.
if (-not $env:SG_MASTER_KEY) {
    $envFile = Join-Path $root ".env"
    if (Test-Path $envFile) {
        $hit = Select-String -Path $envFile -Pattern '^\s*SG_MASTER_KEY\s*=' | Select-Object -First 1
        if ($hit) { $env:SG_MASTER_KEY = ($hit.Line -split '=', 2)[1].Trim().Trim('"').Trim("'") }
    }
}
$keyFile = Join-Path $root "data\.master_key"
if (-not $env:SG_MASTER_KEY -and (Test-Path $keyFile)) {
    $env:SG_MASTER_KEY = (Get-Content $keyFile -Raw).Trim()
}
if (-not $env:SG_MASTER_KEY) {
    New-Item -ItemType Directory -Force -Path (Split-Path $keyFile) | Out-Null
    $env:SG_MASTER_KEY = & $py -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
    Set-Content -Path $keyFile -Value $env:SG_MASTER_KEY -NoNewline
    Write-Host "Generated SG_MASTER_KEY -> data\.master_key (reused on next start)"
}
$port = "8088"
if ($env:SG_PORT) { $port = $env:SG_PORT }

if (-not (Test-Path (Join-Path $root "data\sentinelgraph.db"))) {
    Write-Host "Bootstrapping empty database + synthetic demo..."
    & $py -m sentinelgraph init
    & $py -m sentinelgraph load-demo
}

# The app itself refuses a non-loopback bind without SG_AUTH_TOKEN.
& $py -m sentinelgraph serve --host $BindHost --port $port
