# Ekspor log Windows untuk SentinelGraph AI  (v2)
#
# PENTING - mengapa versi ini ada:
#   Versi pertama hanya menyalin SELURUH isi event ke satu kolom "message" sebagai
#   teks. SentinelGraph tidak membaca field dari teks bebas - ia butuh field JSON
#   bernama (user_name, process_name, dst_ip, ...). Akibatnya 84% event masuk
#   sebagai "generic" dan rule yang butuh field tidak pernah menyala.
#
#   Versi ini memecah EventData dari XML event menjadi field terstruktur.
#
# Pemakaian (PowerShell AS ADMINISTRATOR untuk log Security):
#   .\export-windows-logs.ps1 -Preset security   -Hours 24 -Out security.json
#   .\export-windows-logs.ps1 -Preset connections -Hours 24 -Out conn.json
#   .\export-windows-logs.ps1 -Preset sysmon     -Hours 24 -Out sysmon.json
#   .\export-windows-logs.ps1 -Preset all        -Hours 6  -Out bundle.json
#
# Tanpa admin (untuk uji coba):
#   .\export-windows-logs.ps1 -Preset powershell -Hours 1 -Out ps.json

[CmdletBinding()]
param(
  [ValidateSet("security","connections","firewall","sysmon","powershell","system","all")]
  [string]$Preset = "security",

  [int]$Hours = 24,
  [string]$Out = "winevents.json",
  [int]$MaxEvents = 5000
)

$ErrorActionPreference = "Stop"
$since = (Get-Date).AddHours(-$Hours)
$hostName = $env:COMPUTERNAME
$collected = @()
$notes = @()

# Pemetaan nama field EventData Windows -> nama field SentinelGraph.
# SentinelGraph memang mengenali nama-nama asli Windows (lihat MAP di ingest.py),
# tetapi penerjemahan eksplisit membuat hasilnya pasti, bukan bergantung tebakan.
# [ordered] penting: logika di bawah memakai "field pertama menang", dan
# hashtable biasa di PowerShell 5.1 tidak menjamin urutan iterasi.
$FieldMap = [ordered]@{
  # Sysmon memakai "User" (mis. DESKTOP-EXAMPLE\analyst) untuk event proses/jaringan.  # PII-SCAN-ALLOW: illustrative placeholder, not a real hostname
  # Nama lain berasal dari Windows Security.
  "User"               = "user_name"
  "TargetUserName"     = "user_name"
  "SubjectUserName"    = "user_name"
  "AccountName"        = "user_name"
  "Username"           = "user_name"
  "NewProcessName"     = "process_name"
  "Image"              = "process_name"
  "ProcessName"        = "process_name"
  "ProcessId"          = "process_id"
  "NewProcessId"       = "process_id"
  "ParentProcessName"  = "parent_process"
  "ParentImage"        = "parent_process"
  "CommandLine"        = "command_line"
  "ProcessCommandLine" = "command_line"
  "IpAddress"          = "src_ip"
  "SourceIp"           = "src_ip"
  "SourceAddress"      = "src_ip"
  "DestinationIp"      = "dst_ip"
  "DestAddress"        = "dst_ip"
  "DestinationPort"    = "dst_port"
  "DestPort"           = "dst_port"
  "QueryName"          = "domain"
  "TargetFilename"     = "file_path"
  "WorkstationName"    = "host"
}

# Event ID -> tipe event. Hanya ID yang jelas maknanya; sisanya "generic".
$TypeMap = @{
  4624 = "logon_success"
  4625 = "logon_failed"
  4634 = "logoff"
  4647 = "logoff"
  4648 = "logon_success"     # logon dengan kredensial eksplisit (indikator lateral)
  4672 = "logon_success"     # special privileges assigned
  4688 = "process_create"
  4663 = "file_access"
  4656 = "file_access"
  5156 = "network_connect"   # Windows Filtering Platform - koneksi diizinkan
  5157 = "network_connect"   # koneksi diblokir
  1    = "process_create"    # Sysmon
  3    = "network_connect"   # Sysmon
  11   = "file_access"       # Sysmon
  22   = "dns_query"         # Sysmon
  4104 = "process_create"    # PowerShell script block
}

function Test-ProcessPath {
  param([string]$v)
  if (-not $v) { return $false }
  $t = $v.Trim()
  # Harus terlihat seperti executable/path, bukan potongan label.
  # Contoh valid:   C:\Windows\System32\lsass.exe  |  \Device\...\foo.exe  |  powershell.exe
  if ($t -notmatch "\.(exe|dll|sys|com|bat|cmd|ps1|scr|msi)$") { return $false }
  if ($t -match ":\s*$")   { return $false }   # berakhir dengan titik dua (label)
  if ($t -match "^\s*(Registry|Token|Process|Creator|New Process)\b") { return $false }
  if ($t.Length -gt 260)   { return $false }
  return $true
}

function Convert-CimDate {
  param($d)
  if (-not $d) { return $null }
  try { return ([datetime]$d).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
  catch { return $null }
}

function Get-EventField {
  param($Xml, [string[]]$Names)
  # Cari nilai pertama yang ada di antara nama-nama kandidat.
  foreach ($n in $Names) {
    $node = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $n } | Select-Object -First 1
    if ($node -and $node.'#text') { return "$($node.'#text')".Trim() }
  }
  return $null
}

function Escape-CsvField {
  param([string]$s)
  if (-not $s) { return "" }
  return ($s -replace "`r", " " -replace "`n", " " -replace "\s+", " ").Trim()
}

function Collect-Log {
  param([string]$LogName, [string]$Tag)

  try {
    $events = Get-WinEvent -FilterHashtable @{
      LogName = $LogName; StartTime = $since
    } -MaxEvents $MaxEvents -ErrorAction Stop
  } catch {
    $msg = $_.Exception.Message.Split([Environment]::NewLine)[0]
    $script:notes += "$LogName : TIDAK TERBACA ($msg)"
    return
  }

  $count = 0
  $userId = 0
  foreach ($e in $events) {
    # --- Pecah XML event menjadi field terstruktur ---
    $xml = $null
    try { $xml = [xml]$e.ToXml() } catch { $xml = $null }

    $rec = [ordered]@{}
    $rec["@timestamp"] = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $rec["host"]       = $hostName
    $rec["source"]     = $Tag
    $rec["channel"]    = $LogName
    $rec["event_id"]   = [int]$e.Id
    $rec["event_type"] = if ($TypeMap.ContainsKey([int]$e.Id)) { $TypeMap[[int]$e.Id] } else { "generic" }

    if ($e.LevelDisplayName) {
      $rec["severity"] = $e.LevelDisplayName.ToString().ToLower()
    }

    # Terapkan pemetaan field dari struktur XML EventData bila tersedia.
    if ($xml) {
      foreach ($winName in $FieldMap.Keys) {
        $target = $FieldMap[$winName]
        if ($rec.Contains($target)) { continue }   # field pertama menang
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $winName } | Select-Object -First 1
        if ($node -and $node.'#text') {
          $val = "$($node.'#text')".Trim()
          if ($val -and $val -ne "-") {
            # Bersihkan nilai sampah khas log Windows
            if ($target -eq "process_name" -or $target -eq "parent_process") {
              if ($val -match "^[0-9a-fA-F]{1,8}\$") { continue }   # ini PID, bukan path
              $val = ($val -replace "^(\\\\\?\\|\\Device\\HarddiskVolume\d+)", "")
            }
            if ($target -eq "src_ip" -and $val -eq "::1") { $val = "127.0.0.1" }
            $rec[$target] = $val
          }
        }
      }
    }

    # --- Fallback: ekstrak dari teks pesan ---
    # Banyak channel menaruh EventData di dalam Message yang sudah dirender, dan
    # tidak semua event bisa di-ToXml() oleh user non-admin. Tanpa fallback ini,
    # ribuan event masuk sebagai "generic" tanpa user/proses/IP - persis bug yang
    # membuat rule tidak pernah menyala pada impor nyata.
    $msgRaw = ""
    try { $msgRaw = "$($e.Message)" } catch { $msgRaw = "" }

    if (-not $rec.Contains("user_name")) {
      # Windows messages contain MULTIPLE "Account Name" fields (Subject, New Logon).
      # The Subject is often the machine account (HOST$) or SYSTEM - not the actor.
      # Prefer the section that names the real actor.
      $actor = $null
      if ($msgRaw -match "New Logon:.*?Account Name:\s*([^\s\t]+)") { $actor = $Matches[1] }
      elseif ($msgRaw -match "Target User Name:\s*([^\s\t]+)") { $actor = $Matches[1] }
      elseif ($msgRaw -match "Account Whose Credentials Were Used:.*?Account Name:\s*([^\s\t]+)") { $actor = $Matches[1] }
      elseif ($msgRaw -match "Account Name:\s*([^\s\t]+)") { $actor = $Matches[1] }
      if ($actor) {
        $actor = $actor.Trim()
        # Skip machine accounts and placeholders: they are not a human actor and
        # they made every event collapse onto one meaningless "user" in the graph.
        if ($actor -and $actor -ne "-" -and $actor -notmatch "\$$" -and
            $actor -notin @("SYSTEM","LOCAL SERVICE","NETWORK SERVICE","ANONYMOUS LOGON")) {
          $rec["user_name"] = $actor
        }
      }
    }
    if (-not $rec.Contains("process_name")) {
      foreach ($pat in @("New Process Name:\s*([^\r\n\t]+?)(?:\s{2,}|\t|$)",
                         "Process Name:\s*([^\r\n\t]+?)(?:\s{2,}|\t|$)")) {
        $m = [regex]::Match($msgRaw, $pat)
        if ($m.Success) {
          $cand = $m.Groups[1].Value.Trim()
          if (Test-ProcessPath $cand) { $rec["process_name"] = $cand; break }
        }
      }
    }
    if (-not $rec.Contains("parent_process")) {
      $m = [regex]::Match($msgRaw, "Creator Process Name:\s*([^\r\n\t]+?)(?:\s{2,}|\t|$)")
      if ($m.Success) {
        $cand = $m.Groups[1].Value.Trim()
        if (Test-ProcessPath $cand) { $rec["parent_process"] = $cand }
      }
    }
    if (-not $rec.Contains("dst_ip")) {
      # 5156/5157 memakai "Destination Address" / "Source Address"
      if ($msgRaw -match "Destination Address:\s*([0-9a-fA-F\.:]+)") {
        $rec["dst_ip"] = $Matches[1].Trim()
      }
      elseif ($msgRaw -match "Source Address:\s*([0-9a-fA-F\.:]+)") {
        $rec["src_ip"] = $Matches[1].Trim()
      }
    }
    if (-not $rec.Contains("dst_port") -and $msgRaw -match "Destination Port:\s*(\d+)") {
      $rec["dst_port"] = $Matches[1]
    }
    if (-not $rec.Contains("file_path") -and $msgRaw -match "Object Name:\s*([^\r\n\t]+?)(?:\s{2,}|\t|$)") {
      $rec["file_path"] = $Matches[1].Trim()
    }

    # Pesan tetap disimpan untuk analis
    $msg = Escape-CsvField $msgRaw
    if ($msg.Length -gt 600) { $msg = $msg.Substring(0, 600) + " …" }
    $rec["message"]  = $msg
    $rec["provider"] = "$($e.ProviderName)"

    if (-not $rec.Contains("host")) { $rec["host"] = $hostName }

    $script:collected += $rec
    $count++
    $userId++
    if ($userId -gt $MaxEvents) { break }
  }
  $script:notes += "$LogName : $count event"
}

$targets = @()
switch ($Preset) {
  "security"    { $targets += @{ Log="Security"; Tag="windows_security" } }
  "connections" { $targets += @{ Log="Security"; Tag="windows_security" } }   # 5156/5157 ada di Security
  "firewall"    { $targets += @{ Log="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; Tag="firewall" } }
  "sysmon"      { $targets += @{ Log="Microsoft-Windows-Sysmon/Operational"; Tag="edr" } }
  "powershell"  { $targets += @{ Log="Microsoft-Windows-PowerShell/Operational"; Tag="syslog" } }
  "system"      { $targets += @{ Log="System"; Tag="syslog" } }
  "all"         {
    $targets += @{ Log="Security"; Tag="windows_security" }
    $targets += @{ Log="System"; Tag="syslog" }
    $targets += @{ Log="Microsoft-Windows-PowerShell/Operational"; Tag="syslog" }
    $targets += @{ Log="Microsoft-Windows-Sysmon/Operational"; Tag="edr" }
    $targets += @{ Log="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; Tag="firewall" }
  }
}

foreach ($t in $targets) { Collect-Log -LogName $t.Log -Tag $t.Tag }

if ($collected.Count -eq 0) {
  Write-Host "Tidak ada event yang bisa dibaca." -ForegroundColor Yellow
  $notes | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
  Write-Host ""

  # Bedakan "belum terpasang" dari "ada tapi tidak boleh dibaca".
  # Pesan generic sebelumnya menyalahkan pemasangan padahal masalahnya UAC.
  $isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

  $sysmonSvc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
  $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue

  switch ($Preset) {
    "sysmon" {
      if ($sysmonSvc -and $sysmonSvc.Status -eq "Running" -and -not $isAdmin) {
        Write-Host "Sysmon SUDAH terpasang dan berjalan ($($sysmonSvc.Name))." -ForegroundColor Green
        Write-Host "Masalahnya hak akses: log Sysmon hanya bisa dibaca Administrator." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Solusi - buka PowerShell sebagai Administrator, lalu jalankan:" -ForegroundColor Cyan
        Write-Host "  cd <folder-sentinelgraph-ai>"
        Write-Host "  .\tools\export-windows-logs.ps1 -Preset sysmon -Hours 24 -Out sysmon.json"
      }
      elseif (-not $sysmonSvc) {
        Write-Host "Sysmon belum terpasang di mesin ini." -ForegroundColor Yellow
        Write-Host "Pasang dulu lewat:  <folder-sysmon-install>\PASANG-SYSMON.bat" -ForegroundColor Yellow
      }
      else {
        Write-Host "Sysmon terpasang, tapi tidak ada event dalam $Hours jam terakhir." -ForegroundColor Yellow
        Write-Host "Perbesar jendela waktu, mis. -Hours 72" -ForegroundColor Yellow
      }
    }
    "security" {
      if ($isAdmin) {
        Write-Host "Sudah Administrator, tapi tidak ada event Security dalam $Hours jam terakhir." -ForegroundColor Yellow
        Write-Host "Perbesar jendela waktu, mis. -Hours 72" -ForegroundColor Yellow
      } else {
        Write-Host "Log 'Security' memerlukan PowerShell sebagai Administrator." -ForegroundColor Yellow
        Write-Host "Buka PowerShell dengan 'Run as administrator', lalu ulangi." -ForegroundColor Yellow
        Write-Host "Alternatif tanpa admin: -Preset powershell  atau  -Preset system" -ForegroundColor Yellow
      }
    }
    default {
      Write-Host "Tidak ada event pada channel yang diminta untuk $Hours jam terakhir." -ForegroundColor Yellow
      Write-Host "Coba perbesar jendela waktu, mis. -Hours 72" -ForegroundColor Yellow
    }
  }
  exit 2
}

# Ringkasan bagus untuk dilihat sebelum impor.
# Catatan: Group-Object tidak membaca properti OrderedDictionary dengan benar
# (Name selalu kosong), jadi dihitung manual.
$typeCounts = @{}
foreach ($r in $collected) {
  $t = "$($r["event_type"])"
  if (-not $t) { $t = "generic" }
  $typeCounts[$t] = 1 + $(if ($typeCounts.ContainsKey($t)) { $typeCounts[$t] } else { 0 })
}
$withUser = @($collected | Where-Object { $_["user_name"] }).Count
$withProc = @($collected | Where-Object { $_["process_name"] }).Count
$withIp   = @($collected | Where-Object { $_["dst_ip"] -or $_["src_ip"] }).Count

$json = $collected | ConvertTo-Json -Depth 5

# Join-Path merusak path absolut ($Out bisa dikirim absolut, mis. dari EKSPOR-SYSMON.bat).
# Selalu tulis ke path absolut supaya tidak bergantung pada current directory.
$outPath = if ([System.IO.Path]::IsPathRooted($Out)) { $Out }
           else { Join-Path (Get-Location).Path $Out }
$outDir = Split-Path -Parent $outPath
if ($outDir -and -not (Test-Path $outDir)) {
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}
[System.IO.File]::WriteAllText($outPath, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "Selesai: $($collected.Count) event -> $outPath" -ForegroundColor Green
Write-Host ""
Write-Host "Field terstruktur yang berhasil diisi:" -ForegroundColor Cyan
Write-Host "  user_name    : $withUser"
Write-Host "  process_name : $withProc"
Write-Host "  ip (src/dst) : $withIp"
Write-Host ""
Write-Host "Sebaran tipe event:" -ForegroundColor Cyan
$typeCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
  Write-Host ("  {0,-18} {1}" -f $_.Key, $_.Value)
}
Write-Host ""
$notes | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }

if ($withUser -eq 0 -and $withProc -eq 0 -and $withIp -eq 0) {
  Write-Host ""
  Write-Host "PERINGATAN: tidak ada field terstruktur yang terisi." -ForegroundColor Yellow
  Write-Host "Rule berbasis pengguna/proses/IP tidak akan menyala. Untuk telemetry" -ForegroundColor Yellow
  Write-Host "proses dan jaringan yang lengkap, pasang Sysmon lalu pakai -Preset sysmon." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Impor di SentinelGraph: halaman Import -> pilih $outPath -> Import." -ForegroundColor Cyan
