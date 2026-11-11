@echo off
REM ============================================================
REM  Ekspor event Sysmon -> sysmon.json untuk SentinelGraph AI
REM
REM  Kenapa perlu Administrator?
REM    Log Microsoft-Windows-Sysmon/Operational hanya bisa dibaca
REM    oleh Administrator. Tanpa hak itu, ekspor akan gagal.
REM
REM  Cara pakai: KLIK DUA KALI file ini, lalu klik "Yes" di UAC.
REM  Hak admin diminta otomatis oleh skrip ini.
REM ============================================================

REM --- Naikkan hak bila belum Administrator ---
net session >nul 2>&1
if errorlevel 1 (
    echo Meminta hak Administrator... klik "Yes" pada jendela UAC.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM --- Sudah Administrator ---
set "PROJ=%~dp0.."
pushd "%PROJ%"
set "PROJ=%CD%"
set "SYSMON=%~dp0..\..\sysmon-install\Sysmon64.exe"
set "LOG=%PROJ%\sysmon-export.log"

echo ============================================================>"%LOG%"
echo  EKSPOR SYSMON - %DATE% %TIME%>>"%LOG%"
echo ============================================================>>"%LOG%"
echo Project : %PROJ%>>"%LOG%"
echo Sysmon  : %SYSMON%>>"%LOG%"
echo.>>"%LOG%"

echo --- CONFIG SYSMON YANG AKTIF --->>"%LOG%"
if exist "%SYSMON%" (
    "%SYSMON%" -c >>"%LOG%" 2>&1
) else (
    echo Sysmon64.exe tidak ditemukan di %SYSMON%>>"%LOG%"
)
echo.>>"%LOG%"

echo --- EKSPOR EVENT (24 jam terakhir) --->>"%LOG%"
if exist "%PROJ%\sysmon.json" del "%PROJ%\sysmon.json"
powershell -NoProfile -ExecutionPolicy Bypass -File "%PROJ%\tools\export-windows-logs.ps1" -Preset sysmon -Hours 24 -Out "%PROJ%\sysmon.json">>"%LOG%" 2>&1

echo.>>"%LOG%"
if exist "%PROJ%\sysmon.json" (
    echo HASIL: sysmon.json BERHASIL dibuat.>>"%LOG%"
) else (
    echo HASIL: sysmon.json GAGAL dibuat. Lihat pesan di atas.>>"%LOG%"
)

type "%LOG%"
echo.
echo ============================================================
echo  Selesai. Jendela ini bisa ditutup.
echo  File log: %LOG%
echo ============================================================
pause
