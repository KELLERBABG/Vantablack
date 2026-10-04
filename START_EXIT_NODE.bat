@echo off
title Vantablack Exit Node
cd /d "%~dp0"
cls
echo ======================================================================
echo           VANTABLACK - Post-Quantum WAN Mesh Exit Node
echo ======================================================================
echo.
echo   Local Gateway Address: 192.168.178.27:55225
echo   Privacy DNS:           1.1.1.1 (Cloudflare Clean / Zero Leak)
echo   Clients Allowed:       All paired mesh devices
echo.
echo ======================================================================
echo   Starting daemon... Press Ctrl+C to stop.
echo ======================================================================
echo.

set GHOST_EXE=
if exist "target\release\ggn.exe" set GHOST_EXE=target\release\ggn.exe
if exist "target\debug\ggn.exe" if "%GHOST_EXE%"=="" set GHOST_EXE=target\debug\ggn.exe

if "%GHOST_EXE%"=="" (
    echo [ERROR] Neither target\release\ggn.exe nor target\debug\ggn.exe found.
    echo Please run "cargo build --bin ggn" first.
    pause
    exit /b 1
)

:: Stop any running instance first to release port
taskkill /F /IM ggn.exe >nul 2>&1
timeout /t 1 /nobreak >nul

:: Set daemon exit node configuration
set GHOST_NO_GUI=1
set GHOST_EXIT=1
set GHOST_VPN=hub
set GHOST_VPN_DNS=1.1.1.1

:: Start daemon in background
start "" /B "%GHOST_EXE%" --exit

echo Daemon started! Live event stream:
echo ----------------------------------------------------------------------
powershell -NoProfile -Command "$log = \"$env:APPDATA\GlobalGhostNet\ghost.log\"; while (-not (Test-Path $log)) { Start-Sleep -Milliseconds 100 }; Get-Content -Path $log -Tail 15 -Wait"
pause
