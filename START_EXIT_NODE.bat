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

set GHOST_NO_GUI=1
set GHOST_EXIT=1
set GHOST_VPN=hub
set GHOST_VPN_DNS=1.1.1.1

if exist "target\release\ggn.exe" (
    target\release\ggn.exe --exit
) else if exist "target\debug\ggn.exe" (
    target\debug\ggn.exe --exit
) else (
    echo [ERROR] Neither target\release\ggn.exe nor target\debug\ggn.exe found.
    echo Please run "cargo build --bin ggn" first.
    pause
)
pause
