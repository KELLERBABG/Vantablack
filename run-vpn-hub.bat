@echo off
title Global Ghost Net - VPN Hub
cd /d "%~dp0"

echo ======================================================================
echo           GLOBAL GHOST NET (VANTABLACK) - VPN HUB
echo ======================================================================
echo Starting LAN-over-WAN Hub Node...
echo.

:: Load configuration from config.env if present
if exist "config.env" (
    for /f "usebackq tokens=1,* delims==" %%A in ("config.env") do (
        set line=%%A
        if not "!line:~0,1!"=="#" (
            set "%%A=%%B"
        )
    )
)

:: Ensure VPN Hub mode is set
set GHOST_VPN=hub
if "%GHOST_BIND%"=="" set GHOST_BIND=0.0.0.0:2271
if "%RUST_LOG%"=="" set RUST_LOG=info

:: Ensure the release binary exists
if not exist "target\release\vantablack.exe" (
    echo Binary not found, building target\release\vantablack.exe with --features vpn...
    cargo build --release --features vpn
    if errorlevel 1 (
        echo [!] Build failed.
        pause
        exit /b 1
    )
)

echo Starting Hub on %GHOST_BIND%...
echo Note: Set GHOST_VPN_CLIENTS in config.env to allowlist client fingerprints.
echo.

target\release\vantablack.exe
pause
