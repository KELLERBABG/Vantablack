@echo off
title Global Ghost Net - VPN Client (Elevated Wintun)
cd /d "%~dp0"

echo ======================================================================
echo           GLOBAL GHOST NET (VANTABLACK) - VPN CLIENT
echo ======================================================================
echo Starting LAN-over-WAN road-warrior client node...
echo.

:: Check for Administrator elevation
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Administrator privileges not detected!
    echo Creating the Wintun adapter requires running as Administrator.
    echo Please right-click this batch file and select "Run as administrator".
    echo.
)

:: Check for wintun.dll
if not exist "wintun.dll" if not exist "target\release\wintun.dll" (
    if exist "C:\Program Files\Tailscale\wintun.dll" (
        echo Found wintun.dll in Tailscale directory. Copying to working directory for dev use...
        copy "C:\Program Files\Tailscale\wintun.dll" "wintun.dll" >nul
    ) else (
        echo [!] wintun.dll not found in current directory, target\release, or Tailscale!
        echo Download wintun.dll from https://www.wintun.net and place it in this folder.
    )
)

:: Load configuration from config.env if present
if exist "config.env" (
    for /f "usebackq tokens=1,* delims==" %%A in ("config.env") do (
        set line=%%A
        if not "!line:~0,1!"=="#" (
            set "%%A=%%B"
        )
    )
)

:: Ensure VPN Client mode is set
set GHOST_VPN=client
if "%GHOST_BIND%"=="" set GHOST_BIND=0.0.0.0:0
if "%RUST_LOG%"=="" set RUST_LOG=info

if "%GHOST_VPN_HUB_FP%"=="" (
    echo.
    echo [!] GHOST_VPN_HUB_FP is not set!
    echo Please set GHOST_VPN_HUB_FP in config.env or pass it as an environment variable.
    echo Example: set GHOST_VPN_HUB_FP=d6c83ed79eb7fc7f
    echo.
    set /p GHOST_VPN_HUB_FP="Enter Hub Fingerprint: "
)

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

echo Starting VPN Client connecting to Hub %GHOST_VPN_HUB_FP%...
echo.

target\release\vantablack.exe
pause
