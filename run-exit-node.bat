@echo off
title Vantablack - Exit Node
cd /d "%~dp0"

echo ======================================================================
echo           VANTABLACK (VANTABLACK) - EXIT NODE
echo ======================================================================
echo Starting high-capacity Exit Node with WAN transit routing enabled...
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

:: Ensure Exit Allowlist is enabled
set GHOST_EXIT_ALLOWLIST=any
if "%GHOST_LISTEN_PORT%"=="" set GHOST_LISTEN_PORT=2270
if "%RUST_LOG%"=="" set RUST_LOG=info

target\release\vantablack.exe
pause
