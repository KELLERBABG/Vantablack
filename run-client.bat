@echo off
title Vantablack - Client Node
cd /d "%~dp0"

echo ======================================================================
echo           VANTABLACK (VANTABLACK) - CLIENT NODE
echo ======================================================================
echo Starting node with zero-mock peer mesh discovery...
echo SOCKS5 Proxy will listen on 127.0.0.1:1080
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

:: Set default fallback environment variables
if "%GHOST_LISTEN_PORT%"=="" set GHOST_LISTEN_PORT=2270
if "%GHOST_SOCKS5_PORT%"=="" set GHOST_SOCKS5_PORT=1080
if "%RUST_LOG%"=="" set RUST_LOG=info

target\release\vantablack.exe
pause
