@echo off
title Global Ghost Net - VPN loopback self-test
cd /d "%~dp0"

echo ======================================================================
echo           GLOBAL GHOST NET - VPN LOOPBACK SELF-TEST
echo ======================================================================
echo.
echo Runs a REAL two-process tunnel round trip over real UDP sockets with
echo the client on the in-memory TUN: no wintun.dll, no Administrator, no
echo OS interface and no traffic leaving this machine.
echo.
echo The test itself is a bash script (scripts\vpn_loopback_test.sh).
echo PowerShell will NOT run a .sh file directly - it returns silently with
echo no output. This wrapper locates bash and runs it for you.
echo.

set "SH="
where bash >nul 2>&1 && set "SH=bash"
if not defined SH if exist "%ProgramFiles%\Git\bin\bash.exe" set "SH=%ProgramFiles%\Git\bin\bash.exe"
if not defined SH if exist "%ProgramFiles(x86)%\Git\bin\bash.exe" set "SH=%ProgramFiles(x86)%\Git\bin\bash.exe"
if not defined SH if exist "%LOCALAPPDATA%\Programs\Git\bin\bash.exe" set "SH=%LOCALAPPDATA%\Programs\Git\bin\bash.exe"

if not defined SH (
    echo [!] bash not found. Install Git for Windows ^(https://git-scm.com^), then
    echo     re-run this file, or run the test from Git Bash / WSL directly:
    echo.
    echo         bash scripts/vpn_loopback_test.sh
    echo.
    pause
    exit /b 1
)

"%SH%" scripts/vpn_loopback_test.sh
set RC=%ERRORLEVEL%

echo.
if "%RC%"=="0" (
    echo [+] VPN loopback self-test PASSED
) else (
    echo [!] VPN loopback self-test FAILED ^(exit %RC%^) - see the log above
)
pause
exit /b %RC%
