@echo off
setlocal
title Global Ghost Net - VPN loopback self-test
cd /d "%~dp0"

echo ======================================================================
echo           GLOBAL GHOST NET - VPN LOOPBACK SELF-TEST
echo ======================================================================
echo.
echo Runs a REAL two-process tunnel round trip over real UDP sockets, with the
echo client on the in-memory TUN: no wintun.dll, no Administrator, no OS
echo interface and no traffic leaving this machine.
echo.
echo The test is a bash script (scripts\vpn_loopback_test.sh).
echo.
echo Windows note: in PowerShell/cmd the NAME "bash" usually resolves to the
echo WSL shim (C:\Windows\System32\bash.exe). Without an installed WSL
echo distribution that fails with "Windows-Subsystem fuer Linux verfuegt
echo ueber keine installierten Distributionen". This wrapper therefore looks
echo for Git Bash explicitly and never invokes "bash" from PATH.
echo.

set "SH="
call :try "%LOCALAPPDATA%\Programs\Git\bin\bash.exe"
call :try "%LOCALAPPDATA%\Programs\Git\usr\bin\bash.exe"
call :try "%ProgramFiles%\Git\bin\bash.exe"
call :try "%ProgramFiles%\Git\usr\bin\bash.exe"
call :try "%ProgramFiles(x86)%\Git\bin\bash.exe"

if not defined SH (
    echo [!] Git Bash not found.
    echo.
    echo     Install "Git for Windows" ^(https://git-scm.com/download/win^) and
    echo     re-run this file. Do NOT fall back to the "bash" on PATH - on this
    echo     machine that is the WSL shim, which needs a WSL distribution.
    echo.
    pause
    exit /b 1
)

echo [*] Using: %SH%
echo.
"%SH%" scripts/vpn_loopback_test.sh
set RC=%ERRORLEVEL%
echo.
if "%RC%"=="0" (
    echo [+] VPN loopback self-test PASSED
) else (
    echo [!] VPN loopback self-test FAILED ^(exit %RC%^) - see the output above
)
pause
exit /b %RC%

:try
if defined SH exit /b 0
if exist %1 set "SH=%~1"
exit /b 0
