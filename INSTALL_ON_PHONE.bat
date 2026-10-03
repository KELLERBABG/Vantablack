@echo off
title Vantablack - Install to Android Phone
cd /d "%~dp0"
cls
echo ======================================================================
echo           VANTABLACK - Automated Phone Setup & Install
echo ======================================================================
echo.
echo   1. Plug your phone into this PC via USB cable.
echo   2. Ensure USB debugging is enabled on your phone.
echo.
echo Waiting for device...
adb wait-for-device
echo [OK] Device detected!
echo.

set APK_FILE=
if exist "vantablack-latest.apk" set APK_FILE=vantablack-latest.apk
if exist "android\app\build\outputs\apk\debug\app-debug.apk" set APK_FILE=android\app\build\outputs\apk\debug\app-debug.apk

if "%APK_FILE%"=="" (
    echo Fetching latest APK from GitHub Releases...
    powershell -NoProfile -Command ^
        "$tag = (Invoke-RestMethod -Uri 'https://api.github.com/repos/KELLERBABG/Vantablack/releases/latest').tag_name; ^
         $asset = (Invoke-RestMethod -Uri 'https://api.github.com/repos/KELLERBABG/Vantablack/releases/latest').assets | Where-Object { $_.name -like '*android.apk' } | Select-Object -First 1; ^
         if ($asset) { ^
             Write-Host 'Downloading ' $asset.name ' (' $tag ')...'; ^
             Invoke-WebRequest -Uri $asset.browser_download_url -OutFile 'vantablack-latest.apk'; ^
             Write-Host '[OK] Download complete!'; ^
         } else { ^
             Write-Host '[WARN] No APK asset found in latest release.'; ^
         }"
    if exist "vantablack-latest.apk" set APK_FILE=vantablack-latest.apk
)

if "%APK_FILE%"=="" (
    echo [ERROR] No APK found to install.
    echo Please make sure the GitHub release build has completed or place vantablack-latest.apk in this folder.
    pause
    exit /b 1
)

echo.
echo Installing %APK_FILE% to phone...
adb install -r "%APK_FILE%"
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] adb install failed. If prompted on your phone, tap "Allow from this computer".
    pause
    exit /b 1
)

echo.
echo Launching Vantablack on phone...
adb shell am start -n dev.globalghost.net/.MainActivity

echo.
echo ======================================================================
echo   [SUCCESS] Vantablack is installed and opened on your phone!
echo.
echo   The Gateway is already pre-filled: 192.168.178.27:55225
echo   Just tap "CONNECT" on the phone screen!
echo ======================================================================
echo.
pause
