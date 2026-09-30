<#
.SYNOPSIS
    Calculates SHA256 of the release installer and updates or submits the Winget manifest.
#>
param(
    [string]$Version = "0.8.0",
    [string]$InstallerUrl,
    [string]$LocalInstallerPath
)

$ErrorActionPreference = 'Stop'

if (-not $InstallerUrl) {
    $InstallerUrl = "https://github.com/KELLERBABG/Vantablack/releases/download/v$Version/ggn-$Version-windows-setup.exe"
}

$tempFile = $null
if ($LocalInstallerPath -and (Test-Path $LocalInstallerPath)) {
    $targetFile = $LocalInstallerPath
} else {
    Write-Host "==> Downloading $InstallerUrl to calculate SHA256..." -ForegroundColor Cyan
    $tempFile = [System.IO.Path]::GetTempFileName() + ".exe"
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $tempFile
    $targetFile = $tempFile
}

$sha256 = (Get-FileHash -Path $targetFile -Algorithm SHA256).Hash.ToUpper()
Write-Host "==> SHA256: $sha256" -ForegroundColor Green

if ($tempFile -and (Test-Path $tempFile)) {
    Remove-Item -Force $tempFile
}

$installerManifest = "$PSScriptRoot/manifests/k/KellerSystems/Vantablack/$Version/KellerSystems.Vantablack.installer.yaml"
if (Test-Path $installerManifest) {
    (Get-Content $installerManifest) -replace 'InstallerSha256: .*', "InstallerSha256: $sha256" | Set-Content $installerManifest
    Write-Host "==> Updated $installerManifest with verified SHA256!" -ForegroundColor Green
}

Write-Host ""
Write-Host "To submit to Microsoft winget-pkgs repository:" -ForegroundColor Yellow
Write-Host "1. Install wingetcreate: winget install Microsoft.WingetCreate"
Write-Host "2. Submit: wingetcreate submit $PSScriptRoot/manifests/k/KellerSystems/Vantablack/$Version"
