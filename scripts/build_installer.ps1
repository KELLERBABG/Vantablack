<#
.SYNOPSIS
    Builds the Vantablack Windows installer (ggn-<version>-windows-setup.exe).

.DESCRIPTION
    Stages the release payload into dist\staging, then compiles installer\ggn.iss
    with Inno Setup. The version comes from the compiled binary's version
    resource, so the installer, the executable and Add/Remove Programs can never
    disagree - provided assets\app.rc matches Cargo.toml, which a unit test
    (ghost::icon::version_resource_is_readable_by_the_shell) enforces.

    ASCII only on purpose: Windows PowerShell 5.1 reads .ps1 files as ANSI unless
    they carry a UTF-8 BOM, so a stray em-dash in a comment breaks the parser.

.PARAMETER BinDir
    Directory holding ggn.exe. Defaults to target\release; pass an explicit
    target triple's output directory when cross-building, for example
    target\x86_64-pc-windows-msvc\release.

.PARAMETER SkipBuild
    Do not run cargo; fail if the binary is missing instead.

.PARAMETER Version
    Override the version (useful when the binary predates a version bump).

.PARAMETER WintunVersion
    Official Wintun release to download when no local DLL is supplied (default 0.14.1).

.PARAMETER WintunPath
    Explicit path to an operator-reviewed official wintun.dll.

.EXAMPLE
    powershell -File scripts/build_installer.ps1
    powershell -File scripts/build_installer.ps1 -BinDir target\x86_64-pc-windows-msvc\release
#>
[CmdletBinding()]
param(
    [string]$BinDir = 'target\release',
    [switch]$SkipBuild,
    [string]$Version,
    [string]$WintunVersion = '0.14.1',
    [string]$WintunPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$IssFile  = Join-Path $RepoRoot 'installer\ggn.iss'
$StageDir = Join-Path $RepoRoot 'dist\staging'
$OutDir   = Join-Path $RepoRoot 'dist'

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Find-Iscc {
    $cmd = Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    # Inno Setup installs per user by default when installed without admin.
    $roots = @(
        @{ Base = $env:LOCALAPPDATA; Sub = 'Programs\Inno Setup 6\ISCC.exe' },
        @{ Base = ${env:ProgramFiles(x86)}; Sub = 'Inno Setup 6\ISCC.exe' },
        @{ Base = $env:ProgramFiles; Sub = 'Inno Setup 6\ISCC.exe' }
    )
    foreach ($root in $roots) {
        if ([string]::IsNullOrEmpty($root.Base)) { continue }
        $candidate = Join-Path $root.Base $root.Sub
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }

    throw ('Inno Setup 6 was not found.' + [Environment]::NewLine +
           'Install it with:  winget install JRSoftware.InnoSetup' + [Environment]::NewLine +
           'or download it from https://jrsoftware.org/isdl.php')
}

# Normalise anything version-shaped ("0.4.1", "0.4.1.0", "0.4.1-beta") into a
# three-part display version and a four-part file version.
function ConvertTo-VersionPair([string]$Raw) {
    $parts = @($Raw -split '[.\-+]' | Where-Object { $_ -match '^\d+$' } | Select-Object -First 4)
    if ($parts.Count -eq 0) { throw "Unusable version string: '$Raw'" }

    $three = @($parts)
    while ($three.Count -lt 3) { $three += '0' }
    $three = @($three[0], $three[1], $three[2])

    $quad = @($three[0], $three[1], $three[2], '0')
    if ($parts.Count -ge 4) { $quad[3] = $parts[3] }

    return [pscustomobject]@{
        Short = ($three -join '.')
        Quad  = ($quad -join '.')
    }
}

function Resolve-AppVersion([string]$ExePath, [string]$CargoToml) {
    $raw = $null
    if (Test-Path -LiteralPath $ExePath) {
        $raw = (Get-Item -LiteralPath $ExePath).VersionInfo.ProductVersion
    }
    if ([string]::IsNullOrWhiteSpace($raw) -and (Test-Path -LiteralPath $CargoToml)) {
        Write-Host '    (binary carries no readable version resource; reading Cargo.toml)' -ForegroundColor DarkYellow
        $match = Select-String -Path $CargoToml -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($match) { $raw = $match.Matches[0].Groups[1].Value }
    }
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Could not determine a version from $ExePath or Cargo.toml."
    }
    return ConvertTo-VersionPair $raw
}

if (-not (Test-Path -LiteralPath $IssFile)) { throw "Missing installer script: $IssFile" }

# -- 1. The application binary -----------------------------------------------
$ExePath = Join-Path $RepoRoot (Join-Path $BinDir 'ggn.exe')

if (-not (Test-Path -LiteralPath $ExePath)) {
    if ($SkipBuild) { throw "-SkipBuild was given but $ExePath does not exist." }
    Write-Step 'Building the release application (cargo build --release --bin ggn)'
    Push-Location $RepoRoot
    try {
        & cargo build --release --bin ggn
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path -LiteralPath $ExePath)) { throw "Expected binary not found: $ExePath" }

# -- 2. Version --------------------------------------------------------------
$resolved = if ($Version) { ConvertTo-VersionPair $Version }
            else { Resolve-AppVersion -ExePath $ExePath -CargoToml (Join-Path $RepoRoot 'Cargo.toml') }
Write-Step "Version $($resolved.Short) (file version $($resolved.Quad))"

# -- 3. Stage exactly what gets installed ------------------------------------
Write-Step 'Staging the payload into dist\staging'
if (Test-Path -LiteralPath $StageDir) { Remove-Item -LiteralPath $StageDir -Recurse -Force }
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

# The installer must ship the official WireGuard Wintun release, never a
# redistributor's copy. Download only when the operator did not provide a
# verified local DLL; the archive layout is checked before it enters staging.
$wintunDestination = Join-Path $RepoRoot 'dist\wintun.dll'
if ([string]::IsNullOrWhiteSpace($WintunPath)) {
    $WintunPath = Join-Path $RepoRoot 'wintun.dll'
}
if (-not (Test-Path -LiteralPath $WintunPath)) {
    $zip = Join-Path $RepoRoot ("dist\wintun-$WintunVersion.zip")
    New-Item -ItemType Directory -Path (Split-Path -Parent $zip) -Force | Out-Null
    $url = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"
    Write-Step "Downloading official Wintun $WintunVersion"
    try {
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    } catch {
        $fallbackUrl = "https://www.wintun.net/downloads/wintun-$WintunVersion.zip"
        Invoke-WebRequest -Uri $fallbackUrl -OutFile $zip -UseBasicParsing
    }
    $extract = Join-Path $RepoRoot 'dist\wintun-extract'
    if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
    Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
    $dll = Get-ChildItem -LiteralPath $extract -Recurse -Filter 'wintun.dll' |
        Where-Object { $_.FullName -match '[\\/]amd64[\\/]wintun\.dll$' } |
        Select-Object -First 1
    if (-not $dll) { throw "Official Wintun archive did not contain amd64\wintun.dll" }
    Copy-Item -LiteralPath $dll.FullName -Destination $wintunDestination -Force
    $WintunPath = $wintunDestination
}
if (-not (Test-Path -LiteralPath $WintunPath)) {
    throw "Wintun DLL not found: $WintunPath"
}

# Required first, then the optional extras (shipped when present).
$required = @{ 'ggn.exe' = $ExePath; 'wintun.dll' = $WintunPath }
$optional = @{
    'README.md'  = (Join-Path $RepoRoot 'README.md')
    'LICENSE'    = (Join-Path $RepoRoot 'LICENSE')
}

foreach ($name in $required.Keys) {
    $src = $required[$name]
    if (-not (Test-Path -LiteralPath $src)) { throw "Required file missing: $src" }
    Copy-Item -LiteralPath $src -Destination $StageDir
}
foreach ($name in $optional.Keys) {
    $src = $optional[$name]
    if (Test-Path -LiteralPath $src) {
        Copy-Item -LiteralPath $src -Destination $StageDir
    } else {
        Write-Host "    (skipping optional $name)" -ForegroundColor DarkGray
    }
}

Get-ChildItem -LiteralPath $StageDir | Sort-Object Name | ForEach-Object {
    $kb = [math]::Round($_.Length / 1KB, 1)
    Write-Host ("    {0,-14} {1,10} KB" -f $_.Name, $kb)
}

# -- 4. Compile --------------------------------------------------------------
$iscc = Find-Iscc
Write-Step "Compiling with $iscc"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

& $iscc "/DMyAppVersion=$($resolved.Short)" "/DMyAppVersionQuad=$($resolved.Quad)" $IssFile
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed with exit code $LASTEXITCODE" }

$SetupPath = Join-Path $OutDir "ggn-$($resolved.Short)-windows-setup.exe"
if (-not (Test-Path -LiteralPath $SetupPath)) { throw "Installer was not produced: $SetupPath" }

$info = Get-Item -LiteralPath $SetupPath
Write-Host ''
Write-Host "Installer ready: $($info.FullName)" -ForegroundColor Green
Write-Host ("  size    : {0:N0} bytes" -f $info.Length)
Write-Host "  version : $($info.VersionInfo.ProductVersion)"
Write-Host ''
Write-Host 'Unattended use:' -ForegroundColor DarkGray
Write-Host ("  install  : {0} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -f $info.Name) -ForegroundColor DarkGray
Write-Host '  uninstall: "%LOCALAPPDATA%\Programs\GlobalGhostNet\unins000.exe" /VERYSILENT' -ForegroundColor DarkGray
