[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$TargetDir = "C:\build\vb-check",
    [string]$SdkLibDir = "",
    [string]$SdkIncludeDir = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArgs = @("check", "--all-targets", "--message-format", "short")
)

$ErrorActionPreference = "Stop"

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
$vcvars = $null
if (Test-Path $vswhere) {
    $vsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
    if (-not $vsRoot) {
        $vsRoot = & $vswhere -all -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
    }
    if ($vsRoot) {
        $candidate = Join-Path $vsRoot "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $candidate) { $vcvars = $candidate }
    }
}
if (-not $vcvars) { throw "no Visual Studio x64 build environment found (vcvars64.bat)" }

# A machine can have the C++ workload without the Windows SDK component, which
# surfaces as `LNK1181: cannot open input file 'kernel32.lib'` minutes into the
# build and reads like a project defect. Both halves of the SDK are on NuGet:
# Microsoft.Windows.SDK.CPP.x64 carries the libraries and Microsoft.Windows.SDK.CPP
# the headers, so a machine can be made to build without the installer.
#
# vcvars writes INCLUDE and LIB into its cmd session. They are imported into this
# process rather than extended inside a cmd chain: a chained `set "LIB=%LIB%;..."`
# expands before vcvars runs and silently discards what vcvars installed, and the
# delayed form that avoids that still left the C compiler without stddef.h.
$vcvarsEnv = & cmd.exe /V:ON /c "call `"$vcvars`" >nul 2>&1 && set"
$envLines = @{}
foreach ($line in $vcvarsEnv) {
    if ($line -match '^([A-Za-z_][A-Za-z0-9_()]*)=(.*)$') { $envLines[$Matches[1]] = $Matches[2] }
}
foreach ($name in @('INCLUDE', 'LIB', 'LIBPATH', 'PATH', 'VCINSTALLDIR', 'VCToolsInstallDir', 'WindowsSdkDir', 'WindowsSDKVersion', 'UCRTVersion', 'UniversalCRTSdkDir')) {
    if ($envLines.ContainsKey($name)) { Set-Item -Path "env:$name" -Value $envLines[$name] }
}

$libDirs = @($env:LIB -split ';' | Where-Object { $_ })
if ($SdkLibDir) {
    foreach ($sub in @("c\um\x64", "c\ucrt\x64")) {
        $p = Join-Path $SdkLibDir $sub
        if (Test-Path $p) { $libDirs += $p }
    }
}
if (-not ($libDirs | Where-Object { Test-Path (Join-Path $_ 'kernel32.lib') })) {
    throw "the Windows SDK import libraries are missing: no kernel32.lib on LIB. Add the 'Windows 11 SDK' component in the Visual Studio Installer, pass -SdkLibDir pointing at an extracted Microsoft.Windows.SDK.CPP.x64 package, or build in Linux/WSL instead (scripts/build-gate.sh)."
}
$env:LIB = ($libDirs -join ';')

if ($SdkIncludeDir) {
    $incDirs = @($env:INCLUDE -split ';' | Where-Object { $_ })
    $versioned = Get-ChildItem $SdkIncludeDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($versioned) {
        foreach ($sub in @("ucrt", "um", "shared", "winrt")) {
            $p = Join-Path $versioned.FullName $sub
            if (Test-Path $p) { $incDirs += $p }
        }
    }
    if (-not ($incDirs | Where-Object { $_ -and (Test-Path (Join-Path $_ 'stddef.h')) })) {
        throw "the Windows SDK C headers are missing: no stddef.h on INCLUDE. Pass -SdkIncludeDir pointing at an extracted Microsoft.Windows.SDK.CPP package, or install the SDK component."
    }
    $env:INCLUDE = ($incDirs -join ';')
}

# The MSVC toolchain cannot link without this environment; the gnu default
# cannot compile ring's C. Both failures look like project errors and are not.
$env:CARGO_TARGET_DIR = $TargetDir
& cargo @CargoArgs
exit $LASTEXITCODE
