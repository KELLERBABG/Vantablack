# Vantablack — automated node installer (Windows PowerShell).
#
# Served at the site root as advertised by the landing page:
#   irm https://ggn.kellersystems.dev/install.ps1 | iex
#
# The daemon takes NO command-line arguments: it is configured entirely through
# environment variables (see config.env.example).

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "   VANTABLACK // Automated Node Installer   " -ForegroundColor White
Write-Host "=================================================" -ForegroundColor Cyan

$destDir = "$HOME\.ggn"
if (!(Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

Write-Host "[*] Checking Rust toolchain..." -ForegroundColor Yellow
if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Cargo/Rust is not installed on this system." -ForegroundColor Red
    Write-Host "[*] Install Rust from: https://rustup.rs" -ForegroundColor Yellow
    exit 1
}

if (!(Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "[!] git is not installed on this system." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Cloning Vantablack repository..." -ForegroundColor Yellow
$repoDir = "$destDir\Global-Ghost-Net"
if (Test-Path $repoDir) {
    git -C $repoDir pull --ff-only origin main
} else {
    git clone https://github.com/KELLERBABG/Global-Ghost-Net.git $repoDir
}

Write-Host "[*] Compiling the desktop application (native window + tray icon)..." -ForegroundColor Yellow
cargo build --release --manifest-path "$repoDir\Cargo.toml"

$bin = "$repoDir\target\release\ggn.exe"
Write-Host "`n[+] Build complete: $bin" -ForegroundColor Green
Write-Host "[+] The program takes no command-line arguments. Configure it with env vars:" -ForegroundColor Cyan
Write-Host ""
Write-Host "    # Desktop app: opens its own window; closing it hides to the tray." -ForegroundColor White
Write-Host "    # The control center also answers at http://127.0.0.1:2270 and the log" -ForegroundColor White
Write-Host "    # is mirrored to ghost.log next to the executable." -ForegroundColor White
Write-Host "    & '$bin'" -ForegroundColor White
Write-Host ""
Write-Host "    # Server / headless node, no window (control center in a browser tab)" -ForegroundColor White
Write-Host "    `$env:GHOST_NO_GUI='1'; & '$bin'" -ForegroundColor White
Write-Host ""
Write-Host "    # SOCKS5 client node (proxy on 127.0.0.1:1080)" -ForegroundColor White
Write-Host "    `$env:GHOST_SOCKS5='1'; & '$bin'" -ForegroundColor White
Write-Host ""
Write-Host "    # Exit node (peers reach it on 2271 - 2270/UDP is the discovery beacon)" -ForegroundColor White
Write-Host "    `$env:GHOST_EXIT_ALLOWLIST='any'; `$env:GHOST_BIND='0.0.0.0:2271'; & '$bin'" -ForegroundColor White
