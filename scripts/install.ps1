# Vantablack — automated node installer (Windows PowerShell).
#
# Served at the site root as advertised by the landing page:
#   irm https://vantablack.kellersystems.dev/install.ps1 | iex
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
    git clone https://github.com/KELLERBABG/Vantablack.git $repoDir
}

Write-Host "[*] Compiling the desktop application (native window + tray icon)..." -ForegroundColor Yellow
cargo build --release --manifest-path "$repoDir\Cargo.toml"

$bin = "$repoDir\target\release\ggn.exe"
Write-Host "`n[+] Build complete: $bin" -ForegroundColor Green
Write-Host "[+] Quick Launch Options:" -ForegroundColor Cyan
Write-Host ""
Write-Host "    # Desktop app: opens native window (tray icon, control center on :2270)" -ForegroundColor White
Write-Host "    & '$bin'" -ForegroundColor White
Write-Host ""
Write-Host "    # Low-Latency Mode (1ms micro-jitter for gaming/VoIP)" -ForegroundColor White
Write-Host "    & '$bin' --low-latency" -ForegroundColor White
Write-Host ""
Write-Host "    # Zero-Admin Mode (Userspace SOCKS5 on :1080 & DNS on :1053, no elevation)" -ForegroundColor White
Write-Host "    & '$bin' --zero-admin" -ForegroundColor White
Write-Host ""
Write-Host "    # Server / headless node (no window, web dashboard on http://127.0.0.1:2270)" -ForegroundColor White
Write-Host "    `$env:GHOST_NO_GUI='1'; & '$bin'" -ForegroundColor White
Write-Host ""
Write-Host "    # CLI Help & Shamir Secret Sharing Tools" -ForegroundColor White
Write-Host "    & '$bin' --help" -ForegroundColor White
