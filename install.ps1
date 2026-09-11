Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "   GLOBAL GHOST NET // Automated Node Installer   " -ForegroundColor White
Write-Host "=================================================" -ForegroundColor Cyan

$destDir = "$HOME\.ggn"
if (!(Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

Write-Host "[*] Checking Rust toolchain..." -ForegroundColor Yellow
if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Cargo/Rust is not installed on this system." -ForegroundColor Red
    Write-Host "[*] Install Rust from: https://rustup.rs" -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Cloning Global Ghost Net repository..." -ForegroundColor Yellow
$repoDir = "$destDir\Global-Ghost-Net"
if (Test-Path $repoDir) {
    git -C $repoDir pull origin main
} else {
    git clone https://github.com/KELLERBABG/Global-Ghost-Net.git $repoDir
}

Write-Host "[*] Compiling high-performance GGN release binary..." -ForegroundColor Yellow
cargo build --release --manifest-path "$repoDir\Cargo.toml"

Write-Host "`n[+] Build complete!" -ForegroundColor Green
Write-Host "[+] Local SOCKS5 proxy daemon ready." -ForegroundColor Cyan
Write-Host "To launch, run: $repoDir\run-client.bat" -ForegroundColor White