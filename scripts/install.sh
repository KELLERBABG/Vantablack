#!/usr/bin/env sh
set -e

echo "\033[1;36m=================================================\033[0m"
echo "\033[1;37m   GLOBAL GHOST NET // Automated Node Installer   \033[0m"
echo "\033[1;36m=================================================\033[0m"

DEST_DIR="$HOME/.ggn"
mkdir -p "$DEST_DIR"

if ! command -v cargo >/dev/null 2>&1; then
    echo "\033[1;31m[!] Rust/Cargo is not installed.\033[0m"
    echo "\033[1;33m[*] Please install Rust from https://rustup.rs and retry.\033[0m"
    exit 1
fi

REPO_DIR="$DEST_DIR/Global-Ghost-Net"
if [ -d "$REPO_DIR" ]; then
    echo "\033[1;33m[*] Updating existing repository...\033[0m"
    git -C "$REPO_DIR" pull origin main
else
    echo "\033[1;33m[*] Cloning Global Ghost Net...\033[0m"
    git clone https://github.com/KELLERBABG/Global-Ghost-Net.git "$REPO_DIR"
fi

echo "\033[1;33m[*] Building release daemon...\033[0m"
cargo build --release --manifest-path "$REPO_DIR/Cargo.toml"

echo "\033[1;32m[+] Global Ghost Net daemon built successfully.\033[0m"
echo "\033[1;37mRun with: $REPO_DIR/target/release/ggn-daemon --listen 0.0.0.0:2270 --socks 127.0.0.1:1080\033[0m"