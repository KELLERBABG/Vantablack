#!/usr/bin/env sh
# Vantablack — automated node installer (POSIX sh).
#
# Served at the site root as advertised by the landing page:
#   curl -sSf https://vantablack.kellersystems.dev/install.sh | sh
#
# The daemon takes NO command-line arguments: it is configured entirely through
# environment variables (see config.env.example). `printf` is used rather than
# `echo` because `echo "\033[..m"` is not portable — dash/sh print the escape
# sequences literally.
set -e

printf '\033[1;36m=================================================\033[0m\n'
printf '\033[1;37m   VANTABLACK // Automated Node Installer   \033[0m\n'
printf '\033[1;36m=================================================\033[0m\n'

DEST_DIR="$HOME/.ggn"
mkdir -p "$DEST_DIR"

if ! command -v cargo >/dev/null 2>&1; then
    printf '\033[1;31m[!] Rust/Cargo is not installed.\033[0m\n'
    printf '\033[1;33m[*] Install Rust from https://rustup.rs and retry.\033[0m\n'
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    printf '\033[1;31m[!] git is not installed.\033[0m\n'
    exit 1
fi

REPO_DIR="$DEST_DIR/Global-Ghost-Net"
if [ -d "$REPO_DIR" ]; then
    printf '\033[1;33m[*] Updating existing repository...\033[0m\n'
    git -C "$REPO_DIR" pull --ff-only origin main
else
    printf '\033[1;33m[*] Cloning Vantablack...\033[0m\n'
    git clone https://github.com/KELLERBABG/Vantablack.git "$REPO_DIR"
fi

# The default build is the desktop application: a native window plus a tray
# icon, with the web control center running underneath. That needs GTK/WebKit
# development headers on Linux, so if they are missing we install the headless
# server build instead of failing.
BUILD_ARGS=""
if [ "$(uname -s)" = "Linux" ] && ! pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
    printf '\033[1;33m[*] GTK/WebKit headers not found - installing the headless server build.\033[0m\n'
    printf '\033[1;33m    For the desktop app, install them first, for example:\033[0m\n'
    printf '\033[1;33m      Debian/Ubuntu: sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev\033[0m\n'
    printf '\033[1;33m      Fedora:        sudo dnf install webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel librsvg2-devel\033[0m\n'
    BUILD_ARGS="--no-default-features"
fi

printf '\033[1;33m[*] Building release binary...\033[0m\n'
# shellcheck disable=SC2086
cargo build --release $BUILD_ARGS --manifest-path "$REPO_DIR/Cargo.toml"

BIN="$REPO_DIR/target/release/ggn"
printf '\033[1;32m[+] Built: %s\033[0m\n\n' "$BIN"
printf 'Quick Launch Options:\n\n'
printf '  # Desktop app: opens native window (control center on http://127.0.0.1:2270)\n'
printf '  %s\n\n' "$BIN"
printf '  # Low-Latency Mode (1ms micro-jitter for gaming/VoIP)\n'
printf '  %s --low-latency\n\n' "$BIN"
printf '  # Zero-Admin Mode (Userspace SOCKS5 on :1080 & DNS on :1053, no root needed)\n'
printf '  %s --zero-admin\n\n' "$BIN"
printf '  # Server / headless node, no window (control center in a browser tab)\n'
printf '  GHOST_NO_GUI=1 %s\n\n' "$BIN"
printf '  # CLI Help & Options\n'
printf '  %s --help\n' "$BIN"
