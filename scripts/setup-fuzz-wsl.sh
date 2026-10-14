#!/usr/bin/env bash
# Bootstrap the fuzzing toolchain inside WSL: cargo-fuzz needs nightly, and the
# sanitizer runtimes only exist there. Nothing here touches the repo.
set -o pipefail
export PATH="$HOME/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin"
echo "rustup: $(command -v rustup || echo missing)"
rustup --version 2>&1 | head -1
rustup toolchain list 2>&1 | head -5
if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
  echo "installing nightly"
  rustup toolchain install nightly --profile minimal --component llvm-tools-preview 2>&1 | tail -5
fi
if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "installing cargo-fuzz"
  cargo +nightly install cargo-fuzz --locked 2>&1 | tail -5
fi
echo "cargo-fuzz: $(command -v cargo-fuzz || echo missing)"
