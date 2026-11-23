#!/usr/bin/env bash
# The standard verification for this repository.
#
# Why the `quic` runs are here and not optional: the MASQUE transport (endpoint,
# client, admission, carriage in both directions) lives behind the `quic` feature,
# because quinn is an optional dependency. A plain `cargo test` therefore does not
# even compile it, and "compiled only in a configuration nobody runs" is how a
# transport silently rots. The loopback end-to-end tests in `daemon::masque` and
# `daemon::bonding` are the ones that would rot, so their feature run is part of
# this gate.
#
# Usage: ./scripts/verify.sh            (or: bash scripts/verify.sh)
#        CARGO=/path/to/cargo ./scripts/verify.sh
set -euo pipefail

cd "$(dirname "$0")/.."
CARGO="${CARGO:-cargo}"

run() {
    echo
    echo "=== $* ==="
    "$@"
}

run "$CARGO" fmt -- --check
run "$CARGO" clippy --all-targets -- -D warnings
run "$CARGO" clippy --all-targets --features quic -- -D warnings

run "$CARGO" test --lib
run "$CARGO" test --bin ggn

# The QUIC-enabled runs: library carrier tests plus the daemon's MASQUE and HPEB
# loopback end-to-end tests, which exist only in this configuration.
run "$CARGO" test --lib --features quic
run "$CARGO" test --bin ggn --features quic

echo
echo "All verification gates passed."
