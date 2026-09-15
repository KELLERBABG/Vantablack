#!/usr/bin/env bash
#
# scripts/bench_transport.sh — `GTF_bulk` vs `QUIC` (SOTA P1-2 verify step).
#
# What this measures, and what it cannot:
#
#   * Both carriers move the *same* GTF frames, built by `net::build_gtf_frame`
#     and recovered by `net::unframe`, so the comparison is of transports and not
#     of stand-ins.
#   * It runs over loopback, which is a **lossless, zero-latency, single-host**
#     path. That is the one path where the UDP carrier is at its best and where
#     QUIC's reason for existing (loss recovery, congestion control, and an
#     encrypted transport a middlebox cannot inspect) cannot show up at all. Read
#     the table as "what the framing costs", not as "which carrier is faster on a
#     real path".
#   * Numbers are only comparable *within one run* on one machine. Debug builds
#     are included for throughput shape, not for absolute figures.
#
# Usage:
#   scripts/bench_transport.sh              # optimized (profile: bench-transport)
#   GGN_BENCH_DEV=1 scripts/bench_transport.sh   # dev profile: compiles fast
#
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is not on PATH" >&2
  exit 1
fi

PROFILE_FLAGS=(--profile bench-transport)
PROFILE_NAME="bench-transport"
if [[ "${GGN_BENCH_DEV:-0}" == "1" ]]; then
  PROFILE_FLAGS=()
  PROFILE_NAME="dev"
fi

echo "GTF_bulk vs QUIC transport benchmark"
echo "  profile : $PROFILE_NAME"
echo "  feature : quic (quinn + rustls-ring)"
echo "  volume  : 4 MiB of application payload per row, 256 KiB warm-up"
echo "  path    : 127.0.0.1 (loopback: lossless, so it cannot show loss recovery)"
echo

# The bench is `#[ignore]`d so an ordinary `cargo test` never pays for it; this
# script is the only thing that runs it.
cargo test "${PROFILE_FLAGS[@]}" --features quic --test bench_transport \
  -- --ignored --nocapture

echo
echo "Reminder: the loopback path cannot demonstrate why the QUIC carrier exists"
echo "(loss, congestion, and payloads a middlebox will not inspect). To see that,"
echo "run the mesh under the kernel netem topology and compare the same workload:"
echo "  scripts/mesh_smoke_test.sh"
