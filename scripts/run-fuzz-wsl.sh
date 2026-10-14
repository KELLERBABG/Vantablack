#!/usr/bin/env bash
# Fuzz smoke gates, the same shape CI runs. Needs nightly (sanitizer runtimes)
# and cargo-fuzz; scripts/setup-fuzz-wsl.sh installs both.
#
# Usage: run-fuzz-wsl.sh [seconds-per-target]
set -o pipefail
export PATH="$HOME/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin"
cd "/mnt/c/Users/INTAL Admin/SYSTEMS & CREATIONS/Vantablack/fuzz" || exit 2

SECONDS_PER_TARGET="${1:-10}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/vb-fuzz-target}"

TARGETS="fuzz_handle_pkt fuzz_parse_handshake_pdu fuzz_kyber_ciphertext fuzz_build_gtf_frame fuzz_parse_relay_header fuzz_unframe fuzz_parse_quic_binding"
# The quic target only exists in a build with the feature; skip it if it is not
# declared rather than failing the whole run.
DECLARED=$(grep -oP '^name = "\K[^"]+' Cargo.toml | tr '\n' ' ')

failed=0
for target in $TARGETS; do
  case " $DECLARED " in
    *" $target "*) ;;
    *) echo "SKIP $target (not declared in fuzz/Cargo.toml)"; continue ;;
  esac
  echo "=== fuzzing $target for ${SECONDS_PER_TARGET}s ==="
  if cargo +nightly fuzz run "$target" -- -max_total_time="$SECONDS_PER_TARGET" >"/tmp/fuzz_${target}.log" 2>&1; then
    echo "PASS $target"
  else
    echo "FAIL $target"
    tail -n 20 "/tmp/fuzz_${target}.log"
    failed=$((failed + 1))
  fi
done
echo "targets failed: $failed"
exit "$failed"
