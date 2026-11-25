#!/usr/bin/env bash
# Reproducible release hashes (V3 Stage 7 release gate).
#
# Two measurements, both of which a release claim needs:
#
#   1. A deterministic source manifest: every tracked file, sorted by path, with
#      its SHA-256, hashed again. This is what a verifier can rebuild from a
#      checkout; it includes working-tree content, so an uncommitted edit changes
#      it (by design — the manifest describes the tree you are about to ship).
#
#   2. A bit-for-bit binary comparison: the same `ggn` binary is built twice in
#      two fresh target directories with `--locked`, `CARGO_INCREMENTAL=0` and
#      no default features. Different target directories are the point: an
#      incremental rebuild proves nothing about reproducibility.
#
# Usage:
#   scripts/reproducible_hash.sh                # release profile (default)
#   PROFILE=dev scripts/reproducible_hash.sh    # debug, much faster
#   CARGO=/path/to/cargo scripts/reproducible_hash.sh
#
# Exit status: 0 only when both builds hash identically.
set -euo pipefail

cd "$(dirname "$0")/.."
CARGO="${CARGO:-cargo}"
PROFILE="${PROFILE:-release}"

case "$PROFILE" in
    release) BUILD_ARGS=(--release); OUT_DIR=release ;;
    dev) BUILD_ARGS=(); OUT_DIR=debug ;;
    *) echo "PROFILE must be 'release' or 'dev', got '$PROFILE'" >&2; exit 2 ;;
esac

case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) EXE=".exe" ;;
    *) EXE="" ;;
esac

sha() { sha256sum -- "$1" | cut -d' ' -f1; }

# COFF/PE links embed the link time in the header and debug directory. Two
# otherwise identical release builds differed in exactly those 24 bytes until
# `/Brepro` was passed to lld-link; with it they hash identically. Only the
# MSVC host needs the flag, so other targets are left alone.
HOST=$("$CARGO" -vV | sed -n 's/^host: //p')
if [[ "$HOST" == *windows-msvc* ]]; then
    export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C link-arg=/Brepro"
    echo "host $HOST: linking with /Brepro (no COFF timestamps)"
fi

manifest() {
    git ls-files | LC_ALL=C sort | while IFS= read -r path; do
        [ -f "$path" ] || continue
        printf '%s  %s\n' "$(sha "$path")" "$path"
    done
}

mkdir -p target
manifest > target/source-manifest.txt
SOURCE_HASH=$(sha target/source-manifest.txt)
echo "source manifest: target/source-manifest.txt"
echo "source hash:     $SOURCE_HASH"
echo

for run in a b; do
    echo "=== building ($run, $PROFILE, --no-default-features) ==="
    CARGO_TARGET_DIR="target/repro-$run" CARGO_INCREMENTAL=0 \
        "$CARGO" build --locked "${BUILD_ARGS[@]}" --no-default-features --bin ggn
done

BIN_A="target/repro-a/$OUT_DIR/ggn$EXE"
BIN_B="target/repro-b/$OUT_DIR/ggn$EXE"
HASH_A=$(sha "$BIN_A")
HASH_B=$(sha "$BIN_B")

echo
echo "binary a: $HASH_A"
echo "binary b: $HASH_B"

if [ "$HASH_A" = "$HASH_B" ]; then
    echo "REPRODUCIBLE: both $PROFILE builds are byte-identical"
    exit 0
fi

echo "NOT REPRODUCIBLE: $PROFILE builds differ" >&2
# Show where they differ when cmp is available; the hashes already prove the
# failure, this just points at the first differing byte.
cmp -l "$BIN_A" "$BIN_B" | head -5 >&2 || true
exit 1
