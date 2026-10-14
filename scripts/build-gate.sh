#!/usr/bin/env bash
# Build gate for this host. WSL is the only toolchain that can compile `ring`
# here: the Windows gnu toolchain's gcc 16 fails the C build, and the MSVC
# toolchain has no linker or Windows SDK libraries installed.
set -o pipefail

export PATH="$HOME/.cargo/bin:$PATH"
cd "/mnt/c/Users/INTAL Admin/SYSTEMS & CREATIONS/Vantablack" || exit 2

# A target dir under the Linux filesystem, so cargo is not writing object files
# across the 9p mount for every crate.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/vb-target}"

exec cargo "$@"
