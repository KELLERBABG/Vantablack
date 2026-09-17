#!/usr/bin/env bash
set -euo pipefail

PREFIX=${PREFIX:-/usr}
BINDIR="$PREFIX/bin"
UNITDIR=${UNITDIR:-/etc/systemd/system}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (or set a staging PREFIX and UNITDIR)." >&2
  exit 1
fi

HEADLESS="$ROOT/target/release/ggn-headless"
if [[ ! -f "$HEADLESS" ]]; then HEADLESS="$ROOT/target/release/ggn"; fi
if [[ ! -f "$HEADLESS" ]]; then echo "missing release binary: $HEADLESS" >&2; exit 1; fi
install -Dm755 "$HEADLESS" "$BINDIR/ggn-headless"
install -Dm644 "$ROOT/packaging/linux/ggn.service" "$UNITDIR/ggn.service"
if ! getent group ggn >/dev/null 2>&1; then groupadd --system ggn; fi
if ! getent passwd ggn >/dev/null 2>&1; then
  useradd --system --gid ggn --home-dir /var/lib/globalghostnet --no-create-home --shell /usr/sbin/nologin ggn
fi
install -d -o ggn -g ggn -m 0750 /var/lib/globalghostnet /var/log/globalghostnet
systemctl daemon-reload
systemctl enable --now ggn.service
printf 'Installed and started ggn.service\n'
