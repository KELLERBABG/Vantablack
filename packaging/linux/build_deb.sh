#!/usr/bin/env bash
set -euo pipefail

VERSION=${1:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)}
ARCH=${DEB_ARCH:-amd64}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT=${OUT_DIR:-$ROOT/dist}
PKG="$OUT/global-ghost-net_${VERSION}_${ARCH}"
rm -rf "$PKG"
HEADLESS="$ROOT/target/release/ggn-headless"
if [[ ! -f "$HEADLESS" ]]; then HEADLESS="$ROOT/target/release/ggn"; fi
if [[ ! -f "$HEADLESS" ]]; then echo "missing release binary: $HEADLESS" >&2; exit 1; fi
install -Dm755 "$HEADLESS" "$PKG/usr/bin/ggn-headless"
install -Dm644 "$ROOT/packaging/linux/ggn.service" "$PKG/lib/systemd/system/ggn.service"
install -d "$PKG/DEBIAN"
cat > "$PKG/DEBIAN/control" <<EOF
Package: global-ghost-net
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Keller Systems
Description: Vantablack post-quantum mesh node
 A headless Vantablack daemon with SOCKS5 and optional VPN support.
EOF
cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! getent group ggn >/dev/null 2>&1; then groupadd --system ggn; fi
if ! getent passwd ggn >/dev/null 2>&1; then useradd --system --gid ggn --home-dir /var/lib/globalghostnet --no-create-home --shell /usr/sbin/nologin ggn; fi
install -d -o ggn -g ggn -m 0750 /var/lib/globalghostnet /var/log/globalghostnet
systemctl daemon-reload || true
systemctl enable ggn.service || true
EOF
chmod 0755 "$PKG/DEBIAN/postinst"
mkdir -p "$OUT"
dpkg-deb --build "$PKG" "$OUT/global-ghost-net_${VERSION}_${ARCH}.deb"
rm -rf "$PKG"
printf '%s\n' "$OUT/global-ghost-net_${VERSION}_${ARCH}.deb"
