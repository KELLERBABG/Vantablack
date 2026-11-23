#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-2.1.0}"
BIN_PATH="${2:-target/aarch64-apple-darwin/release/ggn}"
OUT_DMG="${3:-ggn-v${VERSION}-aarch64-apple-darwin.dmg}"

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

APP_DIR="$STAGE_DIR/Vantablack.app/Contents"
mkdir -p "$APP_DIR/MacOS" "$APP_DIR/Resources"

cp "$BIN_PATH" "$APP_DIR/MacOS/ggn"
chmod +x "$APP_DIR/MacOS/ggn"

cat > "$APP_DIR/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>Vantablack</string>
  <key>CFBundleExecutable</key>
  <string>ggn</string>
  <key>CFBundleIdentifier</key>
  <string>dev.kellersystems.vantablack</string>
  <key>CFBundleName</key>
  <string>Vantablack</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF

ln -s /Applications "$STAGE_DIR/Applications"

if [[ -n "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  codesign --force --deep --options runtime --sign "$APPLE_SIGNING_IDENTITY" "$STAGE_DIR/Vantablack.app"
fi

hdiutil create -volname "Vantablack" -srcfolder "$STAGE_DIR" -ov -format UDZO "$OUT_DMG"

if [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_PASSWORD:-}" ]]; then
  xcrun notarytool submit "$OUT_DMG" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
  xcrun stapler staple "$OUT_DMG"
fi
