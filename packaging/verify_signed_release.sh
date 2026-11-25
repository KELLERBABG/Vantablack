#!/usr/bin/env bash
# Verify that a release actually carries the signatures Stage 5 promises.
#
# This gate is deliberately allowed to fail: a build machine without the
# project's signing keys can produce artifacts, but it cannot produce a signed
# release claim. The Rust adoption status consumes `--json` and reports
# installers as withheld until this script verifies all four families.
#
# Usage:
#   packaging/verify_signed_release.sh [--json] [dist-dir]
#
# `dist-dir` defaults to $GGN_SIGNED_DIST, then ./dist.
#
# Expected artifact names (globs are intentional):
#   dist/ggn-*-windows-setup.exe      Authenticode, verified with signtool
#   dist/*.tar.gz + *.tar.gz.sig      Homebrew bottle and its detached signature
#   dist/*.deb + *.deb.sig            .deb package and its detached signature
#   dist/*-android.apk                APK signature, verified with apksigner
#
# Exit status: 0 only when all four verify; 1 otherwise. `--json` still prints a
# document on failure (and always exits non-zero), so the caller can report the
# exact reason without parsing prose.
set -euo pipefail

JSON=0
if [ "${1:-}" = "--json" ]; then
  JSON=1
  shift
fi
DIST="${1:-${GGN_SIGNED_DIST:-dist}}"

ROWS=$(mktemp)
REASONS=$(mktemp)
cleanup() { rm -f "$ROWS" "$REASONS"; }
trap cleanup EXIT
fail=0

note() {
  if [ "$JSON" -eq 0 ]; then printf '%s\n' "$*"; fi
}
withhold() {
  note "WITHHELD: $*"
  printf '%s\n' "$*" >>"$REASONS"
  fail=1
}

json_string() {
  local escaped
  escaped=$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
  printf '"%s"' "$escaped"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    return 1
  fi
}

# Rows use the unit separator (not a tab: IFS whitespace collapses empty
# fields, which turns a missing artifact into the next column). Only a family
# that actually verified gets signed=1, and its real digest is recorded.
SEP=$'\x1f'
emit_row() {
  printf '%s%s%s%s%s%s%s\n' "$1" "$SEP" "$2" "$SEP" "$3" "$SEP" "$4" >>"$ROWS"
}

record_ok() {
  local kind="$1" artifact="$2" sha
  if ! sha=$(sha256_of "$artifact"); then
    withhold "$kind artifact is present but its sha256 could not be computed"
    emit_row "$kind" "$artifact" 0 ""
    return
  fi
  emit_row "$kind" "$artifact" 1 "$sha"
}

record_unsigned() {
  local kind="$1" artifact="$2" why="$3"
  withhold "$why"
  emit_row "$kind" "$artifact" 0 ""
}

verify_authenticode() {
  local exe
  exe=$(find "$DIST" -maxdepth 1 -name 'ggn-*-windows-setup.exe' -print -quit 2>/dev/null || true)
  if [ -z "$exe" ]; then
    record_unsigned winget "" "winget/Windows installer missing"
    return
  fi
  if command -v signtool >/dev/null 2>&1; then
    if signtool verify /pa "$exe" >/dev/null 2>&1; then
      record_ok winget "$exe"
    else
      record_unsigned winget "$exe" "Authenticode verification failed for $exe"
    fi
  elif command -v osslsigncode >/dev/null 2>&1; then
    if osslsigncode verify "$exe" >/dev/null 2>&1; then
      record_ok winget "$exe"
    else
      record_unsigned winget "$exe" "Authenticode verification failed for $exe"
    fi
  else
    record_unsigned winget "$exe" "no signtool/osslsigncode available to verify $exe"
  fi
}

verify_detached() {
  local kind="$1" artifact="$2" label="$3"
  if [ ! -f "$artifact" ]; then
    record_unsigned "$kind" "" "$label artifact missing"
    return
  fi
  if [ ! -f "$artifact.sig" ]; then
    record_unsigned "$kind" "$artifact" "$label has no detached signature"
    return
  fi
  if ! command -v gpg >/dev/null 2>&1; then
    record_unsigned "$kind" "$artifact" "gpg unavailable to verify $label"
    return
  fi
  if gpg --verify "$artifact.sig" "$artifact" >/dev/null 2>&1; then
    record_ok "$kind" "$artifact"
  else
    record_unsigned "$kind" "$artifact" "$label signature does not verify"
  fi
}

verify_brew() {
  local bottle
  bottle=$(find "$DIST" -maxdepth 1 -name '*.tar.gz' -print -quit 2>/dev/null || true)
  if [ -z "$bottle" ]; then
    record_unsigned homebrew "" "Homebrew bottle missing"
    return
  fi
  verify_detached homebrew "$bottle" "Homebrew bottle"
}

verify_deb() {
  local deb
  deb=$(find "$DIST" -maxdepth 1 -name '*.deb' -print -quit 2>/dev/null || true)
  if [ -z "$deb" ]; then
    record_unsigned deb "" ".deb package missing"
    return
  fi
  verify_detached deb "$deb" ".deb"
}

verify_apk() {
  local apk
  apk=$(find "$DIST" -maxdepth 1 -name '*-android.apk' -print -quit 2>/dev/null || true)
  if [ -z "$apk" ]; then
    record_unsigned apk "" "Android APK missing"
    return
  fi
  if ! command -v apksigner >/dev/null 2>&1; then
    record_unsigned apk "$apk" "apksigner unavailable to verify $apk"
    return
  fi
  if apksigner verify --verbose "$apk" >/dev/null 2>&1; then
    record_ok apk "$apk"
  else
    record_unsigned apk "$apk" "APK signature does not verify"
  fi
}

verify_authenticode
verify_brew
verify_deb
verify_apk

verified=false
if [ "$fail" -eq 0 ]; then verified=true; fi

if [ "$JSON" -eq 1 ]; then
  printf '{"verified":%s,"dist":%s,"installers":[' "$verified" "$(json_string "$DIST")"
  first=1
  while IFS="$SEP" read -r kind artifact signed sha; do
    [ -z "$kind" ] && continue
    if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
    if [ "$signed" = "1" ]; then signed_json=true; else signed_json=false; fi
    printf '{"kind":%s,"artifact":%s,"signed":%s,"sha256":%s}' \
      "$(json_string "$kind")" \
      "$(json_string "$artifact")" \
      "$signed_json" \
      "$(json_string "$sha")"
  done <"$ROWS"
  printf '],"reasons":['
  first=1
  while IFS= read -r reason; do
    [ -z "$reason" ] && continue
    if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
    printf '%s' "$(json_string "$reason")"
  done <"$REASONS"
  printf ']}\n'
else
  if [ "$fail" -ne 0 ]; then
    note "Signed-release claim: WITHHELD (at least one artifact is unsigned or unverified)"
  else
    note "Signed-release claim: VERIFIED (winget, Homebrew, .deb and APK)"
  fi
fi

exit "$fail"
