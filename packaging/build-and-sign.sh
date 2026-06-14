#!/usr/bin/env bash
#
# Build, bundle, sign and notarize the Sentinel AI-DLP menu-bar agent.
#
# The menu-bar app and CLI build straight from SwiftPM. The NetworkExtension and
# EndpointSecurity *system extensions* must be built and embedded via an Xcode
# project (system extensions are app-extension bundles that SwiftPM can't emit);
# this script assembles and signs the agent app and documents where the extension
# bundles are embedded.
#
# Requirements: a "Developer ID Application" certificate, your Team ID, and a
# notarytool keychain profile. Set:
#   export TEAM_ID=ABCDE12345
#   export SIGN_ID="Developer ID Application: Acme, Inc. (ABCDE12345)"
#   export NOTARY_PROFILE=sentinel-notary    # xcrun notarytool store-credentials
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/.build/release"
APP="$ROOT/dist/Sentinel.app"
: "${SIGN_ID:?set SIGN_ID to your Developer ID Application identity}"

echo "▸ Building release binaries…"
( cd "$ROOT" && swift build -c release --product SentinelAgent --product dlpctl )

echo "▸ Assembling $APP …"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/SystemExtensions"
cp "$BUILD_DIR/SentinelAgent" "$APP/Contents/MacOS/Sentinel"
cp "$BUILD_DIR/dlpctl" "$APP/Contents/MacOS/dlpctl"
cp "$ROOT/packaging/Info/SentinelAgent-Info.plist" "$APP/Contents/Info.plist"
# Bundle the SwiftPM resource bundle (patterns.json, ai-services.json) into
# Contents/Resources. DLPCore's DLPResources loader searches Bundle.main.resourceURL
# (= Contents/Resources) for SentinelDLP_DLPCore.bundle, so this is where it must go.
# Fail LOUDLY if it's missing: DLPResources degrades to a tiny fallback catalog, so
# a release shipped without the full 61-pattern/20-service pack would silently have
# broad detection gaps rather than crash.
RES_BUNDLE="$BUILD_DIR/SentinelDLP_DLPCore.bundle"
if [ ! -f "$RES_BUNDLE/patterns.json" ] || [ ! -f "$RES_BUNDLE/ai-services.json" ]; then
  echo "✗ Resource bundle missing or incomplete: $RES_BUNDLE"
  echo "  Run 'swift build -c release' first so patterns.json / ai-services.json exist."
  exit 1
fi
cp -R "$RES_BUNDLE" "$APP/Contents/Resources/"
if [ ! -f "$APP/Contents/Resources/SentinelDLP_DLPCore.bundle/patterns.json" ]; then
  echo "✗ Resource bundle did not copy into the app — aborting."
  exit 1
fi

# Pull pre-built system extensions from a STAGING dir (the app bundle is wiped on
# every run, so they can't live inside it between runs). Build the
# NetworkExtension / EndpointSecurity targets in Xcode and drop their bundles in
# $EXTENSIONS_DIR (default dist/extensions/).
EXTENSIONS_DIR="${EXTENSIONS_DIR:-$ROOT/dist/extensions}"
if [ -d "$EXTENSIONS_DIR" ]; then
  find "$EXTENSIONS_DIR" -mindepth 1 -maxdepth 1 \( -name '*.appex' -o -name '*.systemextension' \) \
    -exec cp -R {} "$APP/Contents/Library/SystemExtensions/" \;
fi

cat <<EOF

▸ System extensions are staged from: $EXTENSIONS_DIR
    (build SentinelNetworkFilter.appex / SentinelEndpointSecurity.systemextension
     in Xcode and place them there before running this script)

▸ Signing (order matters — sign nested code first):
EOF

# Require the embedded system extensions to be present BEFORE signing. Signing the
# app over an empty SystemExtensions dir produces a notarized bundle with no
# network filter, and copying extensions in afterwards invalidates the app
# signature. Set ALLOW_NO_EXTENSIONS=1 to intentionally build a clipboard-only
# agent (no network/ES vectors).
ext_count=$(find "$APP/Contents/Library/SystemExtensions" -mindepth 1 -maxdepth 1 \
  \( -name '*.appex' -o -name '*.systemextension' \) 2>/dev/null | wc -l | tr -d ' ')
if [ "$ext_count" -eq 0 ] && [ -z "${ALLOW_NO_EXTENSIONS:-}" ]; then
  echo "✗ No system extensions found in $APP/Contents/Library/SystemExtensions/."
  echo "  Build the NetworkExtension/EndpointSecurity targets in Xcode and copy"
  echo "  their .appex/.systemextension bundles there BEFORE running this script,"
  echo "  or set ALLOW_NO_EXTENSIONS=1 to build a clipboard-only agent."
  echo "  Aborting: signing now would ship an app with no network filter, and"
  echo "  embedding extensions afterward would break the app signature."
  exit 1
fi

echo "▸ Signing…"
# Sign embedded extensions first (if present), then the app, deep + hardened
# runtime. Each extension MUST get its own entitlements file — signing the
# Endpoint Security extension with the network-filter entitlements would strip
# `com.apple.developer.endpoint-security.client` and it would fail at runtime.
find "$APP/Contents/Library/SystemExtensions" -maxdepth 1 -type d 2>/dev/null | while read -r ext; do
  [ "$ext" = "$APP/Contents/Library/SystemExtensions" ] && continue
  base="$(basename "$ext" | tr '[:upper:]' '[:lower:]')"
  case "$base" in
    *endpointsecurity*|*endpoint-security*)
      ent="$ROOT/packaging/entitlements/SentinelEndpointSecurity.entitlements" ;;
    *networkfilter*|*network-filter*)
      ent="$ROOT/packaging/entitlements/SentinelNetworkFilter.entitlements" ;;
    *)
      echo "  ⚠︎ unknown extension '$base' — defaulting to network-filter entitlements; verify manually"
      ent="$ROOT/packaging/entitlements/SentinelNetworkFilter.entitlements" ;;
  esac
  echo "  signing $(basename "$ext") with $(basename "$ent")"
  codesign --force --options runtime --timestamp \
    --entitlements "$ent" \
    --sign "$SIGN_ID" "$ext"
done

# Sign the embedded CLI helper in Contents/MacOS BEFORE the outer bundle. Per
# Apple TN2206 all nested code must already be signed before the app is signed,
# otherwise notarization/Gatekeeper can reject the (unsigned/ad-hoc) helper.
if [ -f "$APP/Contents/MacOS/dlpctl" ]; then
  echo "  signing Contents/MacOS/dlpctl"
  codesign --force --options runtime --timestamp --sign "$SIGN_ID" "$APP/Contents/MacOS/dlpctl"
fi

codesign --force --options runtime --timestamp \
  --entitlements "$ROOT/packaging/entitlements/SentinelAgent.entitlements" \
  --sign "$SIGN_ID" "$APP"

echo "▸ Verifying signature…"
codesign --verify --deep --strict --verbose=2 "$APP"

if [ -n "${NOTARY_PROFILE:-}" ]; then
  echo "▸ Notarizing…"
  DITTO_ZIP="$ROOT/dist/Sentinel.zip"
  ditto -c -k --keepParent "$APP" "$DITTO_ZIP"
  xcrun notarytool submit "$DITTO_ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$APP"
fi

echo "✓ Done: $APP"
