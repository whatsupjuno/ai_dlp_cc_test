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
# Bundle the SwiftPM resource bundles (patterns.json, ai-services.json).
cp -R "$BUILD_DIR"/*.bundle "$APP/Contents/Resources/" 2>/dev/null || true

cat <<EOF

▸ Embed the system extension(s):
    Build SentinelNetworkFilter.appex (and SentinelEndpointSecurity.systemextension)
    from the Xcode project, then copy into:
      $APP/Contents/Library/SystemExtensions/

▸ Signing (order matters — sign nested code first):
EOF

echo "▸ Signing…"
# Sign embedded extensions first (if present), then the app, deep + hardened runtime.
find "$APP/Contents/Library/SystemExtensions" -maxdepth 1 -type d 2>/dev/null | while read -r ext; do
  [ "$ext" = "$APP/Contents/Library/SystemExtensions" ] && continue
  codesign --force --options runtime --timestamp \
    --entitlements "$ROOT/packaging/entitlements/SentinelNetworkFilter.entitlements" \
    --sign "$SIGN_ID" "$ext"
done

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
