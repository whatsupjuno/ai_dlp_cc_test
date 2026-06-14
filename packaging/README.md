# Packaging & enterprise deployment

| File | Purpose |
|---|---|
| `entitlements/SentinelAgent.entitlements` | Menu-bar app: installs the system extension, App Group |
| `entitlements/SentinelNetworkFilter.entitlements` | NEFilterDataProvider: `content-filter-provider-systemextension` |
| `entitlements/SentinelEndpointSecurity.entitlements` | ES extension: restricted `endpoint-security.client` |
| `Info/SentinelAgent-Info.plist` | `LSUIElement` (no Dock icon), bundle id, versions |
| `Info/SentinelNetworkFilter-Info.plist` | `NSExtension` filter-data registration |
| `mdm/Sentinel-DLP.mobileconfig` | Silent enterprise deployment profile |
| `build-and-sign.sh` | Assemble `.app`, codesign (hardened runtime), notarize |

## Steps

1. **Replace placeholders** — `ABCDE12345` → your Apple **Team ID**; the
   `*DesignatedRequirement` strings → `codesign -dr -` output for each binary.
2. **Build & sign** the agent + CLI:
   ```bash
   export SIGN_ID="Developer ID Application: Acme, Inc. (ABCDE12345)"
   export NOTARY_PROFILE=sentinel-notary
   ./packaging/build-and-sign.sh
   ```
3. **Build the system extensions** in Xcode (NetworkExtension + Endpoint
   Security targets that link the `DLPCore` SwiftPM package and the sources in
   `Sources/SentinelNetworkFilter/` and `extensions/EndpointSecurity/`), embed
   the `.appex` / `.systemextension` in
   `Sentinel.app/Contents/Library/SystemExtensions/`.
4. **Distribute the MDM profile** (`mdm/Sentinel-DLP.mobileconfig`) so the
   extension is pre-approved and the filter/TCC/login-item are configured with
   no end-user interaction.

## Why some targets are "source-only" here

The Command Line Tools toolchain can compile every Swift file, but it cannot
codesign or run **system extensions**. `SentinelNetworkFilter` is provided as a
compiling SwiftPM library (so its provider class is type-checked in CI) and is
*packaged* as a `.appex` via Xcode; the Endpoint Security monitor lives under
`extensions/` because `es_new_client` refuses to run without the restricted
entitlement. Both are real, reviewable source — only the signing/run step needs
a Developer ID + entitlements.
