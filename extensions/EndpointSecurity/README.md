# Endpoint Security extension (reference source)

`EndpointSecurityMonitor.swift` is the optional **Endpoint Security (ES)** vector.
It is intentionally **not** part of the SwiftPM package because it cannot run
outside a signed, entitled system extension:

- Requires the **restricted** entitlement
  `com.apple.developer.endpoint-security.client` (granted by Apple per Team ID).
- Must run as **root** inside a `.systemextension` bundle.
- `es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` otherwise.

## Why it's worth adding

| Vector | Sees plaintext? | Can block *before* egress? |
|---|---|---|
| Clipboard (NSPasteboard) | ✅ | partially (redact/clear after copy) |
| File (FSEvents) | ✅ | ❌ (observe after write) |
| Network (NEFilterDataProvider) | ❌ TLS ciphertext | ✅ by destination only |
| **Endpoint Security** | ✅ | ✅ true block-before-paste / open |

ES is the only vector that can **synchronously deny** an action (`AUTH` events),
making it the strongest enforcement point. It feeds the same `DLPCore` engine.

## Integrating

1. Add an Xcode **System Extension** target (type: Endpoint Security).
2. Add this file + the `DLPCore` Swift package to the target.
3. Apply `packaging/entitlements/SentinelEndpointSecurity.entitlements`.
4. Add the bundle id to the MDM `AllowedSystemExtensions` list.
5. Respect the ES message **deadline** — cache verdicts; never block the handler.
