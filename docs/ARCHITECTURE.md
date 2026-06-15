# Sentinel AI-DLP — Architecture

## 1. Design principles

1. **One brain, many sources.** All detection/policy logic lives in `DLPCore`,
   a pure Swift library with no AppKit / NetworkExtension / SwiftUI dependency.
   Every vector (clipboard, file, network, Endpoint Security, CLI) is a thin
   *adapter* that feeds plaintext + context into the same `DLPEngine`. This keeps
   the security-critical code unit-testable and portable.
2. **Privacy by construction.** Raw sensitive values never leave the detection
   call. Findings carry a masked preview and a 64-bit SHA-256 fingerprint only.
3. **Fail predictably.** A bad operator-supplied rule is quarantined, not fatal.
   `failMode` chooses availability vs protection on internal error.
4. **Honesty about TLS.** The network filter enforces by *destination*; content
   classification happens where plaintext exists.

## 2. Component model

```
        ┌────────────────────────── user space ──────────────────────────┐
        │                                                                 │
        │   SentinelAgent (menu-bar app, LSUIElement)                     │
        │     • OSSystemExtensionRequest → installs sysext                │
        │     • DLPService: ClipboardMonitor + FileSystemMonitor          │
        │     • SwiftUI status popover, live audit                        │
        │                                                                 │
        │   dlpctl (CLI)  ── scan / watch / patterns / services / audit   │
        └───────────────┬─────────────────────────────────────────────────┘
                        │ App Group (group.com.sentinel.dlp): policy + audit
        ┌───────────────▼──────────────── system space ──────────────────┐
        │   SentinelNetworkFilter (.appex, root)                          │
        │     NEFilterDataProvider → destination-tier verdicts            │
        │                                                                 │
        │   SentinelEndpointSecurity (.systemextension, root, restricted) │
        │     es_client → AUTH_OPEN / NOTIFY_EXEC, block-before-paste     │
        └─────────────────────────────────────────────────────────────────┘

        DLPCore (linked into every target above)
          Detection → Classification → Policy → Redaction → Risk → Audit
```

### DLPCore pipeline

```
text + InspectionContext
      │
      ▼  DetectionEngine
   ┌── RegexDetector (61 patterns + checksum/entropy validators)
   ├── KeywordDetector (org classification banners; KR/EN)
   └── NLEntityDetector (on-device NER: person/org/location)
      │  → overlap resolution (priority interval selection)
      │  → ContextBooster (proximity confidence promotion)
      ▼
   DestinationClassifier  (host → AI service → risk tier)
      ▼
   PolicyEngine           (ordered rules, first-match-wins, monitor downgrade)
      ▼
   Redactor               (placeholder / mask / tokenize, span-merge safe)
      ▼
   RiskScorer             (severity·confidence·destination·volume → 0…1)
      ▼
   AuditSink              (JSONL + CEF; masked only)  →  DLPVerdict
```

## 3. Data flow: "user pastes an API key into ChatGPT"

1. User copies `sk-ant-api03-…` → `ClipboardMonitor` sees `changeCount` change.
2. `DLPService.ingest` builds an `InspectionContext(channel: .clipboard)`.
3. `DLPEngine.inspect` → `RegexDetector` matches `anthropic-api-key`
   (critical/credential); `ContextBooster` may promote it.
4. `PolicyEngine` matches `block-secrets` → action `block`.
5. Enforcement: the clipboard is cleared/replaced so the secret can't be pasted.
6. An `AuditEvent` (masked `sk••••••FF`, fingerprint, rule id, risk) is written to
   JSONL and the menu-bar activity feed.

On the **network** path the flow instead reaches `FilterDataProvider`, which sees
`chatgpt.com` (unsanctioned) and applies destination-tier policy; if the body is
plaintext it is additionally classified, but for TLS it is governed by tier.

## 4. Threat model (STRIDE-oriented)

| Threat | Vector | Mitigation |
|---|---|---|
| **Tampering** with policy/patterns | Malicious local edit / bad MDM push | Rules quarantined on parse error; ship policy via signed MDM; `failMode` |
| **Bypass** via TLS opacity | Paste body inside HTTPS | Clipboard/ES vectors inspect plaintext before egress; network does tier enforcement |
| **Bypass** via uncovered channel | AirDrop, screenshot, personal device | Documented residual risk; ES + DLP on managed endpoints; not a silver bullet |
| **Exfil** of secrets to AI | Developer pastes key into chatbot | `block-secrets` rule; near-zero-FP credential patterns |
| **Bulk exfil** | Paste a customer list | `categoryThresholds` (≥15 PII) → block |
| **DoS** of the agent | Pathological input / bad regex | Per-rule match caps, inspection length cap, regex quarantine, no `try!` |
| **Privacy/works-council** concern | Over-collection | Masked-only audit; `monitor` mode; on-device, no content egress |
| **False sense of security** | "DLP covers everything" | This doc states coverage limits explicitly |

## 5. Deployment lifecycle

1. MDM pushes `Sentinel-DLP.mobileconfig`:
   - `com.apple.system-extension-policy` pre-approves the sysext (no user prompt).
   - `com.apple.webcontent-filter` enables the socket filter.
   - `com.apple.TCC.configuration-profile-policy` grants file access.
   - `com.apple.servicemanagement` auto-launches the agent.
2. Agent launches → `OSSystemExtensionRequest.activationRequest` → OS validates
   the bundle against the allowed-extensions list → activates.
3. `NEFilterManager` is configured (`filterSockets = true`) and enabled.
4. Policy/pattern packs are delivered via App Group / MDM and hot-swapped into
   the running `DLPService` without restart.

## 6. SIEM integration

- **JSONL** (`JSONLFileAuditSink`) — one event per line, ISO-8601 timestamps,
  ready for the Splunk/Elastic/Datadog file inputs.
- **CEF** (`CEFFormatter`) — ArcSight Common Event Format for syslog pipelines.
- Both emit masked values + fingerprints only; correlate "same secret seen
  again" across events via the fingerprint without ever storing plaintext.
- `MultiAuditSink` fans out to local + remote (e.g. a webhook) simultaneously.

## 7. Network content-path limitations (by design)

The `NEFilterDataProvider` is a **destination-tier enforcer first**; outbound
*content* inspection is best-effort beneath that guarantee:

- **No held tail / no deadlock.** Each inspected outbound window is released
  synchronously (`passBytes == window`). A content filter has no per-request
  "outbound complete" signal on keep-alive connections, so withholding an
  already-sent tail to catch a boundary-split secret would stall legitimate
  uploads. We refuse to do that.
- **Residual:** a plaintext secret split exactly across an outbound window
  boundary can leak its first fragment before the flow is dropped. Bodies past
  the 64 KiB cap pass unclassified.
- **TLS is opaque.** Real AI traffic is HTTPS, so the wire bytes are ciphertext;
  those flows are governed solely by destination-tier policy in `handleNewFlow`
  (block/audit by service). Authoritative plaintext content DLP lives on the
  **clipboard / file / Endpoint-Security** vectors.
- **Verification:** the verdict byte-semantics are validated against the SDK
  header + unit tests on the pure `decideOutbound`. They must be re-verified on a
  signed build on real hardware before any drop/enforcement ships on the network
  path — **prefer audit-only there until then**. Window-boundary split coverage,
  if ever mandated, requires the async `pauseVerdict` + `resumeFlow` path.

## 8. Performance

- Detection is linear in input size; each rule has a per-scan match cap and the
  engine has an inspection-length cap (network sets 64 KB).
- NER is bounded to a configurable prefix (default 50 KB).
- Clipboard polling is an integer `changeCount` compare every 250 ms — negligible.
