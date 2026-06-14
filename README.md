# Sentinel AI-DLP for macOS

**Enterprise Data Loss Prevention focused on the #1 modern exfiltration channel:
employees pasting secrets and regulated data into AI tools (ChatGPT, Claude,
Gemini, Copilot, …).** Written in Swift 6, on-device, privacy-preserving.

Sentinel detects sensitive data (PII, credentials/API keys, financial,
government IDs, PHI) the moment it heads toward an AI service — via the
clipboard, the filesystem, or the network — and **allows, audits, redacts,
warns, blocks, or quarantines** it according to a declarative enterprise policy.
All detection runs **locally**; raw sensitive values are never logged or
transmitted.

```
   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
   │  Clipboard   │   │  Filesystem  │   │   Network    │
   │ NSPasteboard │   │   FSEvents   │   │ NEFilterData │
   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
          │ plaintext        │ plaintext        │ host/SNI (+plaintext if any)
          └──────────────────┼──────────────────┘
                             ▼
                   ┌───────────────────┐     detect → classify dest →
                   │     DLPCore        │     evaluate policy → redact →
                   │  (the shared brain)│     score → audit
                   └─────────┬─────────┘
              ┌──────────────┼───────────────┐
              ▼              ▼               ▼
      Allow / Audit    Redact / Warn    Block / Quarantine
              └──────────────┼───────────────┘
                             ▼
                ┌────────────────────────┐
                │  Audit (JSONL / CEF)    │ → Splunk / Elastic / syslog SIEM
                └────────────────────────┘
```

## Highlights

- **61 production detection patterns** across financial (Luhn-validated PANs,
  IBAN mod-97, SWIFT, ABA), government IDs (US SSN/ITIN, Korean RRN with
  checksum, UK NINO, EU national IDs), **credentials/API keys** (AWS, GCP, Azure,
  GitHub, Slack, Stripe, **OpenAI `sk-`, Anthropic `sk-ant-`**, JWT, PEM private
  keys, …), PII, and PHI (ICD-10, NPI, DEA).
- **Checksum & statistical validators** (Luhn, IBAN mod-97, Korean RRN, ABA,
  NPI-Luhn, Shannon-entropy) so high-volume patterns don't drown you in false
  positives. Patterns that don't compile are **quarantined, never crash** the
  agent.
- **On-device NER** (Apple `NaturalLanguage`) to catch names/orgs/locations no
  regex can enumerate — entirely offline.
- **Proximity/context boosting** — a keyword like `SSN:` near a match promotes
  confidence and kills false positives (Korean lexicon included).
- **AI-destination intelligence** — 20 AI services classified into
  `sanctioned / monitored / unsanctioned / blocked` risk tiers, with
  longest-suffix host matching and per-org overrides.
- **Declarative policy engine** — ordered rules, first-match-wins, finding- and
  context-level conditions, `monitor` (observe-only) vs `enforce` modes.
- **Privacy by construction** — findings carry only a masked preview
  (`12••••••89`) and a 64-bit fingerprint; the plaintext never leaves detection.
- **SIEM-ready audit** — JSONL and ArcSight CEF.
- Ships as a **menu-bar agent**, a **CLI**, a **NetworkExtension content
  filter**, and an optional **Endpoint Security** extension.

## The vectors (and an honest note on TLS)

| Vector | Sees plaintext? | Enforcement | Status |
|---|---|---|---|
| Clipboard (`NSPasteboard`) | ✅ | redact / clear on copy | **runs with no entitlements** |
| Filesystem (`FSEvents`) | ✅ | observe + audit | runs (user-readable dirs) |
| Network (`NEFilterDataProvider`) | ❌ TLS is ciphertext | **block/allow by destination** | system extension |
| Endpoint Security (`es_client`) | ✅ | **block-before-paste/open** | system extension (restricted) |

> Every AI endpoint is HTTPS, so the network content filter sees the destination
> host (SNI) but **not** the prompt body. Sentinel therefore does *destination-tier
> enforcement* on the network path, and runs *content classification* on the
> clipboard / file / ES vectors where plaintext is available. This is stated
> plainly rather than implying the regex pack inspects encrypted ChatGPT traffic.

## Build & run

Requires Swift 6 (Xcode 16 / a Swift 6 toolchain).

```bash
swift build
swift test            # needs XCTest — run under a full Xcode toolchain:
                      # DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

### CLI

```bash
# Scan a file or stdin; classify the destination; print the verdict.
echo 'my key is sk-ant-api03-AAAA1111BBBB2222CCCC3333DDDD4444EEEE' \
  | swift run dlpctl scan --host chatgpt.com

swift run dlpctl scan secrets.env --host claude.ai
swift run dlpctl watch            # live clipboard protection (redacts/clears on hit)
swift run dlpctl patterns --lint  # verify every pattern compiles
swift run dlpctl services         # list recognized AI services + risk tiers
swift run dlpctl policy           # show the default enforcement policy
swift run dlpctl audit ~/Library/Logs/SentinelDLP/audit.jsonl
```

`scan` exits non-zero when egress would be blocked, so it drops into CI/git hooks.

### Menu-bar agent

```bash
swift run SentinelAgent      # status-bar item + live clipboard protection + audit log
```

## Policy model

A policy is an ordered list of rules; the **first match wins**. Each rule ANDs
finding-level conditions (data type, category, min severity/confidence, bulk
count thresholds) with context conditions (destination tier/service, channel,
source-app glob, user group, byte count) and resolves to an action:
`allow · audit · redact · warn · block · quarantine`.

```jsonc
{
  "id": "block-secrets",
  "name": "Block credentials & secrets",
  "conditions": { "categories": ["credential", "sourceSecret"], "minConfidence": "medium" },
  "action": "block",
  "message": "API keys and private keys must never be sent to AI services."
}
```

The built-in `enterpriseDefault` policy blocks secrets and critical national
IDs, blocks forbidden destinations and bulk-PII exfiltration, warns on financial
& health data, redacts ordinary PII, and audits all shadow-AI usage. Start in
`monitor` mode (every block downgrades to audit) for a frictionless rollout.

## Deployment

See [`packaging/`](packaging/) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md):

- Entitlements for the app + NetworkExtension + Endpoint Security targets.
- Info.plist templates (`LSUIElement`, `NSExtension` registration).
- An **MDM `.mobileconfig`** that silently pre-approves the system extension,
  enables the content filter, grants TCC, and auto-launches the agent.
- `build-and-sign.sh` — assemble, codesign (hardened runtime), and notarize.

## Project layout

```
Sources/
  DLPCore/                 Detection + policy + redaction + audit (pure, portable, tested)
    Detection/             Validators, RegexDetector, NL NER, ContextBooster, DetectionEngine
    Policy/                Policy model, PolicyEngine, DefaultPolicy, RiskScorer
    Classification/        AI-service catalog + DestinationClassifier
    Redaction/ · Audit/    Redactor; JSONL/CEF sinks
    Resources/             patterns.json (61), ai-services.json (20)
  DLPDaemon/               ClipboardMonitor, FileSystemMonitor (FSEvents), DLPService
  dlpctl/                  CLI (scan / watch / patterns / services / policy / audit)
  SentinelAgent/           SwiftUI menu-bar agent
  SentinelNetworkFilter/   NEFilterDataProvider + system-extension activation
extensions/EndpointSecurity/  ES reference source (built via Xcode)
packaging/                 entitlements, Info.plists, MDM profile, sign/notarize script
Tests/DLPCoreTests/        70 tests: validators, patterns, policy, redaction, classifier, audit
```

## Security & privacy model

- Detection is **on-device**; no content is sent anywhere by Sentinel itself.
- Audit records contain **masked** values + fingerprints only — never plaintext.
- `failMode` lets you choose availability (`open`) vs protection (`closed`) on
  internal error. Malformed operator-supplied rules are quarantined, not fatal.
- Threat model, bypass analysis, and SIEM integration: see
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## License

MIT — see [LICENSE](LICENSE).
