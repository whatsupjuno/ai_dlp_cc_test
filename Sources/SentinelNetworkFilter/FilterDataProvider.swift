import Foundation
import NetworkExtension
import DLPCore

/// The Sentinel content-filter system extension (`NEFilterDataProvider`).
///
/// ## What this can and cannot do (read this before judging coverage)
/// A macOS content filter sees socket **flows** and their byte stream. For the
/// HTTPS endpoints every AI service uses, those bytes are **TLS ciphertext** —
/// the provider can read the destination host (SNI / endpoint) but *not* the
/// plaintext prompt body. Therefore the network vector does **destination-tier
/// enforcement** (block/allow/observe by which AI service the flow targets),
/// while *content* classification (the regex/NER pattern pack) runs on the
/// clipboard and file vectors where plaintext is available. Best-effort content
/// inspection is still attempted here for any plaintext (non-TLS) flow.
///
/// This file compiles against the SDK but must be packaged as a signed system
/// extension with the `com.apple.developer.networking.networkextension`
/// (`content-filter-provider`) entitlement to run. See `packaging/`.
public final class FilterDataProvider: NEFilterDataProvider {

    /// The shared DLP brain. NOTE: built WITHOUT an audit sink — the per-chunk
    /// sensitivity checks in handleOutboundData must NOT emit an audit event per
    /// callback. Audits are recorded explicitly: once per flow at the destination
    /// tier (handleNewFlow) and once when a flow is actually dropped for content.
    private let classifier = DestinationClassifier()
    private let engine = DLPEngine(configuration: DLPConfiguration(maxInspectLength: 64 * 1024))
    private let auditSink: AuditSink? = FilterDataProvider.makeAuditSink()

    private let maxAccumulate = 64 * 1024
    /// Forward look-ahead requested per callback while a plaintext body is still
    /// streaming under the cap. It only ever applies to bytes the client has NOT
    /// sent yet, so (unlike a held tail) it can never withhold an already-sent
    /// request tail and deadlock a keep-alive upload.
    private let peekChunk = 4 * 1024

    /// Per-flow accumulated outbound buffer (for cumulative inspection). `seen`
    /// is the highest absolute offset accumulated, so a cumulative/re-delivered
    /// window isn't double-counted regardless of how the OS chunks the stream.
    private struct FlowState {
        var buffer = Data()
        var seen = 0
        // Two independent once-per-flow audit slots: a low-value audit-level
        // finding (e.g. a name) must not consume the slot that records the
        // enforcement verdict (the secret that actually drops the flow).
        var findingAudited = false
        var enforcementAudited = false
    }
    private let stateLock = NSLock()
    private var flows: [String: FlowState] = [:]

    /// The audit sink writes into the shared App Group container that the
    /// containing app / SIEM forwarder reads; if it is unavailable (unit tests,
    /// missing entitlement) we degrade to no sink rather than failing.
    static func makeAuditSink() -> AuditSink? {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.sentinel.dlp") else { return nil }
        let url = container.appendingPathComponent("Logs/network-audit.jsonl")
        return try? JSONLFileAuditSink(url: url)
    }

    /// Record ONE destination-tier audit event for a flow (the engine has no
    /// sink, so `inspect` doesn't auto-record — we do it explicitly).
    private func recordTierAudit(host: String) {
        guard let auditSink else { return }
        auditSink.record(AuditEvent(verdict: engine.inspect("", channel: .network, host: host, sourceApp: nil)))
    }

    private enum AuditSlot { case finding, enforcement }

    /// Record a content verdict once per flow per slot. The `finding` slot covers
    /// the first audit-level finding; the `enforcement` slot covers the first
    /// block/redact/warn/quarantine verdict — kept separate so a low-value finding
    /// can't suppress the secret-bearing verdict that drops the flow.
    private func auditOnce(_ verdict: DLPVerdict, for key: String, slot: AuditSlot) {
        stateLock.lock()
        var st = flows[key] ?? FlowState()
        let already: Bool
        switch slot {
        case .finding:     already = st.findingAudited;     st.findingAudited = true
        case .enforcement: already = st.enforcementAudited; st.enforcementAudited = true
        }
        flows[key] = st
        stateLock.unlock()
        if !already { auditSink?.record(AuditEvent(verdict: verdict)) }
    }

    // MARK: - Lifecycle

    public override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Filtering rules can be installed here (e.g. only filter TCP 443/80).
        // We filter all new flows and decide per-flow in `handleNewFlow`.
        completionHandler(nil)
    }

    public override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stateLock.lock(); flows.removeAll(); stateLock.unlock()
        completionHandler()
    }

    // MARK: - Flow handling

    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let host = Self.hostname(for: flow) else { return .allow() }
        let destination = classifier.classify(host: host)

        switch destination.tier {
        case .blocked:
            // Record the denied egress to a forbidden AI service BEFORE dropping —
            // this is the highest-risk policy path and must be visible in
            // audit/SIEM (block-forbidden-destination fires on the empty body).
            recordTierAudit(host: host)
            return .drop()

        case .sanctioned, .unknown:
            // Approved or not-an-AI-service: pass without inspection overhead.
            return .allow()

        case .monitored, .unsanctioned:
            // Record the destination-tier egress ONCE now, at flow creation. The
            // body is almost always TLS ciphertext we can never inspect, so without
            // this the audit-unsanctioned / monitored policy would never fire and
            // network-audit.jsonl would stay empty for normal ChatGPT/Claude use.
            recordTierAudit(host: host)
            // Then request outbound bytes so we can also inspect any plaintext.
            return .filterDataVerdict(
                withFilterInbound: false,
                peekInboundBytes: 0,
                filterOutbound: true,
                peekOutboundBytes: maxAccumulate
            )
        }
    }

    public override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        let key = Self.key(for: flow)
        let buffer = accumulate(readBytes, offset: offset, for: key)
        let host = Self.hostname(for: flow)

        // The engine has no sink, so inspect() here records nothing by itself.
        // We audit the FIRST findings-bearing content verdict once per flow — this
        // covers audit-level findings (allowed) as well as drops, without one
        // event per clean chunk.
        let decision = Self.decideOutbound(
            buffer: buffer, windowCount: readBytes.count, peekChunk: peekChunk, maxAccumulate: maxAccumulate
        ) { text in
            let verdict = self.engine.inspect(text, channel: .network, host: host, sourceApp: nil)
            // "Sensitive" = anything a content filter can't apply in-place
            // (redact/warn) or that must be stopped (block/quarantine).
            let isEnforcement = verdict.action != .allow && verdict.action != .audit
            if isEnforcement {
                // The network filter can only DROP — it can't redact or prompt —
                // so record the action as BLOCK regardless of whether the policy
                // said redact/warn/block. Otherwise SIEM shows REDACT/WARN for a
                // flow that was actually blocked on the wire.
                let asBlocked = DLPVerdict(
                    action: .block, findings: verdict.findings, matchedRuleID: verdict.matchedRuleID,
                    reason: verdict.reason, redactedContent: nil,
                    riskScore: verdict.riskScore, context: verdict.context)
                self.auditOnce(asBlocked, for: key, slot: .enforcement)
            } else if verdict.hasFindings {
                // A low-value audit-level finding (e.g. a name). Clean chunks have
                // no findings, so they never consume this slot.
                self.auditOnce(verdict, for: key, slot: .finding)
            }
            return isEnforcement
        }

        switch decision {
        case .allowAll:
            // Ciphertext, or inspected up to the cap: release + stop inspecting.
            clear(key)
            return .allow()
        case .drop:
            // Fail safe: a content filter cannot rewrite bytes or prompt the user,
            // so any non-allow/audit verdict drops the flow. The causing verdict
            // was already recorded via the enforcement audit slot above.
            clear(key)
            return .drop()
        case let .passWindow(passBytes, peekBytes):
            // Release the ENTIRE current window synchronously (never withhold an
            // already-sent byte → no keep-alive deadlock) and request a small
            // forward look-ahead so we keep inspecting if the body keeps streaming.
            return NEFilterDataVerdict(passBytes: passBytes, peekBytes: peekBytes)
        }
    }

    // LIMITATION (network content path — by design; see PR & docs/ARCHITECTURE.md):
    // We release every inspected outbound window synchronously (passBytes == the
    // whole current window) and NEVER hold a trailing slice. peekBytes is a
    // forward look-ahead only — per NEFilterDataProvider.h the next callback fires
    // only when the client sends more bytes, so withholding an already-sent tail
    // (passBytes < window) would deadlock a keep-alive upload, which we refuse to
    // do. Consequences: (1) a plaintext secret split across an outbound window
    // boundary can leak its first fragment before the flow is dropped (the flow is
    // still killed, but bytes are already out); (2) bodies past the 64 KiB cap pass
    // unclassified; (3) TLS traffic is never content-inspected on the wire and is
    // governed solely by destination-tier enforcement in handleNewFlow — plaintext
    // content DLP authoritatively lives on the clipboard/file/ES vectors. The
    // verdict byte-semantics are validated against the SDK header + unit tests on
    // decideOutbound only; re-verify on a signed build on real hardware before any
    // drop/enforcement ships on the network path (prefer audit-only until then).
    // If window-boundary split coverage is later mandated, the ONLY option is the
    // async pauseVerdict + resumeFlow path with an out-of-band idle timer.

    /// Pure, testable decision over the cumulative outbound buffer. Decoupled
    /// from NetworkExtension types so the allow/drop/pass logic is unit-tested.
    enum OutboundDecision: Equatable {
        case allowAll                                  // release everything, stop inspecting
        case drop                                      // drop the flow (fail safe)
        case passWindow(passBytes: Int, peekBytes: Int) // release this window, peek ahead
    }

    static func decideOutbound(
        buffer: Data, windowCount: Int, peekChunk: Int, maxAccumulate: Int,
        isSensitive: (String) -> Bool
    ) -> OutboundDecision {
        guard !buffer.isEmpty else { return .passWindow(passBytes: 0, peekBytes: peekChunk) }
        // Lossy decode so a multibyte char split at the buffer end becomes U+FFFD
        // rather than failing the whole decode; TLS/binary still reads as noise.
        let text = String(decoding: buffer, as: UTF8.self)
        guard Self.looksLikeText(text) else { return .allowAll }   // ciphertext/binary — don't stall
        if isSensitive(text) { return .drop }
        if buffer.count >= maxAccumulate { return .allowAll }      // inspected up to the cap; release
        // Clean and under the cap: pass the whole current window, peek a little
        // further so subsequent streamed bytes are still inspected.
        return .passWindow(passBytes: windowCount, peekBytes: peekChunk)
    }

    public override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        clear(Self.key(for: flow))
        return .allow()
    }

    // MARK: - Accumulation helpers

    /// Append the genuinely-new portion of `data` to the flow buffer (bounded by
    /// `maxAccumulate`), de-duplicating any bytes at/below `seen` so both
    /// "new-window" and "cumulative re-delivery" chunking styles are handled.
    private func accumulate(_ data: Data, offset: Int, for key: String) -> Data {
        stateLock.lock(); defer { stateLock.unlock() }
        var st = flows[key] ?? FlowState()
        let skip = max(0, st.seen - offset)
        if skip < data.count {
            let fresh = data.dropFirst(skip)
            let room = maxAccumulate - st.buffer.count
            if room > 0 { st.buffer.append(fresh.prefix(room)) }
            st.seen = max(st.seen, offset + data.count)
            flows[key] = st
        }
        return st.buffer
    }

    private func clear(_ key: String) {
        stateLock.lock(); flows[key] = nil; stateLock.unlock()
    }

    // MARK: - Flow introspection

    static func key(for flow: NEFilterFlow) -> String {
        flow.identifier.uuidString
    }

    static func hostname(for flow: NEFilterFlow) -> String? {
        if let socket = flow as? NEFilterSocketFlow {
            if let host = socket.remoteHostname, !host.isEmpty { return host }
            if let endpoint = socket.remoteEndpoint as? NWHostEndpoint { return endpoint.hostname }
        }
        if let url = flow.url, let host = url.host { return host }
        return nil
    }

    static func sourceApp(for flow: NEFilterFlow) -> String? {
        // On macOS the source app is identified by an audit token (not a bundle
        // id as on iOS). Resolving it to a bundle identifier requires
        // `SecCodeCopySigningInformation` over the token; left nil here to keep
        // DLPCore portable. The clipboard/file vectors carry the bundle id.
        nil
    }

    /// Heuristic: avoid running the full engine over obvious binary blobs.
    static func looksLikeText(_ s: String) -> Bool {
        guard !s.isEmpty else { return false }
        let sample = s.prefix(2048)
        let control = sample.unicodeScalars.filter { $0.value < 9 || ($0.value > 13 && $0.value < 32) }.count
        return Double(control) / Double(sample.count) < 0.02
    }
}
