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

    /// The shared DLP brain. Built from the bundled pattern/service packs; an
    /// MDM push can replace the policy via `applySettings`.
    private let classifier = DestinationClassifier()
    private let engine = FilterDataProvider.makeEngine()

    private let maxAccumulate = 64 * 1024

    /// Per-flow outbound state. We HOLD bytes (pass 0) while peeking so a secret
    /// split across `handleOutboundData` callbacks is never partially released
    /// before the combined buffer is recognized. `seen` tracks the highest
    /// absolute offset accumulated, so a cumulative/re-delivered window isn't
    /// double-counted regardless of how the OS chunks the stream.
    private struct FlowState { var buffer = Data(); var seen = 0 }
    private let stateLock = NSLock()
    private var flows: [String: FlowState] = [:]

    /// Build the engine WITH an audit sink so network-side verdicts reach the
    /// audit trail. The sink writes into the shared App Group container that the
    /// containing app / SIEM forwarder reads; if it is unavailable (unit tests,
    /// missing entitlement) we degrade to no sink rather than failing.
    static func makeEngine() -> DLPEngine {
        DLPEngine(configuration: DLPConfiguration(maxInspectLength: 64 * 1024),
                  auditSink: makeAuditSink())
    }

    static func makeAuditSink() -> AuditSink? {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.sentinel.dlp") else { return nil }
        let url = container.appendingPathComponent("Logs/network-audit.jsonl")
        return try? JSONLFileAuditSink(url: url)
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
            // Forbidden AI service — never allow the connection.
            return .drop()

        case .sanctioned, .unknown:
            // Approved or not-an-AI-service: pass without inspection overhead.
            return .allow()

        case .monitored, .unsanctioned:
            // Shadow / monitored AI: allow the connection but request outbound
            // bytes so we can (a) record the egress and (b) inspect any plaintext.
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

        let decision = Self.decideOutbound(buffer: buffer, maxAccumulate: maxAccumulate) { text in
            // "Sensitive" = anything a content filter can't apply in-place
            // (redact/warn) or that must be stopped (block/quarantine).
            let verdict = self.engine.inspect(text, channel: .network, host: host, sourceApp: nil)
            return verdict.action != .allow && verdict.action != .audit
        }

        switch decision {
        case .allow:
            // Release everything buffered + the rest of the flow, stop inspecting.
            clear(key)
            return .allow()
        case .drop:
            // Fail safe: a content filter cannot rewrite bytes or prompt the
            // user, so a redact/warn/block verdict drops the (still-held) flow.
            clear(key)
            return .drop()
        case let .hold(peekBytes):
            // Pass NOTHING yet (passBytes: 0) so a secret spanning the next
            // callback boundary can still be dropped; ask to see more.
            return NEFilterDataVerdict(passBytes: 0, peekBytes: peekBytes)
        }
    }

    /// Pure, testable decision over the cumulative outbound buffer. Decoupled
    /// from NetworkExtension types so the hold/drop/allow logic is unit-tested.
    enum OutboundDecision: Equatable {
        case allow                  // release held + subsequent bytes, stop
        case drop                   // drop the held flow
        case hold(peekBytes: Int)   // pass 0, request to see up to peekBytes total
    }

    static func decideOutbound(
        buffer: Data, maxAccumulate: Int, isSensitive: (String) -> Bool
    ) -> OutboundDecision {
        guard !buffer.isEmpty else { return .hold(peekBytes: maxAccumulate) }
        // Lossy decode so a multibyte char split at the buffer end becomes U+FFFD
        // rather than failing the whole decode; TLS/binary still reads as noise.
        let text = String(decoding: buffer, as: UTF8.self)
        guard Self.looksLikeText(text) else { return .allow }   // ciphertext/binary — don't stall
        if isSensitive(text) { return .drop }
        if buffer.count >= maxAccumulate { return .allow }       // inspected up to the cap; release
        return .hold(peekBytes: maxAccumulate)                   // keep buffering for split secrets
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
