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
    private let engine = DLPEngine(configuration: DLPConfiguration(maxInspectLength: 64 * 1024))

    /// Per-flow outbound accumulation for best-effort plaintext inspection.
    private let accumLock = NSLock()
    private var accumulators: [String: Data] = [:]
    private let maxAccumulate = 64 * 1024

    // MARK: - Lifecycle

    public override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Filtering rules can be installed here (e.g. only filter TCP 443/80).
        // We filter all new flows and decide per-flow in `handleNewFlow`.
        completionHandler(nil)
    }

    public override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        accumLock.lock(); accumulators.removeAll(); accumLock.unlock()
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
        let buffer = append(readBytes, for: key)
        let host = Self.hostname(for: flow)

        let decision = Self.decideOutbound(
            buffer: buffer, chunkBytes: readBytes.count, offset: offset, maxAccumulate: maxAccumulate
        ) { text in
            // "Sensitive" = anything a content filter can't apply in-place
            // (redact/warn) or that must be stopped (block/quarantine).
            let verdict = self.engine.inspect(text, channel: .network, host: host, sourceApp: nil)
            return verdict.action != .allow && verdict.action != .audit
        }

        switch decision {
        case .allow:
            clear(key)
            return .allow()
        case .drop:
            // Fail safe: a content filter cannot rewrite bytes or prompt the
            // user, so a redact/warn/block verdict must drop the flow.
            clear(key)
            return .drop()
        case let .keepPeeking(passBytes, peekBytes):
            // Pass the inspected bytes but keep receiving more — the sensitive
            // content may appear in a later chunk after a clean prefix.
            return NEFilterDataVerdict(passBytes: passBytes, peekBytes: peekBytes)
        }
    }

    /// Pure, testable decision for an outbound chunk. Decoupled from the
    /// NetworkExtension types so the peek/drop/allow logic can be unit-tested.
    enum OutboundDecision: Equatable {
        case allow
        case drop
        case keepPeeking(passBytes: Int, peekBytes: Int)
    }

    static func decideOutbound(
        buffer: Data, chunkBytes: Int, offset: Int, maxAccumulate: Int,
        isSensitive: (String) -> Bool
    ) -> OutboundDecision {
        if let text = String(data: buffer, encoding: .utf8), looksLikeText(text) {
            if isSensitive(text) { return .drop }
            if buffer.count >= maxAccumulate { return .allow }   // cap reached, stop inspecting
            return .keepPeeking(passBytes: chunkBytes, peekBytes: maxAccumulate - buffer.count)
        }
        // Undecodable buffer.
        if offset == 0 { return .allow }                          // first chunk not UTF-8 ⇒ TLS ciphertext
        if buffer.count >= maxAccumulate { return .allow }
        // Possibly a multibyte sequence split across chunks — keep peeking.
        return .keepPeeking(passBytes: chunkBytes, peekBytes: maxAccumulate - buffer.count)
    }

    public override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        clear(Self.key(for: flow))
        return .allow()
    }

    // MARK: - Accumulation helpers

    private func append(_ data: Data, for key: String) -> Data {
        accumLock.lock(); defer { accumLock.unlock() }
        var current = accumulators[key] ?? Data()
        if current.count < maxAccumulate {
            current.append(data.prefix(maxAccumulate - current.count))
            accumulators[key] = current
        }
        return current
    }

    private func clear(_ key: String) {
        accumLock.lock(); accumulators[key] = nil; accumLock.unlock()
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
