import Foundation
import DLPCore

/// Runtime orchestrator: owns the shared `DLPEngine`, wires up the monitors,
/// runs every surfaced payload through the engine, applies channel-appropriate
/// enforcement, and notifies observers (CLI / menu-bar app).
///
/// The engine is held behind a lock so policy can be hot-swapped (e.g. an MDM
/// push) without restarting the agent or losing in-flight monitors.
public final class DLPService: @unchecked Sendable {

    /// How aggressively to act on the clipboard vector (the one place we can
    /// enforce without a system extension).
    public enum ClipboardEnforcement: String, Sendable {
        case off        // observe + audit only
        case enforce    // redact in place, and clear the clipboard on block
    }

    public struct Configuration: Sendable {
        public var enableClipboard: Bool
        public var clipboardInterval: TimeInterval
        public var clipboardEnforcement: ClipboardEnforcement
        public var enableFileMonitoring: Bool
        public var watchedPaths: [String]

        public init(
            enableClipboard: Bool = true,
            clipboardInterval: TimeInterval = 0.25,
            clipboardEnforcement: ClipboardEnforcement = .enforce,
            enableFileMonitoring: Bool = false,
            watchedPaths: [String] = []
        ) {
            self.enableClipboard = enableClipboard
            self.clipboardInterval = clipboardInterval
            self.clipboardEnforcement = clipboardEnforcement
            self.enableFileMonitoring = enableFileMonitoring
            self.watchedPaths = watchedPaths
        }
    }

    private let lock = NSLock()
    private var engine: DLPEngine
    private let config: Configuration
    /// The service owns auditing (not the engine) so the recorded action reflects
    /// what was ACTUALLY enforced per channel. Pass an engine built WITHOUT a sink.
    private let auditSink: AuditSink?
    /// Runtime gate for clipboard enforcement, toggleable from the UI without a
    /// restart. Protected by `lock`.
    private var enforcementEnabled: Bool

    private var monitors: [Monitor] = []
    private var clipboardMonitor: ClipboardMonitor?

    /// Invoked on every verdict that has findings or a non-allow action. The
    /// third argument is the pasteboard change-count captured immediately after
    /// the clipboard was replaced (for warn/redact/block), or `nil` — callers use
    /// it to bind a later restore to exactly this clipboard state without racing.
    public var onVerdict: (@Sendable (DLPVerdict, MonitoredPayload, Int?) -> Void)?

    public init(engine: DLPEngine, auditSink: AuditSink? = nil, configuration: Configuration = Configuration()) {
        self.engine = engine
        self.auditSink = auditSink
        self.config = configuration
        self.enforcementEnabled = configuration.clipboardEnforcement == .enforce
    }

    /// Enable/disable active clipboard enforcement at runtime (observe vs enforce).
    public func setEnforcement(_ enabled: Bool) {
        lock.lock(); defer { lock.unlock() }
        enforcementEnabled = enabled
    }

    public var isEnforcing: Bool {
        lock.lock(); defer { lock.unlock() }
        return enforcementEnabled
    }

    /// Restore content to the clipboard after the user justifies a `.warn`
    /// verdict — but only if the clipboard is still at `expectedChangeCount` (the
    /// count captured when the warning was raised), checked atomically on the
    /// monitor queue so a newer clipboard item is never overwritten. The restored
    /// value isn't re-inspected (the change-count update suppresses the next poll).
    /// Returns whether the restore happened.
    @discardableResult
    public func confirmAndRestore(_ text: String, expectedChangeCount: Int) -> Bool {
        clipboardMonitor?.restoreIfUnchanged(text, expectedChangeCount: expectedChangeCount) ?? false
    }

    /// Hot-swap the engine (new policy / pattern pack) atomically.
    public func update(engine newEngine: DLPEngine) {
        lock.lock(); defer { lock.unlock() }
        engine = newEngine
    }

    private func currentEngine() -> DLPEngine {
        lock.lock(); defer { lock.unlock() }
        return engine
    }

    // MARK: - Lifecycle

    public func start() throws {
        if config.enableClipboard {
            let cm = ClipboardMonitor(interval: config.clipboardInterval) { [weak self] payload in
                self?.ingest(payload)
            }
            clipboardMonitor = cm
            monitors.append(cm)
        }
        if config.enableFileMonitoring, !config.watchedPaths.isEmpty {
            let fm = FileSystemMonitor(paths: config.watchedPaths) { [weak self] payload in
                self?.ingest(payload)
            }
            monitors.append(fm)
        }

        // Start monitors with rollback: if a later monitor fails to start, stop
        // the ones already running so we don't leave (e.g.) clipboard enforcement
        // active in the background while the caller sees a startup failure.
        var started: [Monitor] = []
        do {
            for m in monitors {
                try m.start()
                started.append(m)
            }
        } catch {
            for m in started.reversed() { m.stop() }
            monitors.removeAll()
            clipboardMonitor = nil
            throw error
        }
    }

    public func stop() {
        for m in monitors { m.stop() }
        monitors.removeAll()
        clipboardMonitor = nil
    }

    // MARK: - Inspection

    /// Inspect a payload, apply enforcement, and notify observers. Returns the
    /// verdict so callers (CLI) can render it.
    @discardableResult
    public func ingest(_ payload: MonitoredPayload) -> DLPVerdict {
        // The engine has no sink (see init), so this does not auto-audit.
        let raw = currentEngine().inspect(
            payload.text,
            channel: payload.channel,
            host: nil,
            sourceApp: payload.sourceApp
        )
        // Report the action that was ACTUALLY applied. Only the clipboard vector
        // enforces (redact/block/warn); the filesystem vector is observe-only, so
        // a block/redact there is downgraded to audit — neither users nor SIEM
        // should see a false "blocked" for a file that was never touched.
        let verdict = Self.effectiveVerdict(raw, channel: payload.channel)
        let heldChangeCount = enforce(verdict, for: payload)
        if verdict.hasFindings || verdict.action != .allow {
            auditSink?.record(AuditEvent(verdict: verdict))
            onVerdict?(verdict, payload, heldChangeCount)
        }
        return verdict
    }

    /// Downgrade an enforcement action (block/redact/warn/quarantine) to `.audit`
    /// for channels that don't actually enforce (everything except the clipboard),
    /// so the reported/audited action matches what really happened on the endpoint.
    static func effectiveVerdict(_ v: DLPVerdict, channel: Channel) -> DLPVerdict {
        guard channel != .clipboard, v.action != .allow, v.action != .audit else { return v }
        return DLPVerdict(
            action: .audit, findings: v.findings, matchedRuleID: v.matchedRuleID,
            reason: "Observed (\(channel.displayName) vector is audit-only, not enforced): \(v.reason)",
            redactedContent: nil, riskScore: v.riskScore, context: v.context)
    }

    /// Apply clipboard enforcement. Returns the pasteboard change-count captured
    /// immediately after replacing the clipboard (so the caller can bind a later
    /// restore to this exact state), or `nil` if the clipboard wasn't touched.
    @discardableResult
    private func enforce(_ verdict: DLPVerdict, for payload: MonitoredPayload) -> Int? {
        guard payload.channel == .clipboard,
              isEnforcing,
              let clipboard = clipboardMonitor else { return nil }

        switch verdict.action {
        case .redact:
            guard let redacted = verdict.redactedContent else { return nil }
            return clipboard.replaceClipboard(with: redacted)
        case .block, .quarantine:
            // Remove the sensitive value from the clipboard so it can't be pasted.
            return clipboard.replaceClipboard(with: "⚠︎ Sentinel DLP removed sensitive data from your clipboard.")
        case .warn:
            // `warn` permits only after explicit justification. The headless
            // service can't show that prompt synchronously, so it fails safe:
            // remove the value from the clipboard (it must not stay silently
            // pasteable) and surface it via onVerdict — with the post-replace
            // change-count — so the menu-bar app can run the justification flow
            // and restore the content on confirmation without a TOCTOU race.
            return clipboard.replaceClipboard(with: "⚠︎ Sentinel DLP held sensitive data — sharing this with an AI tool requires confirmation.")
        case .allow, .audit:
            return nil // nothing to enforce on the clipboard
        }
    }
}
