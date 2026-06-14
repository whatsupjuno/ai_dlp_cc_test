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
        var built: [Monitor] = []
        var clipboard: ClipboardMonitor?
        if config.enableClipboard {
            let cm = ClipboardMonitor(interval: config.clipboardInterval) { [weak self] payload in
                self?.ingest(payload)
            }
            clipboard = cm
            built.append(cm)
        }
        if config.enableFileMonitoring, !config.watchedPaths.isEmpty {
            built.append(FileSystemMonitor(paths: config.watchedPaths) { [weak self] payload in
                self?.ingest(payload)
            })
        }

        // Start monitors with rollback: if a later monitor fails to start, stop
        // the ones already running so we don't leave (e.g.) clipboard enforcement
        // active in the background while the caller sees a startup failure. Only
        // publish the monitors (under lock) once they have all started.
        var started: [Monitor] = []
        do {
            for m in built {
                try m.start()
                started.append(m)
            }
        } catch {
            for m in started.reversed() { m.stop() }
            throw error
        }
        lock.lock()
        monitors = built
        clipboardMonitor = clipboard
        lock.unlock()
    }

    public func stop() {
        lock.lock()
        let running = monitors
        monitors.removeAll()
        clipboardMonitor = nil
        lock.unlock()
        for m in running { m.stop() }
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
        // Take ONE atomic snapshot of the enforcement state and the clipboard
        // monitor, and use it for BOTH the reported/audited action and the actual
        // application. Reading these twice (once to decide, once to apply) let a
        // mid-ingest toggle — or an absent monitor — make the audit say "block"
        // while nothing was touched. Only the clipboard vector enforces, and only
        // when enforcement is on AND a monitor exists; everything else is
        // observe-only and is downgraded to .audit.
        lock.lock()
        let enforcing = enforcementEnabled
        let clipboard = clipboardMonitor
        lock.unlock()

        let willEnforce = payload.channel == .clipboard && enforcing && clipboard != nil
        let verdict = Self.effectiveVerdict(raw, channel: payload.channel, enforced: willEnforce)

        var heldChangeCount: Int?
        if willEnforce, let clipboard {
            heldChangeCount = applyClipboardEnforcement(verdict, using: clipboard)
        }

        if verdict.hasFindings || verdict.action != .allow {
            auditSink?.record(AuditEvent(verdict: verdict))
            onVerdict?(verdict, payload, heldChangeCount)
        }
        return verdict
    }

    /// Downgrade an enforcement action (block/redact/warn/quarantine) to `.audit`
    /// when it was NOT actually applied — i.e. the filesystem vector (observe-only)
    /// or the clipboard in observe mode (enforcement off) — so the reported/audited
    /// action matches what really happened on the endpoint. `enforced` is true only
    /// when the channel actually applied the action.
    static func effectiveVerdict(_ v: DLPVerdict, channel: Channel, enforced: Bool) -> DLPVerdict {
        guard !enforced, v.action != .allow, v.action != .audit else { return v }
        let why = channel == .clipboard
            ? "observe mode, enforcement off"
            : "\(channel.displayName) vector is audit-only"
        return DLPVerdict(
            action: .audit, findings: v.findings, matchedRuleID: v.matchedRuleID,
            reason: "Observed (\(why), not enforced): \(v.reason)",
            redactedContent: nil, riskScore: v.riskScore, context: v.context)
    }

    /// Apply the clipboard action. Only called when the caller has already
    /// confirmed (atomically) that enforcement is on and a monitor exists, so the
    /// verdict's action here is exactly what gets applied — keeping the reported
    /// action and the actual mutation consistent. Returns the post-replace change-
    /// count (for warn restore binding), or `nil` for allow/audit.
    private func applyClipboardEnforcement(_ verdict: DLPVerdict, using clipboard: ClipboardMonitor) -> Int? {
        switch verdict.action {
        case .redact:
            return verdict.redactedContent.map { clipboard.replaceClipboard(with: $0) }
        case .block, .quarantine:
            // Remove the sensitive value from the clipboard so it can't be pasted.
            return clipboard.replaceClipboard(with: "⚠︎ Sentinel DLP removed sensitive data from your clipboard.")
        case .warn:
            // `warn` permits only after explicit justification. The headless
            // service can't show that prompt synchronously, so it fails safe:
            // remove the value (it must not stay silently pasteable) and surface it
            // via onVerdict — with the post-replace change-count — so the menu-bar
            // app can run the justification flow and restore on confirmation.
            return clipboard.replaceClipboard(with: "⚠︎ Sentinel DLP held sensitive data — sharing this with an AI tool requires confirmation.")
        case .allow, .audit:
            return nil
        }
    }
}
