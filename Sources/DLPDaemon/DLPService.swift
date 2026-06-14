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
    /// Runtime gate for clipboard enforcement, toggleable from the UI without a
    /// restart. Protected by `lock`.
    private var enforcementEnabled: Bool

    private var monitors: [Monitor] = []
    private var clipboardMonitor: ClipboardMonitor?

    /// Invoked on every verdict that has findings or a non-allow action.
    public var onVerdict: (@Sendable (DLPVerdict, MonitoredPayload) -> Void)?

    public init(engine: DLPEngine, configuration: Configuration = Configuration()) {
        self.engine = engine
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
        let verdict = currentEngine().inspect(
            payload.text,
            channel: payload.channel,
            host: nil,
            sourceApp: payload.sourceApp
        )
        enforce(verdict, for: payload)
        if verdict.hasFindings || verdict.action != .allow {
            onVerdict?(verdict, payload)
        }
        return verdict
    }

    private func enforce(_ verdict: DLPVerdict, for payload: MonitoredPayload) {
        guard payload.channel == .clipboard,
              isEnforcing,
              let clipboard = clipboardMonitor else { return }

        switch verdict.action {
        case .redact:
            if let redacted = verdict.redactedContent {
                clipboard.replaceClipboard(with: redacted)
            }
        case .block, .quarantine:
            // Remove the sensitive value from the clipboard so it can't be pasted.
            clipboard.replaceClipboard(with: "⚠︎ Sentinel DLP removed sensitive data from your clipboard.")
        case .warn:
            // `warn` permits only after explicit justification. The headless
            // service can't show that prompt synchronously, so it fails safe:
            // remove the value from the clipboard (it must not stay silently
            // pasteable) and surface it via onVerdict so the menu-bar app can run
            // the justification flow and restore the content on confirmation.
            clipboard.replaceClipboard(with: "⚠︎ Sentinel DLP held sensitive data — sharing this with an AI tool requires confirmation.")
        case .allow, .audit:
            break // nothing to enforce on the clipboard
        }
    }
}
