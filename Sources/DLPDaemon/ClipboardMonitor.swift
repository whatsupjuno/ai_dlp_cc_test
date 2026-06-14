import Foundation
import DLPCore
import AppKit

/// Watches the system pasteboard for new text. When a user copies something —
/// the precursor to pasting it into a web AI tool — we get the chance to inspect
/// it before it ever leaves the machine. Requires **no** entitlements or system
/// extension, which makes it the most portable enforcement vector (and the live
/// demo of the whole pipeline).
///
/// Implementation: a `DispatchSourceTimer` polls `NSPasteboard.changeCount`
/// (cheap, an integer compare) a few times per second. We deliberately do not
/// add ourselves as a pasteboard *owner* so we never interfere with normal copy
/// / paste; we only read.
public final class ClipboardMonitor: Monitor, @unchecked Sendable {
    public let id = "clipboard"

    private let pasteboard: NSPasteboard
    private let interval: TimeInterval
    private let handler: @Sendable (MonitoredPayload) -> Void
    private let queue = DispatchQueue(label: "dlp.monitor.clipboard")

    private var timer: DispatchSourceTimer?
    private var lastChangeCount: Int

    public init(
        pasteboard: NSPasteboard = .general,
        interval: TimeInterval = 0.25,
        handler: @escaping @Sendable (MonitoredPayload) -> Void
    ) {
        self.pasteboard = pasteboard
        self.interval = interval
        self.handler = handler
        // Seed with the current count so we don't fire on whatever is already
        // on the clipboard at launch.
        self.lastChangeCount = pasteboard.changeCount
    }

    public func start() throws {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + interval, repeating: interval, leeway: .milliseconds(50))
        t.setEventHandler { [weak self] in self?.poll() }
        timer = t
        t.resume()
    }

    public func stop() {
        timer?.cancel()
        timer = nil
    }

    private func poll() {
        let current = pasteboard.changeCount
        guard current != lastChangeCount else { return }
        lastChangeCount = current

        guard let text = pasteboard.string(forType: .string), !text.isEmpty else { return }
        let app = NSWorkspace.shared.frontmostApplication?.bundleIdentifier
        handler(MonitoredPayload(text: text, channel: .clipboard, sourceApp: app, origin: "pasteboard"))
    }

    /// Replace the clipboard contents — used to enforce a `redact` verdict on the
    /// clipboard vector (swap the secret for its sanitized form) or to clear it
    /// on `block`. Updates `lastChangeCount` so our own write doesn't re-trigger
    /// inspection on the next poll.
    public func replaceClipboard(with newValue: String) {
        pasteboard.clearContents()
        pasteboard.setString(newValue, forType: .string)
        lastChangeCount = pasteboard.changeCount
    }
}
