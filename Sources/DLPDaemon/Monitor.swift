import Foundation
import DLPCore

/// A long-running source of inspectable content (clipboard, filesystem, …).
/// Monitors translate a host-OS signal into a `MonitoredPayload` and hand it to
/// the `DLPService`, which runs it through the shared `DLPEngine`.
public protocol Monitor: AnyObject, Sendable {
    var id: String { get }
    /// Begin observing. Throws if the underlying OS resource can't be acquired.
    func start() throws
    /// Stop observing and release resources. Safe to call multiple times.
    func stop()
}

/// A unit of content surfaced by a monitor, ready for inspection.
public struct MonitoredPayload: Sendable {
    public let text: String
    public let channel: Channel
    public let sourceApp: String?
    /// Optional origin description (file path, pasteboard, …) for logging.
    public let origin: String?

    public init(text: String, channel: Channel, sourceApp: String? = nil, origin: String? = nil) {
        self.text = text
        self.channel = channel
        self.sourceApp = sourceApp
        self.origin = origin
    }
}
