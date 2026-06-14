import Foundation

/// The channel through which content is leaving (or attempting to leave) the
/// endpoint. Different channels carry different default risk and are handled by
/// different monitors.
public enum Channel: String, Codable, CaseIterable, Sendable {
    case clipboard      // user copied something (potential paste into an AI tool)
    case network        // outbound HTTP(S) flow seen by the content filter
    case file           // file written / opened (FSEvents / Endpoint Security)
    case manualScan     // explicit scan request (CLI / API)
    case browserUpload  // multipart/form upload or large POST body

    public var displayName: String {
        switch self {
        case .clipboard: return "Clipboard"
        case .network: return "Network"
        case .file: return "File"
        case .manualScan: return "Manual Scan"
        case .browserUpload: return "Browser Upload"
        }
    }
}

/// Everything the policy engine needs to know about an inspection besides the
/// content itself. Deliberately a value type — cheap to pass to monitors / XPC.
public struct InspectionContext: Codable, Hashable, Sendable {
    /// The egress channel.
    public let channel: Channel
    /// Where the content is headed, if known (network flows / classified clipboard).
    public let destination: Destination
    /// Bundle identifier of the foreground / originating application, if known
    /// (e.g. `com.google.Chrome`, `com.openai.chat`).
    public let sourceApp: String?
    /// The local user the action is attributed to.
    public let user: String
    /// Best-effort group/department membership, used by group-scoped rules.
    public let userGroups: [String]
    /// Size of the inspected payload in bytes (may exceed inspected prefix).
    public let byteCount: Int
    /// Wall-clock time of inspection.
    public let timestamp: Date

    public init(
        channel: Channel,
        destination: Destination = .unknown,
        sourceApp: String? = nil,
        user: String = NSUserName(),
        userGroups: [String] = [],
        byteCount: Int = 0,
        timestamp: Date = Date()
    ) {
        self.channel = channel
        self.destination = destination
        self.sourceApp = sourceApp
        self.user = user
        self.userGroups = userGroups
        self.byteCount = byteCount
        self.timestamp = timestamp
    }
}
