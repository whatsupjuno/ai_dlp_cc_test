import Foundation

/// How sensitive the organization considers a given egress destination.
public enum RiskTier: String, Codable, CaseIterable, Comparable, Sendable {
    /// Approved for use; data egress is acceptable subject to policy.
    case sanctioned
    /// Permitted but every interaction is logged/inspected.
    case monitored
    /// Not approved (shadow AI); high scrutiny.
    case unsanctioned
    /// Explicitly forbidden.
    case blocked
    /// Destination not recognized as an AI service.
    case unknown

    public var rank: Int {
        switch self {
        case .sanctioned: return 0
        case .monitored: return 1
        case .unknown: return 2
        case .unsanctioned: return 3
        case .blocked: return 4
        }
    }

    public static func < (lhs: RiskTier, rhs: RiskTier) -> Bool { lhs.rank < rhs.rank }
}

/// A recognized AI / LLM service that data might be sent to.
public struct AIService: Codable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let vendor: String
    public let defaultTier: RiskTier

    public init(id: String, name: String, vendor: String, defaultTier: RiskTier) {
        self.id = id
        self.name = name
        self.vendor = vendor
        self.defaultTier = defaultTier
    }
}

/// The classified destination of an inspected payload.
public struct Destination: Codable, Hashable, Sendable {
    /// The hostname the payload is being sent to, if known.
    public let host: String?
    /// The recognized AI service, if the host matched the catalog.
    public let service: AIService?
    /// Effective risk tier (service default, possibly overridden by policy/config).
    public let tier: RiskTier
    /// Whether this looks like a browser web session vs. a direct API call.
    public let isAPIEndpoint: Bool

    public init(host: String?, service: AIService?, tier: RiskTier, isAPIEndpoint: Bool) {
        self.host = host
        self.service = service
        self.tier = tier
        self.isAPIEndpoint = isAPIEndpoint
    }

    /// A destination representing "we don't know / not network-bound" (e.g. a
    /// clipboard inspection before the user has pasted anywhere).
    public static let unknown = Destination(host: nil, service: nil, tier: .unknown, isAPIEndpoint: false)

    public var displayName: String {
        if let service { return service.name }
        if let host { return host }
        return "Unknown destination"
    }
}
