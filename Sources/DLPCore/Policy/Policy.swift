import Foundation

/// Enforcement posture for the whole policy.
public enum PolicyMode: String, Codable, Sendable {
    /// Observe and audit only; never block or modify (rollout / works-council
    /// friendly). Terminal actions are downgraded to `audit`.
    case monitor
    /// Full enforcement.
    case enforce
}

/// What to do when the engine itself errors (e.g. a detector throws). Security
/// products must choose deliberately between availability and safety.
public enum FailMode: String, Codable, Sendable {
    /// On internal error, allow the traffic (favor availability).
    case open
    /// On internal error, block the traffic (favor data protection).
    case closed
}

/// A per-category count threshold, e.g. "≥ 10 PII findings" (the classic
/// bulk-exfiltration trigger). Kept as an explicit struct so the policy JSON
/// stays clean and readable.
public struct CategoryThreshold: Codable, Hashable, Sendable {
    public let category: DataCategory
    public let count: Int
    public init(category: DataCategory, count: Int) {
        self.category = category
        self.count = count
    }
}

/// The match conditions for a rule. Every non-nil field must hold (logical AND);
/// to express OR, author multiple rules. Finding-level predicates
/// (`dataTypes`, `categories`, `minSeverity`, `minConfidence`) are evaluated
/// against a *single* qualifying finding set so they compose correctly.
public struct RuleConditions: Codable, Hashable, Sendable {
    /// Match if any finding's type id is in this set.
    public var dataTypes: [String]?
    /// Match if any finding's category is in this set.
    public var categories: [DataCategory]?
    /// Match if a qualifying finding's severity is at least this.
    public var minSeverity: Severity?
    /// Match if a qualifying finding's confidence is at least this.
    public var minConfidence: Confidence?
    /// Match if the qualifying finding count is at least this.
    public var minFindings: Int?
    /// Per-category minimum counts (bulk thresholds).
    public var categoryThresholds: [CategoryThreshold]?
    /// Match if the destination risk tier is in this set.
    public var destinationTiers: [RiskTier]?
    /// Match if the destination AI service id is in this set.
    public var services: [String]?
    /// Match if the egress channel is in this set.
    public var channels: [Channel]?
    /// Match if the source app bundle id matches any of these globs (`com.google.*`).
    public var sourceAppGlobs: [String]?
    /// Match if the user belongs to any of these groups.
    public var userGroups: [String]?
    /// Match if the payload is at least this many bytes.
    public var minBytes: Int?

    public init(
        dataTypes: [String]? = nil,
        categories: [DataCategory]? = nil,
        minSeverity: Severity? = nil,
        minConfidence: Confidence? = nil,
        minFindings: Int? = nil,
        categoryThresholds: [CategoryThreshold]? = nil,
        destinationTiers: [RiskTier]? = nil,
        services: [String]? = nil,
        channels: [Channel]? = nil,
        sourceAppGlobs: [String]? = nil,
        userGroups: [String]? = nil,
        minBytes: Int? = nil
    ) {
        self.dataTypes = dataTypes
        self.categories = categories
        self.minSeverity = minSeverity
        self.minConfidence = minConfidence
        self.minFindings = minFindings
        self.categoryThresholds = categoryThresholds
        self.destinationTiers = destinationTiers
        self.services = services
        self.channels = channels
        self.sourceAppGlobs = sourceAppGlobs
        self.userGroups = userGroups
        self.minBytes = minBytes
    }

    /// True when this condition set is empty (matches everything — a catch-all).
    public var isCatchAll: Bool {
        dataTypes == nil && categories == nil && minSeverity == nil && minConfidence == nil
            && minFindings == nil && categoryThresholds == nil && destinationTiers == nil
            && services == nil && channels == nil && sourceAppGlobs == nil
            && userGroups == nil && minBytes == nil
    }
}

/// A single ordered rule.
public struct PolicyRule: Codable, Hashable, Sendable, Identifiable {
    public let id: String
    public let name: String
    public var conditions: RuleConditions
    public var action: PolicyAction
    /// Human-readable message shown to the user for `warn`/`block`.
    public var message: String?
    public var enabled: Bool

    public init(
        id: String,
        name: String,
        conditions: RuleConditions,
        action: PolicyAction,
        message: String? = nil,
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.conditions = conditions
        self.action = action
        self.message = message
        self.enabled = enabled
    }
}

/// A complete, versioned policy document. Distributed to endpoints via MDM/XPC.
public struct Policy: Codable, Hashable, Sendable, Identifiable {
    public let id: String
    public var name: String
    public var version: Int
    public var mode: PolicyMode
    public var failMode: FailMode
    /// Action when no rule matches.
    public var defaultAction: PolicyAction
    /// Ordered rules; first match wins.
    public var rules: [PolicyRule]

    public init(
        id: String,
        name: String,
        version: Int = 1,
        mode: PolicyMode = .enforce,
        failMode: FailMode = .open,
        defaultAction: PolicyAction = .audit,
        rules: [PolicyRule]
    ) {
        self.id = id
        self.name = name
        self.version = version
        self.mode = mode
        self.failMode = failMode
        self.defaultAction = defaultAction
        self.rules = rules
    }
}
