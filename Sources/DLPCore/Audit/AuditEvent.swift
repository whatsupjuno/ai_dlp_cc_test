import Foundation

/// A single, privacy-preserving audit record. It contains everything an analyst
/// needs to investigate — *except* the raw sensitive values, which are only ever
/// represented by masked previews and fingerprints.
public struct AuditEvent: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    public let timestamp: Date
    public let host: String
    public let user: String
    public let channel: Channel
    public let action: PolicyAction
    public let matchedRuleID: String?
    public let destination: String
    public let destinationTier: RiskTier
    public let sourceApp: String?
    public let riskScore: Double
    public let topSeverity: Severity
    public let byteCount: Int
    /// One row per finding (masked).
    public let findings: [Row]

    /// A flattened, log-safe view of a finding.
    public struct Row: Codable, Hashable, Sendable {
        public let typeID: String
        public let typeName: String
        public let category: DataCategory
        public let severity: Severity
        public let confidence: Confidence
        public let masked: String
        public let fingerprint: String

        public init(_ f: Finding) {
            typeID = f.type.id
            typeName = f.type.name
            category = f.category
            severity = f.severity
            confidence = f.confidence
            masked = f.maskedValue
            fingerprint = f.valueFingerprint
        }
    }

    public init(verdict: DLPVerdict, host: String = ProcessInfo.processInfo.hostName) {
        self.id = UUID()
        self.timestamp = verdict.context.timestamp
        self.host = host
        self.user = verdict.context.user
        self.channel = verdict.context.channel
        self.action = verdict.action
        self.matchedRuleID = verdict.matchedRuleID
        self.destination = verdict.context.destination.displayName
        self.destinationTier = verdict.context.destination.tier
        self.sourceApp = verdict.context.sourceApp
        self.riskScore = verdict.riskScore
        self.topSeverity = verdict.topSeverity
        self.byteCount = verdict.context.byteCount
        self.findings = verdict.findings.map(Row.init)
    }
}
