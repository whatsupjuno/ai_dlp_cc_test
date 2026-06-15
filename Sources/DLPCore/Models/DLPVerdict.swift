import Foundation

/// The outcome of running content + context through the full DLP pipeline:
/// detection → policy evaluation → (optional) redaction.
public struct DLPVerdict: Codable, Hashable, Sendable {
    /// The action the policy engine resolved to.
    public let action: PolicyAction
    /// All findings that contributed to the decision (already deduped/sorted).
    public let findings: [Finding]
    /// The id of the policy rule that fired, if any (`nil` for the implicit
    /// default-allow when nothing matched).
    public let matchedRuleID: String?
    /// Human-readable explanation, suitable for a user-facing warning dialog.
    public let reason: String
    /// If the action was `.redact`, the sanitized content with sensitive spans
    /// replaced. `nil` for every other action.
    public let redactedContent: String?
    /// A blended 0...1 risk score combining severity, confidence and destination.
    public let riskScore: Double
    /// The context this verdict was produced for.
    public let context: InspectionContext

    public init(
        action: PolicyAction,
        findings: [Finding],
        matchedRuleID: String?,
        reason: String,
        redactedContent: String? = nil,
        riskScore: Double,
        context: InspectionContext
    ) {
        self.action = action
        self.findings = findings
        self.matchedRuleID = matchedRuleID
        self.reason = reason
        self.redactedContent = redactedContent
        self.riskScore = riskScore
        self.context = context
    }

    /// Whether the egress should be prevented from proceeding unmodified.
    public var blocksEgress: Bool {
        switch action {
        case .block, .quarantine: return true
        case .allow, .audit, .redact, .warn: return false
        }
    }

    /// The single highest severity across all findings (`.info` if none).
    public var topSeverity: Severity {
        findings.map(\.severity).max() ?? .info
    }

    public var hasFindings: Bool { !findings.isEmpty }
}
