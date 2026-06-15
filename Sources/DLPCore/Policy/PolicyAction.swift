import Foundation

/// What the policy engine decides to do about an inspected payload. Ordered by
/// restrictiveness so that when multiple rules could apply we can keep the most
/// restrictive, and `monitor` mode can downgrade terminal actions to `audit`.
public enum PolicyAction: String, Codable, CaseIterable, Comparable, Sendable {
    /// Permit silently (no audit record beyond debug).
    case allow
    /// Permit, but record a full audit event.
    case audit
    /// Strip/replace the sensitive spans, then permit the sanitized content.
    case redact
    /// Prompt the user for justification; permit only on explicit confirm.
    case warn
    /// Prevent the egress.
    case block
    /// Prevent the egress and capture evidence for investigation.
    case quarantine

    /// Higher = more restrictive.
    public var restrictiveness: Int {
        switch self {
        case .allow: return 0
        case .audit: return 1
        case .redact: return 2
        case .warn: return 3
        case .block: return 4
        case .quarantine: return 5
        }
    }

    public static func < (lhs: PolicyAction, rhs: PolicyAction) -> Bool {
        lhs.restrictiveness < rhs.restrictiveness
    }

    /// In `monitor` mode the agent observes but never interrupts the user, so any
    /// action that would block or modify traffic is downgraded to `audit`.
    public var monitoredEquivalent: PolicyAction {
        switch self {
        case .allow: return .allow
        case .audit, .redact, .warn, .block, .quarantine: return .audit
        }
    }

    public var displayName: String {
        switch self {
        case .allow: return "Allow"
        case .audit: return "Audit"
        case .redact: return "Redact"
        case .warn: return "Warn"
        case .block: return "Block"
        case .quarantine: return "Quarantine"
        }
    }
}
