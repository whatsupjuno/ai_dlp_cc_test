import Foundation

/// Evaluates findings + context against a `Policy` and resolves the action.
///
/// Semantics: rules are evaluated top-to-bottom and the **first** matching rule
/// wins (the order is the admin's priority). If none match, the policy's
/// `defaultAction` applies. In `monitor` mode every resolved action is
/// downgraded to its non-interrupting equivalent, so a rollout never blocks a
/// user. The engine never throws — a malformed rule simply fails to match.
public struct PolicyEngine: Sendable {
    public let policy: Policy

    public init(policy: Policy) {
        self.policy = policy
    }

    public struct Decision: Sendable {
        public let action: PolicyAction
        public let matchedRuleID: String?
        public let reason: String
    }

    /// Resolve the action for a set of findings in a given context.
    public func evaluate(findings: [Finding], context: InspectionContext) -> Decision {
        for rule in policy.rules where rule.enabled {
            if Self.matches(rule.conditions, findings: findings, context: context) {
                let action = effective(rule.action)
                let reason = rule.message ?? Self.defaultReason(for: rule, findings: findings, context: context)
                return Decision(action: action, matchedRuleID: rule.id, reason: reason)
            }
        }
        let action = effective(policy.defaultAction)
        let reason = findings.isEmpty
            ? "No sensitive data detected."
            : "No rule matched; applying default action (\(policy.defaultAction.displayName))."
        return Decision(action: action, matchedRuleID: nil, reason: reason)
    }

    private func effective(_ action: PolicyAction) -> PolicyAction {
        policy.mode == .monitor ? action.monitoredEquivalent : action
    }

    // MARK: - Condition matching

    static func matches(_ c: RuleConditions, findings: [Finding], context: InspectionContext) -> Bool {
        // --- Context-level predicates ---
        if let tiers = c.destinationTiers, !tiers.contains(context.destination.tier) { return false }
        if let services = c.services {
            guard let sid = context.destination.service?.id, services.contains(sid) else { return false }
        }
        if let channels = c.channels, !channels.contains(context.channel) { return false }
        if let globs = c.sourceAppGlobs {
            guard let app = context.sourceApp, globs.contains(where: { globMatch($0, app) }) else { return false }
        }
        if let groups = c.userGroups {
            guard !Set(groups).isDisjoint(with: Set(context.userGroups)) else { return false }
        }
        if let minBytes = c.minBytes, context.byteCount < minBytes { return false }

        // --- Finding-level predicates (evaluated against one qualifying set) ---
        let hasFindingPredicate =
            c.dataTypes != nil || c.categories != nil || c.minSeverity != nil ||
            c.minConfidence != nil || c.minFindings != nil || c.categoryThresholds != nil

        if hasFindingPredicate {
            let qualifying = findings.filter { f in
                (c.dataTypes?.contains(f.type.id) ?? true) &&
                (c.categories?.contains(f.category) ?? true) &&
                (c.minSeverity.map { f.severity >= $0 } ?? true) &&
                (c.minConfidence.map { f.confidence >= $0 } ?? true)
            }
            if let minFindings = c.minFindings, qualifying.count < minFindings { return false }
            if let thresholds = c.categoryThresholds {
                for t in thresholds {
                    let n = qualifying.filter { $0.category == t.category }.count
                    if n < t.count { return false }
                }
            }
            // If finding predicates were specified but no count thresholds, require
            // at least one qualifying finding.
            if c.minFindings == nil, c.categoryThresholds == nil, qualifying.isEmpty { return false }
        }

        return true
    }

    /// Glob match supporting `*` and `?`, used for source-app bundle ids.
    static func globMatch(_ pattern: String, _ value: String) -> Bool {
        if pattern == "*" { return true }
        // Escape regex metacharacters, then re-enable the glob wildcards.
        var rx = "^"
        for ch in pattern {
            switch ch {
            case "*": rx += ".*"
            case "?": rx += "."
            case ".", "+", "(", ")", "[", "]", "{", "}", "^", "$", "|", "\\":
                rx += "\\" + String(ch)
            default: rx += String(ch)
            }
        }
        rx += "$"
        guard let re = try? NSRegularExpression(pattern: rx, options: [.caseInsensitive]) else { return false }
        let ns = value as NSString
        return re.firstMatch(in: value, options: [], range: NSRange(location: 0, length: ns.length)) != nil
    }

    private static func defaultReason(for rule: PolicyRule, findings: [Finding], context: InspectionContext) -> String {
        let types = Set(findings.map(\.type.name)).sorted().prefix(4).joined(separator: ", ")
        let dest = context.destination.displayName
        let detail = types.isEmpty ? "" : " (\(types))"
        return "Rule “\(rule.name)” → \(rule.action.displayName) for egress to \(dest)\(detail)."
    }
}
