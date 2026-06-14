import Foundation

public extension Policy {

    /// A strong, opinionated default policy for protecting data egress to AI
    /// tools. Ordered most-severe-first (first match wins). Ships enabled in
    /// `enforce` mode but admins typically start in `.monitor` for rollout.
    static func enterpriseDefault() -> Policy {
        Policy(
            id: "builtin.enterprise-default",
            name: "Sentinel Enterprise Default",
            version: 1,
            mode: .enforce,
            failMode: .open,
            defaultAction: .audit,
            rules: [
                // 1. Secrets / credentials must never leave the endpoint to AI.
                PolicyRule(
                    id: "block-secrets",
                    name: "Block credentials & secrets",
                    conditions: RuleConditions(
                        categories: [.credential, .sourceSecret],
                        minConfidence: .medium
                    ),
                    action: .block,
                    message: "API keys, tokens and private keys must never be sent to AI services. This action was blocked and logged."
                ),
                // 2. Critical government identifiers are blocked outright.
                PolicyRule(
                    id: "block-gov-id-critical",
                    name: "Block critical government IDs",
                    conditions: RuleConditions(
                        categories: [.governmentID],
                        minSeverity: .critical,
                        minConfidence: .medium
                    ),
                    action: .block,
                    message: "National identifiers (SSN, RRN, etc.) cannot be shared with AI tools."
                ),
                // 3. Anything headed to an explicitly forbidden destination.
                PolicyRule(
                    id: "block-forbidden-destination",
                    name: "Block forbidden AI destinations",
                    conditions: RuleConditions(destinationTiers: [.blocked]),
                    action: .block,
                    message: "This AI service is not approved for company use."
                ),
                // 4. Bulk personal-data exfiltration (e.g. a customer list pasted in).
                PolicyRule(
                    id: "block-bulk-pii",
                    name: "Block bulk personal-data exfiltration",
                    conditions: RuleConditions(
                        categoryThresholds: [CategoryThreshold(category: .pii, count: 15)]
                    ),
                    action: .block,
                    message: "Sending large volumes of personal data to AI tools is prohibited."
                ),
                // 4b. Bulk identity exfiltration — NER emits `.identity` (not
                // `.pii`) for names/orgs/locations, so a pasted customer list of
                // names needs its own threshold. Higher count than PII because
                // NER entities are noisier/lower-confidence.
                PolicyRule(
                    id: "block-bulk-identity",
                    name: "Block bulk identity exfiltration",
                    conditions: RuleConditions(
                        categoryThresholds: [CategoryThreshold(category: .identity, count: 25)]
                    ),
                    action: .block,
                    message: "Sending a large list of names/organizations to AI tools is prohibited."
                ),
                // 5. Payment-card data → warn + require justification.
                PolicyRule(
                    id: "warn-financial",
                    name: "Warn on financial data",
                    conditions: RuleConditions(
                        categories: [.financial],
                        minConfidence: .medium
                    ),
                    action: .warn,
                    message: "You're about to send payment-card or banking data to an AI tool. Confirm only if this is necessary and approved."
                ),
                // 6. Health data → warn.
                PolicyRule(
                    id: "warn-health",
                    name: "Warn on health data",
                    conditions: RuleConditions(categories: [.health], minConfidence: .medium),
                    action: .warn,
                    message: "Protected health information detected. Sharing PHI with AI tools may violate HIPAA."
                ),
                // 7. Ordinary PII → redact transparently so the user can continue.
                PolicyRule(
                    id: "redact-pii",
                    name: "Redact personal information",
                    conditions: RuleConditions(categories: [.pii], minConfidence: .medium),
                    action: .redact,
                    message: "Personal information was redacted before sending."
                ),
                // 8. Any interaction with shadow / unsanctioned AI is recorded.
                PolicyRule(
                    id: "audit-unsanctioned",
                    name: "Audit shadow-AI usage",
                    conditions: RuleConditions(destinationTiers: [.unsanctioned]),
                    action: .audit,
                    message: "Use of an unsanctioned AI service was recorded."
                ),
            ]
        )
    }
}
