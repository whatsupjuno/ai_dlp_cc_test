import Foundation

/// Declarative configuration for building a `DLPEngine`.
public struct DLPConfiguration: Sendable {
    public var patterns: [PatternRule]
    public var keywords: [KeywordDetector.Keyword]
    public var enableNER: Bool
    public var enableContextBoost: Bool
    public var policy: Policy
    public var serviceCatalog: AIServiceCatalog
    public var tierOverrides: [String: RiskTier]
    public var redactionStyle: Redactor.Style
    /// Inspect at most this many UTF-16 units (0 = unlimited).
    public var maxInspectLength: Int

    public init(
        patterns: [PatternRule] = PatternLibrary.builtin,
        keywords: [KeywordDetector.Keyword] = PatternLibrary.defaultKeywords,
        enableNER: Bool = true,
        enableContextBoost: Bool = true,
        policy: Policy = .enterpriseDefault(),
        serviceCatalog: AIServiceCatalog = .builtin,
        tierOverrides: [String: RiskTier] = [:],
        redactionStyle: Redactor.Style = .placeholder,
        maxInspectLength: Int = 0
    ) {
        self.patterns = patterns
        self.keywords = keywords
        self.enableNER = enableNER
        self.enableContextBoost = enableContextBoost
        self.policy = policy
        self.serviceCatalog = serviceCatalog
        self.tierOverrides = tierOverrides
        self.redactionStyle = redactionStyle
        self.maxInspectLength = maxInspectLength
    }
}

/// The top-level DLP pipeline: **detect → classify destination → evaluate policy
/// → (optionally) redact → score → audit**. This is the single brain shared by
/// every vector (clipboard monitor, file monitor, network filter, CLI). The
/// system extensions are just different *sources* feeding this same engine.
///
/// Value-typed and `Sendable`; to change policy at runtime, build a new engine
/// (the daemon swaps it behind a lock).
public struct DLPEngine: Sendable {
    public let detection: DetectionEngine
    public let policyEngine: PolicyEngine
    public let classifier: DestinationClassifier
    public let redactor: Redactor
    public let auditSink: AuditSink?
    public let policy: Policy

    public init(configuration config: DLPConfiguration = DLPConfiguration(), auditSink: AuditSink? = nil) {
        var detectors: [any Detector] = []
        detectors.append(RegexDetector(rules: config.patterns))
        if !config.keywords.isEmpty {
            detectors.append(KeywordDetector(keywords: config.keywords))
        }
        if config.enableNER {
            detectors.append(NLEntityDetector())
        }
        self.detection = DetectionEngine(
            detectors: detectors,
            maxInspectLength: config.maxInspectLength,
            contextBooster: config.enableContextBoost ? ContextBooster() : nil
        )
        self.policyEngine = PolicyEngine(policy: config.policy)
        self.classifier = DestinationClassifier(catalog: config.serviceCatalog, overrides: config.tierOverrides)
        self.redactor = Redactor(style: config.redactionStyle)
        self.auditSink = auditSink
        self.policy = config.policy
    }

    /// Full inspection given an explicit context.
    @discardableResult
    public func inspect(_ text: String, context: InspectionContext) -> DLPVerdict {
        let findings = detection.scan(text, context: context)
        let decision = policyEngine.evaluate(findings: findings, context: context)
        let risk = RiskScorer.score(findings: findings, context: context)

        var action = decision.action
        var reason = decision.reason

        // If inspection was truncated to a prefix (text exceeds maxInspectLength),
        // the uninspected remainder may hold undetected secrets. We therefore can't
        // safely REDACT — emitting the full text with only prefix spans removed
        // would leak anything after the cap — so escalate redact → block.
        let truncated = detection.maxInspectLength > 0 && text.utf16.count > detection.maxInspectLength
        if truncated, action == .redact {
            action = .block
            reason = "Content exceeds the inspection limit; the uninspected remainder can't be safely redacted — blocked. (\(reason))"
        }

        let redacted = action == .redact ? redactor.redact(text, findings: findings) : nil

        let verdict = DLPVerdict(
            action: action,
            findings: findings,
            matchedRuleID: decision.matchedRuleID,
            reason: reason,
            redactedContent: redacted,
            riskScore: risk,
            context: context
        )

        // Audit anything interesting: findings present or a non-allow action.
        if verdict.hasFindings || verdict.action != .allow {
            auditSink?.record(AuditEvent(verdict: verdict))
        }
        return verdict
    }

    /// Convenience: inspect content bound for a host, classifying the destination.
    @discardableResult
    public func inspect(
        _ text: String,
        channel: Channel,
        host: String? = nil,
        sourceApp: String? = nil,
        user: String = NSUserName(),
        userGroups: [String] = []
    ) -> DLPVerdict {
        let destination = host.map { classifier.classify(host: $0) } ?? .unknown
        let context = InspectionContext(
            channel: channel,
            destination: destination,
            sourceApp: sourceApp,
            user: user,
            userGroups: userGroups,
            byteCount: text.utf8.count
        )
        return inspect(text, context: context)
    }
}
