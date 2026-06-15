import XCTest
@testable import DLPCore

final class PolicyEngineTests: XCTestCase {

    private func finding(_ id: String, _ category: DataCategory, _ severity: Severity,
                         _ confidence: Confidence = .high) -> Finding {
        Finding(type: SensitiveDataType(id: id, name: id, category: category),
                detectorID: "test", severity: severity, confidence: confidence,
                span: TextSpan(location: 0, length: 4), maskedValue: "•", valueFingerprint: "0")
    }

    private func ctx(channel: Channel = .manualScan, tier: RiskTier = .unknown,
                     serviceID: String? = nil, app: String? = nil,
                     groups: [String] = [], bytes: Int = 0) -> InspectionContext {
        let service = serviceID.map { AIService(id: $0, name: $0, vendor: "v", defaultTier: tier) }
        let dest = Destination(host: serviceID, service: service, tier: tier, isAPIEndpoint: false)
        return InspectionContext(channel: channel, destination: dest, sourceApp: app,
                                 userGroups: groups, byteCount: bytes)
    }

    private let engine = PolicyEngine(policy: .enterpriseDefault())

    func testBlocksCredential() {
        let d = engine.evaluate(findings: [finding("openai-api-key", .credential, .critical)], context: ctx())
        XCTAssertEqual(d.action, .block)
        XCTAssertEqual(d.matchedRuleID, "block-secrets")
    }

    func testBlocksCriticalGovID() {
        let d = engine.evaluate(findings: [finding("us-ssn", .governmentID, .critical)], context: ctx())
        XCTAssertEqual(d.action, .block)
        XCTAssertEqual(d.matchedRuleID, "block-gov-id-critical")
    }

    func testBlocksForbiddenDestinationEvenWithoutFindings() {
        let d = engine.evaluate(findings: [], context: ctx(tier: .blocked, serviceID: "deepseek"))
        XCTAssertEqual(d.action, .block)
        XCTAssertEqual(d.matchedRuleID, "block-forbidden-destination")
    }

    func testWarnsOnFinancial() {
        let d = engine.evaluate(findings: [finding("cc-visa", .financial, .high)], context: ctx())
        XCTAssertEqual(d.action, .warn)
        XCTAssertEqual(d.matchedRuleID, "warn-financial")
    }

    func testRedactsSinglePII() {
        let d = engine.evaluate(findings: [finding("email-address", .pii, .low, .high)], context: ctx())
        XCTAssertEqual(d.action, .redact)
        XCTAssertEqual(d.matchedRuleID, "redact-pii")
    }

    func testBulkPIIBlocks() {
        let many = (0..<15).map { finding("email-\($0)", .pii, .low, .high) }
        let d = engine.evaluate(findings: many, context: ctx())
        XCTAssertEqual(d.action, .block)
        XCTAssertEqual(d.matchedRuleID, "block-bulk-pii")
    }

    func testBulkIdentityBlocks() {
        // A pasted customer list of names is NER-detected as `.identity`, not
        // `.pii`, and must still be blocked at the bulk threshold.
        let many = (0..<25).map { finding("ner-person-\($0)", .identity, .info, .medium) }
        let d = engine.evaluate(findings: many, context: ctx())
        XCTAssertEqual(d.action, .block)
        XCTAssertEqual(d.matchedRuleID, "block-bulk-identity")
    }

    func testFewIdentitiesNotBulkBlocked() {
        let few = (0..<5).map { finding("ner-person-\($0)", .identity, .info, .medium) }
        XCTAssertNotEqual(engine.evaluate(findings: few, context: ctx()).matchedRuleID, "block-bulk-identity")
    }

    func testAuditsUnsanctionedWithoutFindings() {
        let d = engine.evaluate(findings: [], context: ctx(tier: .unsanctioned, serviceID: "perplexity"))
        XCTAssertEqual(d.action, .audit)
        XCTAssertEqual(d.matchedRuleID, "audit-unsanctioned")
    }

    func testDefaultActionWhenNothingMatches() {
        let d = engine.evaluate(findings: [], context: ctx())
        XCTAssertEqual(d.action, .audit)
        XCTAssertNil(d.matchedRuleID)
    }

    func testMonitorModeDowngradesBlock() {
        var policy = Policy.enterpriseDefault()
        policy.mode = .monitor
        let e = PolicyEngine(policy: policy)
        let d = e.evaluate(findings: [finding("openai-api-key", .credential, .critical)], context: ctx())
        XCTAssertEqual(d.action, .audit, "monitor mode downgrades block→audit")
    }

    func testLowConfidenceCredentialNotBlocked() {
        // Confidence below the rule threshold → falls through to default.
        let d = engine.evaluate(findings: [finding("x", .credential, .high, .low)], context: ctx())
        XCTAssertNotEqual(d.action, .block)
    }

    func testGlobMatching() {
        XCTAssertTrue(PolicyEngine.globMatch("com.google.*", "com.google.Chrome"))
        XCTAssertTrue(PolicyEngine.globMatch("*", "anything"))
        XCTAssertTrue(PolicyEngine.globMatch("com.?pple.Safari", "com.apple.Safari"))
        XCTAssertFalse(PolicyEngine.globMatch("com.google.*", "com.apple.Safari"))
        XCTAssertFalse(PolicyEngine.globMatch("com.google.Chrome", "com.google.ChromeBeta"))
    }

    func testSourceAppCondition() {
        var policy = Policy(id: "p", name: "p", defaultAction: .allow, rules: [
            PolicyRule(id: "browsers", name: "browsers",
                       conditions: RuleConditions(categories: [.pii], sourceAppGlobs: ["com.google.*"]),
                       action: .block)
        ])
        policy.mode = .enforce
        let e = PolicyEngine(policy: policy)
        let blocked = e.evaluate(findings: [finding("email", .pii, .low)],
                                 context: ctx(app: "com.google.Chrome"))
        XCTAssertEqual(blocked.action, .block)
        let allowed = e.evaluate(findings: [finding("email", .pii, .low)],
                                 context: ctx(app: "com.apple.Safari"))
        XCTAssertEqual(allowed.action, .allow)
    }

    func testUserGroupCondition() {
        let policy = Policy(id: "p", name: "p", defaultAction: .allow, rules: [
            PolicyRule(id: "contractors", name: "contractors",
                       conditions: RuleConditions(categories: [.pii], userGroups: ["contractors"]),
                       action: .block)
        ])
        let e = PolicyEngine(policy: policy)
        XCTAssertEqual(e.evaluate(findings: [finding("e", .pii, .low)],
                                  context: ctx(groups: ["contractors"])).action, .block)
        XCTAssertEqual(e.evaluate(findings: [finding("e", .pii, .low)],
                                  context: ctx(groups: ["staff"])).action, .allow)
    }

    func testCatchAllRuleMatchesEverything() {
        XCTAssertTrue(RuleConditions().isCatchAll)
        XCTAssertTrue(PolicyEngine.matches(RuleConditions(), findings: [], context: ctx()))
    }
}
