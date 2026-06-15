import XCTest
@testable import DLPCore

final class DLPEngineTests: XCTestCase {

    func testEndToEndBlockSecretToChatGPT() {
        let engine = DLPEngine()
        let v = engine.inspect("here is sk-ant-api03-AAAA1111BBBB2222CCCC3333DDDD4444EEEE",
                               channel: .clipboard, host: "chatgpt.com")
        XCTAssertEqual(v.action, .block)
        XCTAssertTrue(v.blocksEgress)
        XCTAssertEqual(v.context.destination.service?.id, "openai-chatgpt")
        XCTAssertGreaterThan(v.riskScore, 0.5)
    }

    func testEndToEndRedactPII() {
        let engine = DLPEngine()
        let v = engine.inspect("contact john@acme.com", channel: .clipboard)
        XCTAssertEqual(v.action, .redact)
        XCTAssertNotNil(v.redactedContent)
        XCTAssertFalse(v.redactedContent?.contains("john@acme.com") ?? true)
    }

    func testPost2020RRNStillBlocked() {
        // codex round-8 regression: a checksum-unverifiable (post-2020) RRN must
        // still reach block-gov-id-critical, not be silently allowed.
        let engine = DLPEngine()
        let v = engine.inspect("고객 주민등록번호 900101-1234567", channel: .clipboard, host: "chatgpt.com")
        XCTAssertEqual(v.action, .block)
        XCTAssertTrue(v.findings.contains { $0.type.id == "kr-rrn" })
    }

    func testBlockedDestinationAuditedEvenWithoutContent() {
        // codex round-10: a forbidden-tier destination must produce an audit
        // record even when there is no inspectable body (this is what the network
        // filter calls before dropping a blocked flow).
        let sink = InMemoryAuditSink()
        let engine = DLPEngine(auditSink: sink)
        let v = engine.inspect("", channel: .network, host: "deepseek.com")
        XCTAssertEqual(v.action, .block)
        XCTAssertEqual(v.matchedRuleID, "block-forbidden-destination")
        XCTAssertEqual(sink.events.count, 1)
        XCTAssertEqual(sink.events.first?.destinationTier, .blocked)
    }

    func testBareBICTokenDoesNotTriggerFinancialWarning() {
        // "PASSWORD" matches the BIC shape, but at low confidence it must not fire
        // warn-financial (min medium) on ordinary clipboard text.
        let v = DLPEngine().inspect("MEETING PASSWORD FOR TODAY", channel: .clipboard)
        XCTAssertNotEqual(v.action, .warn)
    }

    func testRedactEscalatesToBlockWhenTruncated() {
        // PII (→ redact) in the inspected prefix, then a long uninspected tail.
        // Redaction can't be trusted past the cap, so the action must escalate to
        // block rather than emit the full text with the tail intact.
        var config = DLPConfiguration()
        config.maxInspectLength = 40
        let engine = DLPEngine(configuration: config)
        let text = "email a@b.com " + String(repeating: "x", count: 200)
        let v = engine.inspect(text, channel: .clipboard)
        XCTAssertEqual(v.action, .block, "truncated redact must escalate to block")
        XCTAssertNil(v.redactedContent)
    }

    func testCleanTextAllows() {
        let engine = DLPEngine()
        let v = engine.inspect("the quick brown fox jumps over the lazy dog",
                               channel: .manualScan)
        XCTAssertEqual(v.action, .audit) // default action; no findings
        XCTAssertFalse(v.hasFindings)
        XCTAssertNil(v.redactedContent)
    }

    func testAuditSinkReceivesEvents() {
        let sink = InMemoryAuditSink()
        let engine = DLPEngine(auditSink: sink)
        _ = engine.inspect("ssn 123-45-6789", channel: .clipboard, host: "claude.ai")
        XCTAssertEqual(sink.events.count, 1)
        let event = sink.events.first
        XCTAssertEqual(event?.action, .block)
        // Audit must never contain the raw value.
        let json = String(data: try! AuditCoding.encoder.encode(event!), encoding: .utf8)!
        XCTAssertFalse(json.contains("123-45-6789"), "raw SSN leaked into audit log")
    }

    func testCleanAllowNotAudited() {
        let sink = InMemoryAuditSink()
        let engine = DLPEngine(auditSink: sink)
        _ = engine.inspect("nothing sensitive here", channel: .manualScan)
        // default action is audit (non-allow) → it *is* recorded; verify it is
        // recorded exactly once and carries no findings.
        XCTAssertEqual(sink.events.count, 1)
        XCTAssertTrue(sink.events.first?.findings.isEmpty ?? false)
    }

    func testMonitorModeNeverBlocks() {
        var config = DLPConfiguration()
        config.policy.mode = .monitor
        let engine = DLPEngine(configuration: config)
        let v = engine.inspect("sk-ant-api03-AAAA1111BBBB2222CCCC3333DDDD4444EEEE",
                               channel: .clipboard, host: "chatgpt.com")
        XCTAssertFalse(v.blocksEgress)
        XCTAssertEqual(v.action, .audit)
    }

    func testRiskScoreMonotonicWithDestination() {
        let engine = DLPEngine()
        let text = "card 4111 1111 1111 1111"
        let sanctionedClassifier = DestinationClassifier(overrides: ["openai-chatgpt": .sanctioned])
        let sanctioned = sanctionedClassifier.classify(host: "chatgpt.com")
        let unsanctioned = engine.classifier.classify(host: "chatgpt.com")

        let findings = engine.detection.scan(text, context: InspectionContext(channel: .network))
        let low = RiskScorer.score(findings: findings,
                                   context: InspectionContext(channel: .network, destination: sanctioned))
        let high = RiskScorer.score(findings: findings,
                                    context: InspectionContext(channel: .network, destination: unsanctioned))
        XCTAssertGreaterThan(high, low)
    }
}
