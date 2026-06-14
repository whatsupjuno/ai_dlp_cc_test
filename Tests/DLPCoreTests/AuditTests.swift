import XCTest
@testable import DLPCore

final class AuditTests: XCTestCase {

    private func sampleVerdict() -> DLPVerdict {
        let finding = Finding(type: SensitiveDataType(id: "us-ssn", name: "US SSN", category: .governmentID),
                              detectorID: "regex", severity: .critical, confidence: .high,
                              span: TextSpan(location: 0, length: 11),
                              maskedValue: "12••••••89", valueFingerprint: "deadbeef")
        let dest = Destination(host: "claude.ai",
                               service: AIService(id: "anthropic-claude", name: "Claude", vendor: "Anthropic", defaultTier: .unsanctioned),
                               tier: .unsanctioned, isAPIEndpoint: false)
        let ctx = InspectionContext(channel: .clipboard, destination: dest, sourceApp: "com.google.Chrome",
                                    user: "alice", byteCount: 42)
        return DLPVerdict(action: .block, findings: [finding], matchedRuleID: "block-gov-id-critical",
                          reason: "blocked", redactedContent: nil, riskScore: 0.9, context: ctx)
    }

    func testEventRoundTrips() throws {
        let event = AuditEvent(verdict: sampleVerdict())
        let data = try AuditCoding.encoder.encode(event)
        let decoded = try AuditCoding.decoder.decode(AuditEvent.self, from: data)
        XCTAssertEqual(decoded.action, .block)
        XCTAssertEqual(decoded.findings.first?.typeID, "us-ssn")
        XCTAssertEqual(decoded.destinationTier, .unsanctioned)
    }

    func testJSONLSinkWritesAndFlushes() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("dlp-test-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: url) }

        let sink = try JSONLFileAuditSink(url: url)
        for _ in 0..<5 { sink.record(AuditEvent(verdict: sampleVerdict())) }
        sink.flush()

        let content = try String(contentsOf: url, encoding: .utf8)
        let lines = content.split(separator: "\n")
        XCTAssertEqual(lines.count, 5)
        // each line is valid JSON
        for line in lines {
            XCTAssertNoThrow(try AuditCoding.decoder.decode(AuditEvent.self, from: Data(line.utf8)))
        }
    }

    func testCEFFormatting() {
        let event = AuditEvent(verdict: sampleVerdict())
        let cef = CEFFormatter.format(event)
        XCTAssertTrue(cef.hasPrefix("CEF:0|Sentinel|AIDLP|"))
        XCTAssertTrue(cef.contains("act=block"))
        XCTAssertTrue(cef.contains("cs1=unsanctioned"))
        XCTAssertTrue(cef.contains("suser=alice"))
        XCTAssertFalse(cef.contains("123-45-6789"))
    }

    func testInMemorySinkBounded() {
        let sink = InMemoryAuditSink(capacity: 10)
        for _ in 0..<25 { sink.record(AuditEvent(verdict: sampleVerdict())) }
        XCTAssertEqual(sink.events.count, 10)
    }

    func testMultiSinkFansOut() {
        let a = InMemoryAuditSink(), b = InMemoryAuditSink()
        let multi = MultiAuditSink([a, b])
        multi.record(AuditEvent(verdict: sampleVerdict()))
        XCTAssertEqual(a.events.count, 1)
        XCTAssertEqual(b.events.count, 1)
    }
}
