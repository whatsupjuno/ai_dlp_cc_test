import XCTest
@testable import DLPCore

final class RedactorTests: XCTestCase {

    private func finding(at loc: Int, len: Int, id: String = "x",
                         category: DataCategory = .pii) -> Finding {
        Finding(type: SensitiveDataType(id: id, name: id, category: category),
                detectorID: "t", severity: .high, confidence: .high,
                span: TextSpan(location: loc, length: len),
                maskedValue: "•", valueFingerprint: "abcd1234")
    }

    func testPlaceholderRedaction() {
        let text = "email me at john@acme.com please"
        let f = finding(at: 12, len: 13, id: "email-address")
        let out = Redactor(style: .placeholder).redact(text, findings: [f])
        XCTAssertEqual(out, "email me at [REDACTED:email-address] please")
    }

    func testMaskRedaction() {
        let text = "secret ABCDEFGH end"
        let f = finding(at: 7, len: 8)
        let out = Redactor(style: .mask).redact(text, findings: [f])
        XCTAssertFalse(out.contains("ABCDEFGH"))
        XCTAssertTrue(out.contains("•"))
    }

    func testTokenizeStable() {
        let text = "id ABCDEFGH here"
        let f = finding(at: 3, len: 8, category: .credential)
        let out = Redactor(style: .tokenize).redact(text, findings: [f])
        XCTAssertTrue(out.contains("[secret_abcd1234]"))
    }

    func testMultipleSpansRightToLeftPreservesOffsets() {
        // Two findings; redaction must not corrupt the second span's position.
        let text = "AAAA and BBBB"  // A at 0..4, B at 9..13
        let f1 = finding(at: 0, len: 4, id: "a")
        let f2 = finding(at: 9, len: 4, id: "b")
        let out = Redactor(style: .placeholder).redact(text, findings: [f1, f2])
        XCTAssertEqual(out, "[REDACTED:a] and [REDACTED:b]")
    }

    func testOverlappingSpansNotDoubleSubstituted() {
        let text = "0123456789"
        let outer = finding(at: 0, len: 8, id: "outer")
        let inner = finding(at: 2, len: 3, id: "inner")
        let out = Redactor(style: .placeholder).redact(text, findings: [outer, inner])
        // The two overlapping spans merge into one fully-covered segment with a
        // generic marker (multiple distinct types), leaving no exposed bytes.
        XCTAssertEqual(out, "[REDACTED]89")
    }

    func testNoFindingsReturnsOriginal() {
        XCTAssertEqual(Redactor().redact("unchanged", findings: []), "unchanged")
    }

    func testOutOfBoundsSpanIgnored() {
        let f = finding(at: 100, len: 5)
        XCTAssertEqual(Redactor().redact("short", findings: [f]), "short")
    }
}
