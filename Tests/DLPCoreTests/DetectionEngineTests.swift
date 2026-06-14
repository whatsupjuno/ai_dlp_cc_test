import XCTest
@testable import DLPCore

final class DetectionEngineTests: XCTestCase {

    private func makeEngine(ner: Bool = false, boost: Bool = true) -> DetectionEngine {
        var detectors: [any Detector] = [RegexDetector(rules: PatternLibrary.builtin)]
        if ner { detectors.append(NLEntityDetector()) }
        return DetectionEngine(detectors: detectors, contextBooster: boost ? ContextBooster() : nil)
    }

    private func ctx() -> InspectionContext { InspectionContext(channel: .manualScan) }

    func testDetectsAnthropicKey() {
        let f = makeEngine().scan("token sk-ant-api03-AAAA1111BBBB2222CCCC3333DDDD4444EEEE", context: ctx())
        XCTAssertTrue(f.contains { $0.type.id == "anthropic-api-key" })
    }

    func testDetectsSSNAndMasks() {
        let f = makeEngine().scan("SSN is 123-45-6789 ok", context: ctx())
        let ssn = f.first { $0.type.id == "us-ssn" }
        XCTAssertNotNil(ssn)
        XCTAssertEqual(ssn?.severity, .critical)
        XCTAssertFalse(ssn?.maskedValue.contains("12345") ?? true, "raw value must not appear in mask")
        XCTAssertFalse(ssn!.maskedValue.contains("6789"))
    }

    func testSeparatorTolerantCard() {
        let f = makeEngine().scan("card 4111 1111 1111 1111", context: ctx())
        XCTAssertTrue(f.contains { $0.category == .financial }, "spaced PAN should be detected")
    }

    func testSeparatorTolerantIBAN() {
        // Grouped, human-readable IBAN must be detected (regex tolerates the
        // spaces; the mod-97 validator compacts them).
        let f = makeEngine().scan("please wire to GB82 WEST 1234 5698 7654 32 by EOD", context: ctx())
        XCTAssertTrue(f.contains { $0.type.id == "iban" }, "grouped IBAN should be detected")
    }

    func testLuhnSuppressesRandom16Digits() {
        // A 16-digit number that fails Luhn should not be reported as a card.
        // (1234567812345678 is Luhn-invalid; verified in ValidatorsTests.)
        let f = makeEngine().scan("order 1234567812345678", context: ctx())
        XCTAssertFalse(f.contains { $0.category == .financial && $0.detectorID.hasPrefix("cc") })
    }

    func testOverlapResolutionKeepsHigherPriority() {
        // Two detectors producing overlapping spans → only one survives.
        let a = Finding(type: SensitiveDataType(id: "a", name: "A", category: .pii),
                        detectorID: "x", severity: .low, confidence: .low,
                        span: TextSpan(location: 0, length: 10), maskedValue: "•", valueFingerprint: "0")
        let b = Finding(type: SensitiveDataType(id: "b", name: "B", category: .financial),
                        detectorID: "y", severity: .critical, confidence: .high,
                        span: TextSpan(location: 2, length: 6), maskedValue: "•", valueFingerprint: "1")
        let resolved = DetectionEngine.resolveOverlaps([a, b])
        XCTAssertEqual(resolved.count, 1)
        XCTAssertEqual(resolved.first?.type.id, "b")
    }

    func testNonOverlappingBothKept() {
        let a = Finding(type: SensitiveDataType(id: "a", name: "A", category: .pii),
                        detectorID: "x", severity: .low, confidence: .low,
                        span: TextSpan(location: 0, length: 5), maskedValue: "•", valueFingerprint: "0")
        let b = Finding(type: SensitiveDataType(id: "b", name: "B", category: .pii),
                        detectorID: "y", severity: .low, confidence: .low,
                        span: TextSpan(location: 10, length: 5), maskedValue: "•", valueFingerprint: "1")
        XCTAssertEqual(DetectionEngine.resolveOverlaps([a, b]).count, 2)
    }

    func testContextBoostPromotesConfidence() {
        // "passport" near a low-confidence passport-shaped number boosts it.
        let booster = ContextBooster()
        let finding = Finding(type: SensitiveDataType(id: "us-passport", name: "US passport", category: .governmentID),
                              detectorID: "regex", severity: .high, confidence: .low,
                              span: TextSpan(location: 14, length: 9), maskedValue: "A1••••••8", valueFingerprint: "z")
        let text = "my passport is A12345678 today"
        let boosted = booster.boost([finding], in: text)
        XCTAssertEqual(boosted.first?.confidence, .medium)
        XCTAssertTrue(boosted.first?.note?.contains("context-corroborated") ?? false)
    }

    func testPost2020RRNDowngradedNotDropped() {
        // Date-valid RRN whose legacy checksum fails (post-2020 randomized suffix).
        // Must NOT be dropped — reported at one-lower confidence. Booster off so we
        // observe the raw downgraded value.
        let f = makeEngine(boost: false).scan("900101-1234567", context: ctx())
        let rrn = f.first { $0.type.id == "kr-rrn" }
        XCTAssertNotNil(rrn, "post-2020 RRN must still be detected")
        XCTAssertEqual(rrn?.confidence, .medium, "checksum-unverified ⇒ one level below high")
        XCTAssertTrue(rrn?.note?.contains("checksum-unverified") ?? false)
    }

    func testImpossibleRRNDateDropped() {
        // Matches the regex (day 31 ≤ 31) but Feb 31 isn't a real date → must be
        // dropped, NOT kept as a medium-confidence critical finding (false block).
        let f = makeEngine(boost: false).scan("990231-1234567", context: ctx())
        XCTAssertFalse(f.contains { $0.type.id == "kr-rrn" })
    }

    func testChecksumValidRRNKeepsHighConfidence() {
        let f = makeEngine(boost: false).scan("900101-1234568", context: ctx())
        XCTAssertEqual(f.first { $0.type.id == "kr-rrn" }?.confidence, .high)
    }

    func testLuhnFailureStillDropsHard() {
        // A non-soft validator (Luhn) failure still drops the match entirely.
        let f = makeEngine(boost: false).scan("card 4111 1111 1111 1112", context: ctx())
        XCTAssertFalse(f.contains { $0.detectorID.hasPrefix("cc") })
    }

    func testNERDetectsPersonName() {
        let f = makeEngine(ner: true).scan("Please contact Barack Obama about the report.", context: ctx())
        XCTAssertTrue(f.contains { $0.category == .identity }, "NER should find a person/identity entity")
    }

    func testTruncateNoLimitOrShort() {
        XCTAssertEqual(DetectionEngine.truncate("hello", toUTF16: 0), "hello")
        XCTAssertEqual(DetectionEngine.truncate("hi", toUTF16: 100), "hi")
    }

    func testTruncateSnapsBackOnSplitSurrogate() {
        // 49 'a's, then an emoji occupying UTF-16 offsets 49–50. A cut at 50
        // lands between the surrogate halves.
        let text = String(repeating: "a", count: 49) + "😀 123-45-6789"
        let out = DetectionEngine.truncate(text, toUTF16: 50)
        XCTAssertLessThanOrEqual(out.utf16.count, 50)
        XCTAssertFalse(out.contains("😀"), "emoji split by the cut must be excluded")
        XCTAssertFalse(out.contains("123-45-6789"))
        XCTAssertNotEqual(out, text, "must NOT fall back to the full text (cap bypass)")
    }

    func testCapNotBypassedBySurrogateAtCut() {
        let engine = DetectionEngine(detectors: [RegexDetector(rules: PatternLibrary.builtin)],
                                     maxInspectLength: 50, contextBooster: nil)
        let text = String(repeating: "a", count: 49) + "😀 SSN 123-45-6789"
        let f = engine.scan(text, context: ctx())
        XCTAssertFalse(f.contains { $0.type.id == "us-ssn" }, "SSN past the cap must not be scanned")
    }

    func testMaxInspectLengthTruncates() {
        let padding = String(repeating: "x", count: 1000)
        let engine = DetectionEngine(detectors: [RegexDetector(rules: PatternLibrary.builtin)], maxInspectLength: 100)
        // SSN placed beyond the truncation window should not be found.
        let f = engine.scan(padding + " 123-45-6789", context: ctx())
        XCTAssertFalse(f.contains { $0.type.id == "us-ssn" })
    }
}
