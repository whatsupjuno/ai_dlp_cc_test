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

    func testBICDoesNotSelfCorroborate() {
        // codex round-44: "CARDUS33" matches the low-confidence BIC pattern and
        // contains the lexicon word "card" INSIDE its own span. The booster must
        // exclude the match itself, so a standalone token stays low confidence and
        // never crosses the warn-financial threshold without real context.
        let f = makeEngine().scan("CARDUS33", context: ctx())
        let bic = f.first { $0.detectorID == "swift-bic" }
        XCTAssertNotNil(bic, "CARDUS33 should match the BIC pattern")
        XCTAssertEqual(bic?.confidence, .low, "a self-contained lexicon word must not boost the finding")
    }

    func testBICStillBoostedByNeighborKeyword() {
        // The fix must not disable real corroboration: a BIC token with no lexicon
        // word of its own, next to a genuine keyword, is still promoted.
        let f = makeEngine().scan("wire to account XYZWUS33 today", context: ctx())
        let bic = f.first { $0.detectorID == "swift-bic" }
        XCTAssertEqual(bic?.confidence, .medium, "a neighboring keyword should still boost")
    }

    func testKeywordCorroborationRequiresWordBoundary() {
        // codex round-45: "discard"/"postcard" contain "card" but are not the word
        // "card"; substring corroboration would falsely boost the BIC to medium and
        // trip warn-financial on ordinary text. Boundary matching must reject these.
        for text in ["discard XYZWUS33 now", "postcard XYZWUS33 sent"] {
            let f = makeEngine().scan(text, context: ctx())
            let bic = f.first { $0.detectorID == "swift-bic" }
            XCTAssertEqual(bic?.confidence, .low, "substring inside another word must not corroborate: \(text)")
        }
        // A real word-boundary keyword (even punctuation-adjacent) still boosts.
        let f2 = makeEngine().scan("re: card XYZWUS33", context: ctx())
        XCTAssertEqual(f2.first { $0.detectorID == "swift-bic" }?.confidence, .medium)
    }

    func testKoreanKeywordStillCorroboratesAsSubstring() {
        // Korean has no space-delimited word boundaries, so CJK keywords keep
        // substring matching: 카드 inside 신용카드번호 must still corroborate.
        let f = makeEngine().scan("신용카드번호 XYZWUS33", context: ctx())
        XCTAssertEqual(f.first { $0.detectorID == "swift-bic" }?.confidence, .medium)
    }

    func testIBANNotReportedInsideLongerToken() {
        // codex round-43: a valid IBAN that runs straight into more word chars
        // (no separator) is part of a longer ID/token, not an IBAN, and must not be
        // reported as a high-confidence finding.
        let f = makeEngine().scan("ref DE89370400440532013000A9 end", context: ctx())
        XCTAssertFalse(f.contains { $0.type.id == "iban" }, "IBAN must not be reported inside a longer token")
    }

    func testLowercaseIBANDetected() {
        // codex round-41: a typed/pasted lower/mixed-case IBAN must still match the
        // pattern (the validator uppercases before the checksum). Otherwise real
        // bank-account data slips past the clipboard/file scanners.
        let f = makeEngine().scan("account gb29nwbk60161331926819 thanks", context: ctx())
        XCTAssertTrue(f.contains { $0.type.id == "iban" }, "lowercase IBAN should be detected")
    }

    func testGroupedIBANBoundaryRefinedAwayFromTrailingWords() {
        // codex round-41/42: a grouped IBAN is structurally indistinguishable from
        // one followed by short words, so the regex over-captures and the validator
        // refines the boundary back to the exact country-length IBAN. This must hold
        // whether the real final group is short (GB '...32') or a full four chars
        // (BE '...7034'), and whether the trailing word is lower- or upper-case.
        // The mask must reveal the IBAN's own last two chars — proving the span was
        // trimmed to the IBAN and not the trailing word.
        let cases: [(String, String)] = [
            ("please wire to GB82 WEST 1234 5698 7654 32 by EOD", "32"),
            ("send GB82 WEST 1234 5698 7654 32 BY EOD now", "32"),
            ("account BE68 5390 0754 7034 by reference today", "34"),
            ("acct BE68 5390 0754 7034 NOW please", "34"),
        ]
        for (text, ibanTail) in cases {
            let f = makeEngine().scan(text, context: ctx())
            let iban = f.first { $0.type.id == "iban" }
            XCTAssertNotNil(iban, "IBAN with trailing words should still be detected: \(text)")
            XCTAssertTrue(iban?.maskedValue.hasSuffix(ibanTail) ?? false,
                          "mask '\(iban?.maskedValue ?? "nil")' should end with IBAN tail '\(ibanTail)', not a trailing word")
            XCTAssertFalse(iban?.maskedValue.lowercased().contains("by") ?? true,
                           "trailing word must not be inside the IBAN span")
        }
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
