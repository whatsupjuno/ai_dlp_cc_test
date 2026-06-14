import XCTest
@testable import DLPCore

final class PatternLibraryTests: XCTestCase {

    func testBuiltinLoads() {
        XCTAssertGreaterThanOrEqual(PatternLibrary.builtin.count, 60,
                                    "Built-in pattern pack should load from the bundled resource")
    }

    func testAllPatternsCompile() {
        let detector = RegexDetector(rules: PatternLibrary.builtin)
        XCTAssertTrue(detector.diagnostics.isEmpty,
                      "Patterns failed to compile: \(detector.diagnostics)")
    }

    /// Every rule's `exampleMatch` must be matched by its own regex; and for the
    /// deterministic checksum validators, the example must also pass validation.
    func testExamplesMatchTheirOwnRule() {
        let checksumValidators: Set<ValidatorKind> = [.luhn, .ibanMod97, .krRRNChecksum, .abaRouting, .npiLuhn]
        for rule in PatternLibrary.builtin {
            guard !rule.exampleMatch.isEmpty else { continue }
            guard let re = try? NSRegularExpression(pattern: rule.regex) else {
                XCTFail("rule \(rule.id) regex did not compile"); continue
            }
            let ns = rule.exampleMatch as NSString
            let match = re.firstMatch(in: rule.exampleMatch, range: NSRange(location: 0, length: ns.length))
            XCTAssertNotNil(match, "rule \(rule.id): example '\(rule.exampleMatch)' did not match its regex")

            if checksumValidators.contains(rule.validator), let m = match {
                let value = ns.substring(with: m.range)
                XCTAssertTrue(Validators.run(rule.validator, on: value),
                              "rule \(rule.id): example '\(value)' failed validator \(rule.validator.rawValue)")
            }
        }
    }

    func testLoadCustomPackFromJSON() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "custom-patterns", withExtension: "json"))
        let data = try Data(contentsOf: url)
        let rules = try PatternLibrary.load(fromJSON: data)
        XCTAssertEqual(rules.count, 1)
        XCTAssertEqual(rules.first?.id, "acme-employee-id")
    }

    func testMatchCapCountsRawMatchesNotJustFindings() {
        // Cap of 3 raw matches. The first 4 candidates are Luhn-invalid (drop),
        // the 5th is Luhn-valid. The cap must stop after 3 raw matches — before
        // the valid 5th — so a payload of invalid candidates can't force unbounded
        // validation work (DoS bound).
        let rule = PatternRule(id: "pan16", name: "PAN", category: .financial, severity: .high,
                               regex: #"\b[0-9]{16}\b"#, validator: .luhn, confidence: .high)
        let detector = RegexDetector(rules: [rule], maxMatchesPerRule: 3)
        let text = "1111111111111111 2222222222222222 3333333333333333 4444444444444444 4111111111111111"
        let f = detector.scan(text, context: InspectionContext(channel: .manualScan))
        XCTAssertTrue(f.isEmpty, "cap must bound raw matches; the valid 5th is never reached")
    }

    func testMalformedRuleIsQuarantinedNotCrashing() {
        // A rule with an invalid regex must be skipped, not crash the detector.
        let bad = PatternRule(id: "bad", name: "Bad", category: .pii, severity: .low,
                              regex: "([unclosed", confidence: .low)
        let good = PatternRule(id: "good", name: "Good", category: .pii, severity: .low,
                               regex: #"\bGOOD\b"#, confidence: .high)
        let detector = RegexDetector(rules: [bad, good])
        XCTAssertEqual(detector.diagnostics.count, 1)
        XCTAssertNotNil(detector.diagnostics["bad"])
        let findings = detector.scan("this is GOOD", context: InspectionContext(channel: .manualScan))
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.detectorID, "good")
    }
}
