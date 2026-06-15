import Foundation

/// Runs a set of `PatternRule`s against text using `NSRegularExpression`, applying
/// each rule's checksum/statistical validator to suppress false positives.
///
/// Regexes are compiled once at construction. A rule whose pattern fails to
/// compile is recorded in `diagnostics` and skipped — a bad customer rule can
/// never crash or disable the rest of the engine.
public final class RegexDetector: Detector, @unchecked Sendable {
    // NSRegularExpression is documented thread-safe for matching, and every
    // stored property here is immutable after init, so unchecked Sendable holds.

    public let id: String

    private struct Compiled {
        let rule: PatternRule
        let regex: NSRegularExpression
    }

    private let compiled: [Compiled]

    /// Non-fatal compile errors, keyed by rule id → message. Surfaced by the CLI
    /// (`dlpctl patterns --lint`) so authors can fix bad rules.
    public let diagnostics: [String: String]

    /// Cap on matches reported per rule per scan, to bound work on adversarial
    /// or simply huge inputs.
    private let maxMatchesPerRule: Int

    public init(id: String = "regex", rules: [PatternRule], maxMatchesPerRule: Int = 256) {
        self.id = id
        self.maxMatchesPerRule = maxMatchesPerRule
        var compiled: [Compiled] = []
        var diagnostics: [String: String] = [:]
        for rule in rules where rule.enabled {
            do {
                let re = try NSRegularExpression(pattern: rule.regex, options: [])
                compiled.append(Compiled(rule: rule, regex: re))
            } catch {
                diagnostics[rule.id] = error.localizedDescription
            }
        }
        self.compiled = compiled
        self.diagnostics = diagnostics
    }

    public func scan(_ text: String, context: InspectionContext) -> [Finding] {
        guard !text.isEmpty else { return [] }
        let ns = text as NSString
        let fullRange = NSRange(location: 0, length: ns.length)
        var findings: [Finding] = []

        for entry in compiled {
            let rule = entry.rule
            var count = 0
            entry.regex.enumerateMatches(in: text, options: [], range: fullRange) { match, _, stop in
                guard let match else { return }
                // Prefer the configured capture group; fall back to the whole match.
                var range = match.range
                if rule.captureGroup > 0, rule.captureGroup < match.numberOfRanges {
                    let g = match.range(at: rule.captureGroup)
                    if g.location != NSNotFound { range = g }
                }
                guard range.location != NSNotFound, range.length > 0,
                      NSMaxRange(range) <= ns.length else { return }

                // Count EVERY raw candidate match toward the cap (before any
                // validator early-return), so a payload full of Luhn-invalid
                // PAN-shaped numbers can't force unbounded validation work — the
                // documented DoS bound must hold regardless of how many drop.
                count += 1
                if count >= self.maxMatchesPerRule { stop.pointee = true }

                var value = ns.substring(with: range)

                // Boundary refinement: a greedy regex can over-capture trailing
                // text (e.g. a grouped IBAN swallowing a following short word).
                // Validators that know the exact length from the value itself
                // (IBAN, via the country registry) trim the span back to the real
                // match, so the finding's span/mask/fingerprint reflect only the
                // sensitive value. IBAN charset is ASCII, so the character count
                // returned equals the UTF-16 length used here.
                if let refined = Validators.refinedPrefixLength(rule.validator, on: value),
                   refined > 0, refined < range.length {
                    range = NSRange(location: range.location, length: refined)
                    value = ns.substring(with: range)
                }

                // Apply the validator. A hard failure (e.g. Luhn on a card) drops
                // the match; a *soft* failure (KR RRN checksum on a post-2020
                // randomized number) keeps it at one lower confidence level — but
                // only if it's still plausible (a valid RRN calendar date).
                var confidence = rule.confidence
                var note: String? = rule.validator == .none ? nil : "validated:\(rule.validator.rawValue)"
                if rule.validator != .none, !Validators.run(rule.validator, on: value) {
                    guard rule.validator.failureIsSoft,
                          Validators.softFailStillPlausible(rule.validator, on: value) else { return }
                    confidence = rule.confidence.downgraded
                    note = "checksum-unverified:\(rule.validator.rawValue)"
                }

                findings.append(Finding(
                    type: rule.dataType,
                    detectorID: rule.id,
                    severity: rule.severity,
                    confidence: confidence,
                    span: TextSpan(range),
                    maskedValue: Masking.mask(value),
                    valueFingerprint: Masking.fingerprint(value),
                    note: note
                ))
            }
        }
        return findings
    }
}
