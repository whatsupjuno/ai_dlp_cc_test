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

                let value = ns.substring(with: range)
                guard Validators.run(rule.validator, on: value) else { return }

                let note: String? = rule.validator == .none
                    ? nil
                    : "validated:\(rule.validator.rawValue)"

                findings.append(Finding(
                    type: rule.dataType,
                    detectorID: rule.id,
                    severity: rule.severity,
                    confidence: rule.confidence,
                    span: TextSpan(range),
                    maskedValue: Masking.mask(value),
                    valueFingerprint: Masking.fingerprint(value),
                    note: note
                ))

                count += 1
                if count >= self.maxMatchesPerRule { stop.pointee = true }
            }
        }
        return findings
    }
}
