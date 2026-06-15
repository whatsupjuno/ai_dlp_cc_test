import Foundation

/// Matches organization-defined keywords / classification banners that signal
/// confidential material — e.g. "CONFIDENTIAL", "INTERNAL USE ONLY", project
/// code-names, or a customer's document-classification labels. These are pure
/// substring/word matches (case-insensitive) and are fully data-driven so an
/// admin can manage them without touching regex.
public final class KeywordDetector: Detector, @unchecked Sendable {
    public let id: String

    public struct Keyword: Codable, Hashable, Sendable {
        public let phrase: String
        public let severity: Severity
        public let wholeWord: Bool
        public init(phrase: String, severity: Severity = .medium, wholeWord: Bool = true) {
            self.phrase = phrase
            self.severity = severity
            self.wholeWord = wholeWord
        }
    }

    private let detector: RegexDetector

    public init(id: String = "keyword", keywords: [Keyword]) {
        self.id = id
        // Compile each keyword into a case-insensitive regex rule and reuse the
        // hardened RegexDetector machinery (bounds checks, match caps, masking).
        let rules: [PatternRule] = keywords.enumerated().map { index, kw in
            let escaped = NSRegularExpression.escapedPattern(for: kw.phrase)
            let body = kw.wholeWord ? "\\b\(escaped)\\b" : escaped
            return PatternRule(
                id: "\(id)-\(index)",
                name: "Keyword: \(kw.phrase)",
                category: .sourceSecret,
                severity: kw.severity,
                regex: "(?i)\(body)",
                validator: .none,
                confidence: .high,
                description: "Organization-defined sensitivity keyword.",
                exampleMatch: kw.phrase
            )
        }
        self.detector = RegexDetector(id: id, rules: rules)
    }

    public func scan(_ text: String, context: InspectionContext) -> [Finding] {
        detector.scan(text, context: context)
    }
}
