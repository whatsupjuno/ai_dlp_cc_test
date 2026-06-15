import Foundation

/// Promotes a finding's confidence when corroborating keywords appear near the
/// match — the standard DLP lever for cutting false positives. A bare 9-digit
/// number is weak; the same number with "SSN:" three characters to its left is
/// strong. Operates purely on character windows, so it is cheap and language-
/// agnostic (the default lexicon includes Korean terms).
public struct ContextBooster: Sendable {
    /// How many UTF-16 units on each side of a match to inspect.
    public let window: Int
    /// Lowercased keywords per category that corroborate a match.
    public let lexicon: [DataCategory: [String]]

    public init(window: Int = 48, lexicon: [DataCategory: [String]] = ContextBooster.defaultLexicon) {
        self.window = window
        self.lexicon = lexicon
    }

    public static let defaultLexicon: [DataCategory: [String]] = [
        .financial: ["card", "credit", "debit", "visa", "mastercard", "amex", "account",
                     "iban", "routing", "payment", "cvv", "expiry", "카드", "계좌", "결제"],
        .governmentID: ["ssn", "social security", "passport", "national id", "tax id",
                        "resident registration", "주민", "주민등록", "여권", "외국인등록"],
        .credential: ["key", "token", "secret", "password", "passwd", "api", "bearer",
                      "authorization", "auth", "credential", "access", "private",
                      "비밀번호", "암호", "토큰", "인증"],
        .pii: ["email", "e-mail", "phone", "mobile", "tel", "address", "name", "dob",
               "birth", "전화", "휴대폰", "이메일", "주소", "이름", "생년월일"],
        .health: ["patient", "diagnosis", "npi", "dea", "icd", "medical", "health",
                  "prescription", "환자", "진단", "처방", "의료"],
        .network: ["host", "server", "database", "connection", "jdbc", "dsn", "endpoint"],
        .sourceSecret: ["config", "env", "secret", "private"],
    ]

    /// Return a new finding array with corroborated findings' confidence bumped
    /// one level (and a `context:` note appended). Findings without corroboration
    /// are returned unchanged.
    public func boost(_ findings: [Finding], in text: String) -> [Finding] {
        guard !findings.isEmpty else { return findings }
        let ns = text as NSString
        let len = ns.length

        return findings.map { f in
            guard let keywords = lexicon[f.category], !keywords.isEmpty else { return f }
            let lo = max(0, f.span.location - window)
            let hi = min(len, f.span.upperBound + window)
            guard hi > lo else { return f }

            // Inspect only the context on EITHER SIDE of the match, never the match
            // itself: a token like "CARDUS33"/"VISAGB2L" contains a lexicon word
            // ("card"/"visa") inside its own span, so including it would let the
            // finding self-corroborate and cross the warn threshold with no real
            // surrounding context. The two sides are joined with a newline so a
            // keyword can't be spuriously formed across the excised gap.
            let leftLen = f.span.location - lo
            let rightLen = hi - f.span.upperBound
            let left = leftLen > 0 ? ns.substring(with: NSRange(location: lo, length: leftLen)) : ""
            let right = rightLen > 0 ? ns.substring(with: NSRange(location: f.span.upperBound, length: rightLen)) : ""
            let around = (left + "\n" + right).lowercased()

            guard keywords.contains(where: { ContextBooster.corroborates(around, $0) }) else { return f }
            guard f.confidence < .high else { return f } // already maxed

            let bumped: Confidence = f.confidence == .low ? .medium : .high
            return Finding(
                id: f.id, type: f.type, detectorID: f.detectorID,
                severity: f.severity, confidence: bumped, span: f.span,
                maskedValue: f.maskedValue, valueFingerprint: f.valueFingerprint,
                note: [f.note, "context-corroborated"].compactMap { $0 }.joined(separator: ";")
            )
        }
    }

    /// Whether `keyword` corroborates within `haystack` (already lowercased).
    ///
    /// Latin keywords must match at WORD BOUNDARIES so that "discard"/"postcard"
    /// do not corroborate via the substring "card". CJK keywords (e.g. Korean
    /// 카드/주민) are matched as substrings because those scripts are not written
    /// with space-delimited word boundaries, so `\b`-style boundaries don't apply.
    static func corroborates(_ haystack: String, _ keyword: String) -> Bool {
        guard !keyword.isEmpty else { return false }
        // Non-ASCII (CJK etc.): no Latin word boundaries — substring match.
        guard keyword.unicodeScalars.allSatisfy({ $0.isASCII }) else {
            return haystack.contains(keyword)
        }
        // Latin: accept only occurrences bounded by non-word characters on both
        // sides (start/end of string counts as a boundary).
        var lower = haystack.startIndex
        while let r = haystack.range(of: keyword, range: lower..<haystack.endIndex) {
            let beforeOK = r.lowerBound == haystack.startIndex
                || !isWordChar(haystack[haystack.index(before: r.lowerBound)])
            let afterOK = r.upperBound == haystack.endIndex
                || !isWordChar(haystack[r.upperBound])
            if beforeOK && afterOK { return true }
            lower = haystack.index(after: r.lowerBound)
        }
        return false
    }

    private static func isWordChar(_ c: Character) -> Bool {
        c.isLetter || c.isNumber || c == "_"
    }
}
