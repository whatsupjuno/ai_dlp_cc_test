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
            let around = ns.substring(with: NSRange(location: lo, length: hi - lo)).lowercased()

            guard keywords.contains(where: { around.contains($0) }) else { return f }
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
}
