import Foundation

/// Loads the built-in detection pattern pack (shipped as a JSON resource) plus
/// the default keyword list, and lets callers merge in customer-supplied rules.
///
/// The pack is data, not code: an admin can push an updated `patterns.json`
/// without recompiling the agent. If the bundled resource is ever missing or
/// corrupt, we fall back to a small hard-coded core set so the agent still
/// detects the highest-risk data types rather than failing open.
public enum PatternLibrary {

    private struct Pack: Decodable {
        let version: Int
        let patterns: [PatternRule]
    }

    /// The built-in pattern pack (61 rules across financial, government-ID,
    /// credential, PII, health, network and source-secret categories).
    public static let builtin: [PatternRule] = loadBuiltin()

    /// The default organization keyword set (classification banners etc.).
    public static let defaultKeywords: [KeywordDetector.Keyword] = [
        .init(phrase: "CONFIDENTIAL", severity: .medium),
        .init(phrase: "INTERNAL USE ONLY", severity: .medium),
        .init(phrase: "PROPRIETARY", severity: .medium),
        .init(phrase: "TRADE SECRET", severity: .high),
        .init(phrase: "ATTORNEY-CLIENT PRIVILEGED", severity: .high),
        .init(phrase: "대외비", severity: .medium),       // KR: "confidential / restricted"
        .init(phrase: "기밀", severity: .high),           // KR: "secret"
        .init(phrase: "사내한", severity: .medium),       // KR: "internal only"
    ]

    private static func loadBuiltin() -> [PatternRule] {
        guard let data = DLPResources.data(named: "patterns", withExtension: "json"),
              let pack = try? JSONDecoder().decode(Pack.self, from: data),
              !pack.patterns.isEmpty else {
            return coreFallback
        }
        return pack.patterns
    }

    /// Decode an external pattern pack (e.g. an MDM-delivered custom rule set).
    /// Returns the parsed rules; throws on malformed JSON so callers can surface
    /// the error rather than silently ignoring a bad push.
    public static func load(fromJSON data: Data) throws -> [PatternRule] {
        if let pack = try? JSONDecoder().decode(Pack.self, from: data) {
            return pack.patterns
        }
        // Also accept a bare array of rules.
        return try JSONDecoder().decode([PatternRule].self, from: data)
    }

    /// Minimal high-confidence core used only if the resource pack can't load.
    static let coreFallback: [PatternRule] = [
        PatternRule(id: "us-ssn", name: "US Social Security Number", category: .governmentID,
                    severity: .critical,
                    regex: #"\b(?!000|666|9[0-9]{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b"#,
                    confidence: .high, description: "US SSN (dashed)."),
        PatternRule(id: "cc-pan-separated", name: "Credit card", category: .financial,
                    severity: .high, regex: #"\b[0-9](?:[ -]?[0-9]){12,18}\b"#,
                    validator: .luhn, confidence: .medium, description: "Luhn-validated PAN."),
        PatternRule(id: "anthropic-api-key", name: "Anthropic API key", category: .credential,
                    severity: .critical, regex: #"\bsk-ant-[a-zA-Z0-9_\-]{20,}\b"#,
                    confidence: .high, description: "Anthropic API key."),
        PatternRule(id: "openai-api-key", name: "OpenAI API key", category: .credential,
                    severity: .critical, regex: #"\bsk-[a-zA-Z0-9]{20,}\b"#,
                    confidence: .high, description: "OpenAI API key."),
        PatternRule(id: "aws-access-key-id", name: "AWS Access Key ID", category: .credential,
                    severity: .high, regex: #"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"#,
                    confidence: .high, description: "AWS access key id."),
        PatternRule(id: "private-key-pem", name: "PEM private key", category: .credential,
                    severity: .critical, regex: #"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"#,
                    confidence: .high, description: "PEM private key header."),
        PatternRule(id: "email-address", name: "Email address", category: .pii,
                    severity: .low, regex: #"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"#,
                    confidence: .high, description: "Email address."),
        PatternRule(id: "kr-rrn", name: "Korean RRN", category: .governmentID, severity: .critical,
                    regex: #"\b[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])-[1-4][0-9]{6}\b"#,
                    validator: .krRRNChecksum, confidence: .high, description: "Korean resident registration number."),
    ]
}
