import Foundation

/// A declarative, regex-based detection rule. The full pattern library is a
/// collection of these, and customers can ship additional rules as JSON without
/// recompiling the agent.
public struct PatternRule: Codable, Hashable, Sendable, Identifiable {
    public let id: String
    public let name: String
    public let category: DataCategory
    public let severity: Severity
    /// ICU / NSRegularExpression-compatible pattern (no surrounding slashes).
    public let regex: String
    /// Optional checksum/statistical validator applied to each match.
    public let validator: ValidatorKind
    /// Confidence assigned to matches that pass the validator.
    public let confidence: Confidence
    /// Which capture group holds the sensitive value (0 = entire match).
    public let captureGroup: Int
    public let description: String
    public let exampleMatch: String
    public let falsePositiveNotes: String
    /// ISO-3166 alpha-2, or "global".
    public let country: String
    /// Whether the rule is active.
    public let enabled: Bool

    public init(
        id: String,
        name: String,
        category: DataCategory,
        severity: Severity,
        regex: String,
        validator: ValidatorKind = .none,
        confidence: Confidence = .medium,
        captureGroup: Int = 0,
        description: String = "",
        exampleMatch: String = "",
        falsePositiveNotes: String = "",
        country: String = "global",
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.category = category
        self.severity = severity
        self.regex = regex
        self.validator = validator
        self.confidence = confidence
        self.captureGroup = captureGroup
        self.description = description
        self.exampleMatch = exampleMatch
        self.falsePositiveNotes = falsePositiveNotes
        self.country = country
        self.enabled = enabled
    }

    /// The `SensitiveDataType` this rule detects.
    public var dataType: SensitiveDataType {
        SensitiveDataType(id: id, name: name, category: category)
    }

    // Decoding tolerates older/leaner JSON (defaults fill missing fields).
    enum CodingKeys: String, CodingKey {
        case id, name, category, severity, regex, validator, confidence
        case captureGroup, description, exampleMatch, falsePositiveNotes, country, enabled
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        category = try c.decode(DataCategory.self, forKey: .category)
        severity = try c.decode(Severity.self, forKey: .severity)
        regex = try c.decode(String.self, forKey: .regex)
        validator = try c.decodeIfPresent(ValidatorKind.self, forKey: .validator) ?? .none
        confidence = try c.decodeIfPresent(Confidence.self, forKey: .confidence) ?? .medium
        captureGroup = try c.decodeIfPresent(Int.self, forKey: .captureGroup) ?? 0
        description = try c.decodeIfPresent(String.self, forKey: .description) ?? ""
        exampleMatch = try c.decodeIfPresent(String.self, forKey: .exampleMatch) ?? ""
        falsePositiveNotes = try c.decodeIfPresent(String.self, forKey: .falsePositiveNotes) ?? ""
        country = try c.decodeIfPresent(String.self, forKey: .country) ?? "global"
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }
}
