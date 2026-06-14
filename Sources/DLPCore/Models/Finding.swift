import Foundation

/// A character range within inspected text, expressed in UTF-16 offsets so it
/// round-trips cleanly with `NSRange` (what `NSRegularExpression` produces) while
/// staying serializable and independent of any particular `String` instance.
public struct TextSpan: Codable, Hashable, Sendable {
    /// UTF-16 offset of the first code unit of the match.
    public let location: Int
    /// Number of UTF-16 code units in the match.
    public let length: Int

    public init(location: Int, length: Int) {
        self.location = location
        self.length = length
    }

    public init(_ range: NSRange) {
        self.location = range.location
        self.length = range.length
    }

    public var nsRange: NSRange { NSRange(location: location, length: length) }
    public var upperBound: Int { location + length }

    /// Whether this span overlaps `other` (touching endpoints do not count).
    public func overlaps(_ other: TextSpan) -> Bool {
        location < other.upperBound && other.location < upperBound
    }
}

/// A single detected occurrence of sensitive data.
public struct Finding: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    /// The kind of sensitive data found.
    public let type: SensitiveDataType
    /// The id of the rule / detector that produced this finding.
    public let detectorID: String
    public let severity: Severity
    public let confidence: Confidence
    /// Location of the match within the inspected text.
    public let span: TextSpan
    /// A privacy-preserving, masked preview of the matched value (never the raw
    /// secret — only a few edge characters are retained). Safe to log.
    public let maskedValue: String
    /// Lowercased SHA-256 of the raw match, used for correlation/dedup without
    /// ever persisting the plaintext. 16 hex chars (64 bits) is plenty here.
    public let valueFingerprint: String
    /// Optional human-readable note (e.g. "passed Luhn checksum").
    public let note: String?

    public init(
        id: UUID = UUID(),
        type: SensitiveDataType,
        detectorID: String,
        severity: Severity,
        confidence: Confidence,
        span: TextSpan,
        maskedValue: String,
        valueFingerprint: String,
        note: String? = nil
    ) {
        self.id = id
        self.type = type
        self.detectorID = detectorID
        self.severity = severity
        self.confidence = confidence
        self.span = span
        self.maskedValue = maskedValue
        self.valueFingerprint = valueFingerprint
        self.note = note
    }

    public var category: DataCategory { type.category }
}
