import Foundation

/// How confident a detector is that a match is a true positive. Used both to
/// rank findings and to drive policy thresholds (e.g. "block only high-confidence
/// critical findings, but audit everything").
public enum Confidence: String, Codable, CaseIterable, Comparable, Sendable {
    case low
    case medium
    case high

    public var rank: Int {
        switch self {
        case .low: return 0
        case .medium: return 1
        case .high: return 2
        }
    }

    public static func < (lhs: Confidence, rhs: Confidence) -> Bool {
        lhs.rank < rhs.rank
    }

    /// A normalized 0...1 score, convenient for blended risk scoring.
    public var score: Double {
        switch self {
        case .low: return 0.4
        case .medium: return 0.7
        case .high: return 0.95
        }
    }
}
