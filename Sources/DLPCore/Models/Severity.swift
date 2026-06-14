import Foundation

/// Risk severity associated with a detected piece of sensitive data or with a
/// policy verdict. Ordered so that comparisons (`>=`) express "at least as severe".
public enum Severity: String, Codable, CaseIterable, Comparable, Sendable {
    case info
    case low
    case medium
    case high
    case critical

    /// Monotonic rank used for ordering and threshold comparisons.
    public var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.rank < rhs.rank
    }

    /// A short, stable symbol suitable for compact CLI / log output.
    public var symbol: String {
        switch self {
        case .info: return "·"
        case .low: return "▽"
        case .medium: return "◆"
        case .high: return "▲"
        case .critical: return "⛔"
        }
    }

    /// ANSI colour code (foreground) for terminal rendering.
    public var ansiColor: Int {
        switch self {
        case .info: return 90      // bright black / grey
        case .low: return 36       // cyan
        case .medium: return 33    // yellow
        case .high: return 35      // magenta
        case .critical: return 31  // red
        }
    }
}
