import Foundation

/// Blends finding severity/confidence, destination risk, and data volume into a
/// single 0...1 risk score for ranking events in dashboards and for coarse
/// thresholds. Deterministic and side-effect-free.
public enum RiskScorer {

    public static func score(findings: [Finding], context: InspectionContext) -> Double {
        let severityFactor: Double = {
            guard let top = findings.map(\.severity).max() else { return 0 }
            return Double(top.rank) / Double(Severity.critical.rank)
        }()

        let confidenceFactor: Double = findings.map { $0.confidence.score }.max() ?? 0

        let destinationFactor: Double = {
            switch context.destination.tier {
            case .sanctioned: return 0.0
            case .monitored: return 0.3
            case .unknown: return 0.4
            case .unsanctioned: return 0.7
            case .blocked: return 1.0
            }
        }()

        let volumeFactor = min(1.0, Double(findings.count) / 20.0)

        // Severity dominates; destination and confidence modulate; volume nudges.
        let raw = 0.5 * severityFactor
                + 0.2 * confidenceFactor
                + 0.2 * destinationFactor
                + 0.1 * volumeFactor
        return min(1.0, max(0.0, raw))
    }
}
