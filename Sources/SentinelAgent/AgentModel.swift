import Foundation
import Combine
import DLPCore
import DLPDaemon

/// Observable state backing the menu-bar UI. All mutations are marshalled onto
/// the main thread by the `AppDelegate` before being applied, so SwiftUI's
/// publishing contract is honored without formal actor isolation.
final class AgentModel: ObservableObject, @unchecked Sendable {
    // @unchecked Sendable: every stored property is mutated only on the main
    // thread (the AppDelegate marshals all updates there), so it is safe to
    // reference this model from the engine's @Sendable verdict callback.

    struct Activity: Identifiable {
        let id = UUID()
        let date: Date
        let action: PolicyAction
        let channel: Channel
        let destination: String
        let topSeverity: Severity
        let riskScore: Double
        let findingNames: [String]
        let reason: String
    }

    @Published var running = false
    @Published var enforcing = true
    @Published var policyName = ""
    @Published var patternCount = 0
    @Published var serviceCount = 0

    @Published var totalEvents = 0
    @Published var blockedCount = 0
    @Published var redactedCount = 0
    @Published var warnedCount = 0
    @Published private(set) var recent: [Activity] = []

    /// A `.warn` verdict awaiting the user's justify-or-keep-blocked decision.
    /// Retains the original (sensitive) clipboard text so it can be restored on
    /// confirmation; held only in memory and cleared as soon as the user decides.
    struct PendingWarning: Identifiable {
        let id = UUID()
        let text: String
        let summary: String
        let destination: String
        /// The pasteboard change-count this warning was raised for. If the
        /// clipboard moves on before the user decides, the pending warning is
        /// stale and must not overwrite the new clipboard content.
        let changeCount: Int
    }
    @Published var pendingWarning: PendingWarning?

    func record(_ verdict: DLPVerdict, payload: MonitoredPayload) {
        totalEvents += 1
        switch verdict.action {
        case .block, .quarantine: blockedCount += 1
        case .redact: redactedCount += 1
        case .warn: warnedCount += 1
        default: break
        }
        let activity = Activity(
            date: Date(),
            action: verdict.action,
            channel: verdict.context.channel,
            destination: verdict.context.destination.displayName,
            topSeverity: verdict.topSeverity,
            riskScore: verdict.riskScore,
            findingNames: Array(Set(verdict.findings.map(\.type.name))).sorted(),
            reason: verdict.reason
        )
        recent.insert(activity, at: 0)
        if recent.count > 100 { recent.removeLast(recent.count - 100) }
    }

    /// The status-bar glyph reflects the most recent risk level.
    var statusSymbol: String {
        guard running else { return "shield.slash" }
        if blockedCount > 0 || (recent.first?.action == .block) { return "shield.lefthalf.filled" }
        return "shield.fill"
    }
}
