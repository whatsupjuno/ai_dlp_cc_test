import Foundation

/// A component that scans text and emits findings. Detectors must be cheap to
/// run repeatedly (the clipboard monitor invokes them on every change) and must
/// never throw — a malformed rule should degrade to "no findings", never crash
/// the agent.
public protocol Detector: Sendable {
    /// Stable identifier (used in audit records and to disable detectors via config).
    var id: String { get }
    /// Scan `text` and return all findings. `context` lets detectors tune
    /// behaviour (e.g. an NER detector may skip tiny clipboard snippets).
    func scan(_ text: String, context: InspectionContext) -> [Finding]
}
