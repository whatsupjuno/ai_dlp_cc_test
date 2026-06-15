import Foundation

/// Aggregates every configured `Detector`, runs them over the input, and resolves
/// overlapping matches into a clean, de-duplicated finding set.
///
/// Overlap resolution is priority-based interval selection: when two findings
/// cover overlapping bytes, the higher-priority one wins (more severe, then more
/// confident, then more specific than NER, then longer). This stops the same
/// secret being counted twice (e.g. a generic "16 digits" rule and a "Visa" rule
/// both firing on one PAN).
public struct DetectionEngine: Sendable {
    public let detectors: [any Detector]
    /// Truncate inspection to this many UTF-16 units; 0 = no limit. Network
    /// monitors set this so a 50 MB upload doesn't stall the filter.
    public let maxInspectLength: Int
    /// Optional proximity-based confidence booster (nil disables it).
    public let contextBooster: ContextBooster?

    public init(
        detectors: [any Detector],
        maxInspectLength: Int = 0,
        contextBooster: ContextBooster? = ContextBooster()
    ) {
        self.detectors = detectors
        self.maxInspectLength = maxInspectLength
        self.contextBooster = contextBooster
    }

    /// Run all detectors and return the resolved finding set, sorted by position.
    public func scan(_ text: String, context: InspectionContext) -> [Finding] {
        let input = Self.truncate(text, toUTF16: maxInspectLength)

        var raw: [Finding] = []
        for detector in detectors {
            raw.append(contentsOf: detector.scan(input, context: context))
        }
        let resolved = Self.resolveOverlaps(raw)
        return contextBooster?.boost(resolved, in: input) ?? resolved
    }

    /// Convenience: a `DetectionSummary` aggregating findings by category/severity.
    public func summarize(_ findings: [Finding]) -> DetectionSummary {
        DetectionSummary(findings: findings)
    }

    // MARK: - Inspection-length cap

    /// Truncate `text` to at most `limit` UTF-16 units, snapping back to a valid
    /// `Character` boundary. A naive `String(text.utf16[..<end])` returns `nil`
    /// when the cut lands between the two code units of a supplementary scalar
    /// (e.g. an emoji), and the old fallback then scanned the *entire* text —
    /// letting a crafted payload defeat the inspection cap. Walking back to a
    /// real boundary keeps the cap honest.
    static func truncate(_ text: String, toUTF16 limit: Int) -> String {
        guard limit > 0, text.utf16.count > limit else { return text }
        let utf16 = text.utf16
        var cut = utf16.index(utf16.startIndex, offsetBy: limit)
        while cut > utf16.startIndex, String.Index(cut, within: text) == nil {
            cut = utf16.index(before: cut)
        }
        guard let boundary = String.Index(cut, within: text) else { return text }
        return String(text[..<boundary])
    }

    // MARK: - Overlap resolution

    static func resolveOverlaps(_ findings: [Finding]) -> [Finding] {
        guard findings.count > 1 else { return findings }

        // Sort by descending priority so greedy selection keeps the best.
        let ordered = findings.sorted { a, b in
            let pa = priority(a), pb = priority(b)
            if pa != pb { return pa > pb }
            // Deterministic tiebreak: earliest, then by detector id.
            if a.span.location != b.span.location { return a.span.location < b.span.location }
            return a.detectorID < b.detectorID
        }

        var accepted: [Finding] = []
        accepted.reserveCapacity(ordered.count)
        for f in ordered {
            if accepted.contains(where: { $0.span.overlaps(f.span) }) { continue }
            accepted.append(f)
        }
        return accepted.sorted { $0.span.location < $1.span.location }
    }

    /// Higher is better. Packs (severity, confidence, specificity, length) into a
    /// single comparable integer.
    private static func priority(_ f: Finding) -> Int {
        let specific = f.detectorID == "nl-ner" ? 0 : 1
        let len = min(f.span.length, 0xFFFF)
        return (f.severity.rank << 28) | (f.confidence.rank << 25) | (specific << 24) | len
    }
}

/// A roll-up of findings for reporting and policy thresholds. Breakdowns are
/// keyed by the enums' raw string values so they serialize as clean JSON objects.
public struct DetectionSummary: Codable, Hashable, Sendable {
    public let total: Int
    public let byCategory: [String: Int]
    public let bySeverity: [String: Int]
    public let topSeverity: Severity
    public let distinctTypes: Int

    public init(findings: [Finding]) {
        total = findings.count
        var cat: [String: Int] = [:]
        var sev: [String: Int] = [:]
        var types = Set<String>()
        for f in findings {
            cat[f.category.rawValue, default: 0] += 1
            sev[f.severity.rawValue, default: 0] += 1
            types.insert(f.type.id)
        }
        byCategory = cat
        bySeverity = sev
        topSeverity = findings.map(\.severity).max() ?? .info
        distinctTypes = types.count
    }

    public func count(of category: DataCategory) -> Int { byCategory[category.rawValue] ?? 0 }
    public func count(of severity: Severity) -> Int { bySeverity[severity.rawValue] ?? 0 }
}
