import Foundation

/// Produces a sanitized copy of inspected text with sensitive spans removed or
/// masked, so a `redact` verdict can let the user proceed without leaking data.
///
/// Replacement is done right-to-left so earlier spans keep their offsets, and
/// overlapping spans are coalesced (the detection engine already de-overlaps,
/// but redaction is defensive about any input).
public struct Redactor: Sendable {

    public enum Style: String, Codable, Sendable {
        /// Replace with a typed placeholder, e.g. `[REDACTED:credit-card]`.
        case placeholder
        /// Replace with bullets of a fixed width (length not leaked).
        case mask
        /// Replace with a stable per-value token, e.g. `[card_3f9a1c2b]`, so the
        /// same value maps to the same token (useful for preserving references).
        case tokenize
    }

    public let style: Style

    public init(style: Style = .placeholder) {
        self.style = style
    }

    /// Return `text` with every finding's span replaced according to `style`.
    ///
    /// Overlapping spans are merged into a single covering segment before
    /// replacement, so no sensitive byte is ever left exposed and no span is
    /// substituted twice. Replacement happens right-to-left to keep offsets valid.
    public func redact(_ text: String, findings: [Finding]) -> String {
        guard !findings.isEmpty else { return text }
        let ns = text as NSString
        let len = ns.length

        // Keep only in-bounds spans, sorted by start position.
        let spans = findings.compactMap { f -> (NSRange, Finding)? in
            let r = f.span.nsRange
            guard r.location != NSNotFound, r.length > 0, NSMaxRange(r) <= len else { return nil }
            return (r, f)
        }.sorted { $0.0.location < $1.0.location }
        guard !spans.isEmpty else { return text }

        // Merge overlapping spans into segments, each remembering its findings.
        var segments: [(range: NSRange, findings: [Finding])] = []
        for (r, f) in spans {
            if var last = segments.last, NSMaxRange(last.range) > r.location {
                let newEnd = max(NSMaxRange(last.range), NSMaxRange(r))
                last.range = NSRange(location: last.range.location, length: newEnd - last.range.location)
                last.findings.append(f)
                segments[segments.count - 1] = last
            } else {
                segments.append((r, [f]))
            }
        }

        let mutable = NSMutableString(string: text)
        for segment in segments.reversed() {
            mutable.replaceCharacters(in: segment.range, with: replacement(for: segment.findings))
        }
        return mutable as String
    }

    private func replacement(for findings: [Finding]) -> String {
        // A merged segment with multiple distinct types gets a generic marker.
        let uniqueIDs = Set(findings.map(\.type.id))
        switch style {
        case .placeholder:
            return uniqueIDs.count == 1 ? "[REDACTED:\(findings[0].type.id)]" : "[REDACTED]"
        case .mask:
            return String(repeating: "•", count: 8)
        case .tokenize:
            guard uniqueIDs.count == 1 else { return "[REDACTED]" }
            return "[\(tokenPrefix(for: findings[0].category))_\(findings[0].valueFingerprint)]"
        }
    }

    private func tokenPrefix(for category: DataCategory) -> String {
        switch category {
        case .financial: return "fin"
        case .governmentID: return "gov"
        case .credential, .sourceSecret: return "secret"
        case .pii: return "pii"
        case .health: return "phi"
        case .network: return "net"
        case .identity: return "id"
        }
    }
}
