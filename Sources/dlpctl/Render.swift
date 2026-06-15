import Foundation
import DLPCore

/// Human-readable rendering of verdicts and findings for the CLI.
enum Render {

    static func actionBadge(_ action: PolicyAction) -> String {
        let label = " \(action.displayName.uppercased()) "
        switch action {
        case .allow:      return Term.color(label, 32, bold: true)               // green
        case .audit:      return Term.color(label, 36, bold: true)               // cyan
        case .redact:     return Term.color(label, 34, bold: true)               // blue
        case .warn:       return Term.color(label, 33, bold: true)               // yellow
        case .block:      return Term.color(label, 31, bold: true)               // red
        case .quarantine: return Term.color(label, 35, bold: true)               // magenta
        }
    }

    static func verdict(_ v: DLPVerdict, source: String) -> String {
        var out = ""
        out += Term.bold("● Sentinel AI-DLP") + Term.dim("  —  \(source)") + "\n"
        let dest = v.context.destination
        let destLine = dest.service != nil
            ? "\(dest.displayName) [\(dest.tier.rawValue)]"
            : (dest.host ?? "—")
        out += "  destination : \(destLine)\n"
        out += "  channel     : \(v.context.channel.displayName)\n"
        if let app = v.context.sourceApp { out += "  source app  : \(app)\n" }
        out += "  risk        : \(Term.meter(v.riskScore)) \(String(format: "%.0f%%", v.riskScore * 100))\n"
        out += "  verdict     : \(actionBadge(v.action))  \(Term.dim(v.reason))\n"

        if v.findings.isEmpty {
            out += "  findings    : none\n"
        } else {
            out += "  findings    : \(v.findings.count)\n"
            out += findingsTable(v.findings)
        }
        if let redacted = v.redactedContent {
            out += "\n" + Term.bold("  redacted output:") + "\n"
            out += redacted.split(separator: "\n", omittingEmptySubsequences: false)
                .map { "    " + $0 }.joined(separator: "\n") + "\n"
        }
        return out
    }

    static func findingsTable(_ findings: [Finding]) -> String {
        var rows = ""
        for f in findings {
            let sev = f.severity.rawValue
            let sym = Term.severityColored(f.severity.symbol, sev)
            let name = f.type.name.padding(toLength: 30, withPad: " ", startingAt: 0)
            let cat = f.category.rawValue.padding(toLength: 13, withPad: " ", startingAt: 0)
            let conf = f.confidence.rawValue.padding(toLength: 6, withPad: " ", startingAt: 0)
            let loc = "@\(f.span.location)"
            let note = f.note.map { Term.dim("  (\($0))") } ?? ""
            rows += "    \(sym) \(Term.bold(name)) \(Term.dim(cat)) \(conf) \(f.maskedValue.padding(toLength: 16, withPad: " ", startingAt: 0)) \(Term.dim(loc))\(note)\n"
        }
        return rows
    }

    static func json<T: Encodable>(_ value: T) -> String {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let data = try? e.encode(value), let s = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return s
    }
}
