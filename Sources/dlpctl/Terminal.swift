import Foundation

/// Minimal ANSI terminal helpers. Colour is auto-disabled when stdout is not a
/// TTY or when `NO_COLOR` is set, so piped/redirected output stays clean.
enum Term {
    static let isTTY: Bool = isatty(fileno(stdout)) != 0
    static let colorEnabled: Bool = isTTY && ProcessInfo.processInfo.environment["NO_COLOR"] == nil

    static func color(_ s: String, _ code: Int, bold: Bool = false) -> String {
        guard colorEnabled else { return s }
        let b = bold ? "1;" : ""
        return "\u{001B}[\(b)\(code)m\(s)\u{001B}[0m"
    }

    static func bold(_ s: String) -> String { colorEnabled ? "\u{001B}[1m\(s)\u{001B}[0m" : s }
    static func dim(_ s: String) -> String { colorEnabled ? "\u{001B}[2m\(s)\u{001B}[0m" : s }

    static func severityColored(_ text: String, _ sev: String) -> String {
        let code: Int
        switch sev {
        case "critical": code = 31
        case "high": code = 35
        case "medium": code = 33
        case "low": code = 36
        default: code = 90
        }
        return color(text, code, bold: sev == "critical")
    }

    /// A unicode meter like ████░░░░ for a 0...1 value.
    static func meter(_ value: Double, width: Int = 16) -> String {
        let filled = max(0, min(width, Int((value * Double(width)).rounded())))
        return String(repeating: "█", count: filled) + String(repeating: "░", count: width - filled)
    }
}

/// Print to stderr (diagnostics / errors), keeping stdout for machine output.
func eprint(_ items: Any..., separator: String = " ") {
    let line = items.map { "\($0)" }.joined(separator: separator)
    FileHandle.standardError.write(Data((line + "\n").utf8))
}
