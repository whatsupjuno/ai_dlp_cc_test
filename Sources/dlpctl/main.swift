import Foundation
import DLPCore
import DLPDaemon

// MARK: - Tiny argument parser

struct Args {
    private(set) var positionals: [String] = []
    private var flags: Set<String> = []
    private var options: [String: String] = [:]

    init(_ argv: [String]) {
        var i = 0
        while i < argv.count {
            let a = argv[i]
            if a.hasPrefix("--") {
                let key = String(a.dropFirst(2))
                if i + 1 < argv.count, !argv[i + 1].hasPrefix("--") {
                    options[key] = argv[i + 1]; i += 2; continue
                } else {
                    flags.insert(key)
                }
            } else {
                positionals.append(a)
            }
            i += 1
        }
    }

    func has(_ flag: String) -> Bool { flags.contains(flag) }
    func option(_ key: String) -> String? { options[key] }
    func option(_ key: String, default def: String) -> String { options[key] ?? def }
}

// MARK: - Shared helpers

func readInput(_ path: String?) -> String {
    if let p = path, p != "-" {
        guard let s = try? String(contentsOfFile: p, encoding: .utf8) else {
            eprint("error: cannot read file: \(p)")
            exit(2)
        }
        return s
    }
    let data = FileHandle.standardInput.readDataToEndOfFile()
    return String(data: data, encoding: .utf8) ?? ""
}

func parseChannel(_ s: String?) -> Channel {
    switch s?.lowercased() {
    case "clipboard": return .clipboard
    case "network": return .network
    case "file": return .file
    case "browser", "upload": return .browserUpload
    default: return .manualScan
    }
}

func buildEngine(_ args: Args, auditSink: AuditSink? = nil) -> DLPEngine {
    var config = DLPConfiguration()
    if args.has("no-ner") { config.enableNER = false }
    if args.has("no-context") { config.enableContextBoost = false }
    if args.has("monitor") { config.policy.mode = .monitor }
    return DLPEngine(configuration: config, auditSink: auditSink)
}

// MARK: - Commands

func cmdScan(_ args: Args) {
    let path = args.positionals.first
    let text = readInput(path)
    let host = args.option("host")
    let channel = parseChannel(args.option("channel"))
    let engine = buildEngine(args)

    let destination = host.map { engine.classifier.classify(host: $0) } ?? .unknown
    let context = InspectionContext(
        channel: channel, destination: destination,
        sourceApp: args.option("app"), byteCount: text.utf8.count
    )
    let verdict = engine.inspect(text, context: context)

    if args.has("json") {
        print(Render.json(verdict))
    } else {
        let source = path.map { "file: \($0)" } ?? "stdin"
        print(Render.verdict(verdict, source: source))
    }
    // Exit non-zero when egress would be blocked, so scripts/CI can gate on it.
    if verdict.blocksEgress { exit(1) }
}

func cmdWatch(_ args: Args) {
    let interval = Double(args.option("interval", default: "0.25")) ?? 0.25
    let enforce = !args.has("observe")
    let json = args.has("json")

    let audit = InMemoryAuditSink()
    let engine = buildEngine(args, auditSink: audit)
    let service = DLPService(
        engine: engine,
        configuration: .init(
            enableClipboard: true,
            clipboardInterval: interval,
            clipboardEnforcement: enforce ? .enforce : .off
        )
    )

    eprint(Term.bold("● Sentinel AI-DLP — clipboard watch"))
    eprint(Term.dim("  mode: \(enforce ? "ENFORCE (redact/clear on hit)" : "observe only")  ·  interval: \(interval)s"))
    eprint(Term.dim("  Copy a test secret (e.g. a fake card or sk-ant- key) to see it caught. Ctrl-C to stop.\n"))

    service.onVerdict = { verdict, payload in
        if json {
            print(Render.json(verdict)); fflush(stdout)
        } else {
            print(Render.verdict(verdict, source: "clipboard"))
            fflush(stdout)
        }
    }

    do { try service.start() } catch {
        eprint("error: failed to start monitors: \(error)")
        exit(2)
    }

    // Clean shutdown on Ctrl-C.
    signal(SIGINT, SIG_IGN)
    let sigsrc = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    sigsrc.setEventHandler {
        eprint("\n" + Term.dim("stopping… \(audit.events.count) event(s) recorded this session."))
        service.stop()
        exit(0)
    }
    sigsrc.resume()
    dispatchMain()
}

func cmdPatterns(_ args: Args) {
    let rules = PatternLibrary.builtin
    if args.has("json") {
        print(Render.json(rules)); return
    }
    if args.has("lint") {
        let detector = RegexDetector(rules: rules)
        if detector.diagnostics.isEmpty {
            print(Term.color("✓ all \(rules.count) patterns compiled successfully", 32))
        } else {
            print(Term.color("✗ \(detector.diagnostics.count) pattern(s) failed to compile:", 31))
            for (id, msg) in detector.diagnostics.sorted(by: { $0.key < $1.key }) {
                print("  \(Term.bold(id)): \(msg)")
            }
            exit(1)
        }
        return
    }
    // Default: grouped listing.
    print(Term.bold("Built-in detection patterns (\(rules.count)):\n"))
    let grouped = Dictionary(grouping: rules, by: { $0.category })
    for category in DataCategory.allCases {
        guard let items = grouped[category], !items.isEmpty else { continue }
        print(Term.bold("  \(category.displayName) (\(items.count))"))
        for r in items {
            let sym = Term.severityColored(r.severity.symbol, r.severity.rawValue)
            let val = r.validator == .none ? "" : Term.dim("  ⟨\(r.validator.rawValue)⟩")
            print("    \(sym) \(r.id.padding(toLength: 28, withPad: " ", startingAt: 0)) \(Term.dim(r.name))\(val)")
        }
        print("")
    }
}

func cmdServices(_ args: Args) {
    let catalog = AIServiceCatalog.builtin
    if args.has("json") {
        print(Render.json(catalog.entries)); return
    }
    print(Term.bold("Recognized AI services (\(catalog.entries.count)):\n"))
    for e in catalog.entries {
        let tierColor: Int
        switch e.defaultTier {
        case .blocked: tierColor = 31
        case .unsanctioned: tierColor = 35
        case .monitored: tierColor = 33
        case .sanctioned: tierColor = 32
        case .unknown: tierColor = 90
        }
        let tier = Term.color(e.defaultTier.rawValue.padding(toLength: 13, withPad: " ", startingAt: 0), tierColor)
        print("  \(tier) \(Term.bold(e.name)) \(Term.dim("(\(e.vendor))"))")
        let domains = (e.webDomains + e.apiHosts).prefix(4).joined(separator: ", ")
        if !domains.isEmpty { print("      \(Term.dim(domains))") }
    }
}

func cmdPolicy(_ args: Args) {
    let policy = Policy.enterpriseDefault()
    if args.has("json") {
        print(Render.json(policy)); return
    }
    print(Term.bold("Policy: \(policy.name)  v\(policy.version)  [\(policy.mode.rawValue)]\n"))
    print("  default action : \(policy.defaultAction.displayName)")
    print("  fail mode      : \(policy.failMode.rawValue)\n")
    print(Term.bold("  Rules (first match wins):"))
    for (i, r) in policy.rules.enumerated() {
        print("   \(i + 1). \(Render.actionBadge(r.action)) \(Term.bold(r.name))  \(Term.dim(r.id))")
        if let msg = r.message { print("      \(Term.dim(String(msg.prefix(96))))") }
    }
}

func cmdAudit(_ args: Args) {
    guard let path = args.positionals.first else {
        eprint("usage: dlpctl audit <path-to-jsonl>")
        exit(2)
    }
    guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
        eprint("error: cannot read \(path)"); exit(2)
    }
    let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
    var events: [AuditEvent] = []
    for line in content.split(separator: "\n") {
        if let data = line.data(using: .utf8), let ev = try? decoder.decode(AuditEvent.self, from: data) {
            events.append(ev)
        }
    }
    if args.has("json") { print(Render.json(events)); return }
    print(Term.bold("Audit trail: \(events.count) event(s)\n"))
    let fmt = ISO8601DateFormatter()
    for ev in events {
        let when = fmt.string(from: ev.timestamp)
        print("  \(Term.dim(when))  \(Render.actionBadge(ev.action))  \(ev.destination)  \(Term.dim("risk \(Int(ev.riskScore*100))%"))")
        for r in ev.findings {
            print("      \(Term.severityColored(r.severity.symbol, r.severity.rawValue)) \(r.typeName) \(Term.dim(r.masked))")
        }
    }
}

func printHelp() {
    let help = """
    \(Term.bold("Sentinel AI-DLP")) — enterprise data-loss prevention for macOS

    \(Term.bold("USAGE"))
      dlpctl <command> [options]

    \(Term.bold("COMMANDS"))
      scan [PATH]            Scan a file (or stdin) for sensitive data and print the verdict.
      watch                  Watch the clipboard live and catch/redact secrets in real time.
      patterns               List the built-in detection patterns.
      services               List recognized AI services and their risk tiers.
      policy                 Show the default enforcement policy.
      audit PATH             Pretty-print a JSONL audit log.
      version                Print version.
      help                   Show this help.

    \(Term.bold("SCAN OPTIONS"))
      --host HOST            Classify the egress destination (e.g. chatgpt.com).
      --channel C            clipboard|network|file|browser|manual  (default: manual)
      --app BUNDLE_ID        Attribute to a source application.
      --json                 Emit machine-readable JSON.
      --no-ner               Disable on-device named-entity recognition.
      --no-context           Disable proximity-based confidence boosting.
      --monitor              Evaluate in monitor mode (downgrade blocks to audit).

    \(Term.bold("WATCH OPTIONS"))
      --observe              Observe only; do not modify the clipboard.
      --interval N           Poll interval in seconds (default 0.25).
      --json                 Emit JSON per hit.

    \(Term.bold("EXAMPLES"))
      echo 'my key is sk-ant-api03-AAAA1111BBBB2222CCCC3333DDDD4444' | dlpctl scan
      dlpctl scan secrets.env --host chatgpt.com
      dlpctl watch
      dlpctl patterns --lint
    """
    print(help)
}

// MARK: - Entry

let argv = Array(CommandLine.arguments.dropFirst())
let command = argv.first ?? "help"
let rest = Args(Array(argv.dropFirst()))

switch command {
case "scan", "eval": cmdScan(rest)
case "watch", "watch-clipboard": cmdWatch(rest)
case "patterns": cmdPatterns(rest)
case "services": cmdServices(rest)
case "policy": cmdPolicy(rest)
case "audit": cmdAudit(rest)
case "version", "--version", "-v": print("Sentinel AI-DLP dlpctl 1.0.0")
case "help", "--help", "-h": printHelp()
default:
    eprint("unknown command: \(command)\n")
    printHelp()
    exit(2)
}
