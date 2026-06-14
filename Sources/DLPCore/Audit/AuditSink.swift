import Foundation

/// A destination for audit events. Implementations must be safe to call from
/// multiple monitor queues concurrently.
public protocol AuditSink: Sendable {
    func record(_ event: AuditEvent)
}

/// Shared JSON coder configured for stable, SIEM-friendly output. The encoder
/// and decoder use matching ISO-8601 date strategies so events round-trip.
public enum AuditCoding {
    public static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }()

    public static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}

/// Appends one JSON object per line to a file (JSONL) — the canonical format for
/// Splunk / Elastic / Datadog ingestion. Writes are serialized and durable.
public final class JSONLFileAuditSink: AuditSink, @unchecked Sendable {
    private let handle: FileHandle
    private let queue = DispatchQueue(label: "dlp.audit.jsonl")
    private let url: URL

    public init(url: URL) throws {
        self.url = url
        let fm = FileManager.default
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil)
        }
        self.handle = try FileHandle(forWritingTo: url)
        self.handle.seekToEndOfFile()
    }

    deinit {
        // Drain queued writes before closing — a teardown right after a verdict
        // (e.g. block-a-paste then quit) must not drop or write past a closed
        // handle. The serial queue guarantees prior async writes have completed.
        queue.sync {}
        try? handle.synchronize()
        try? handle.close()
    }

    public func record(_ event: AuditEvent) {
        queue.async { [handle] in
            guard var data = try? AuditCoding.encoder.encode(event) else { return }
            data.append(0x0A) // newline
            handle.write(data)
        }
    }

    /// Block until queued writes are flushed (used on shutdown / before reads).
    public func flush() {
        queue.sync {}
        try? handle.synchronize()
    }
}

/// Keeps events in memory (tests, the CLI `scan` summary, the menu-bar app's
/// recent-activity list). Bounded to avoid unbounded growth.
public final class InMemoryAuditSink: AuditSink, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [AuditEvent] = []
    private let capacity: Int

    public init(capacity: Int = 1000) {
        self.capacity = capacity
    }

    public func record(_ event: AuditEvent) {
        lock.lock(); defer { lock.unlock() }
        storage.append(event)
        if storage.count > capacity { storage.removeFirst(storage.count - capacity) }
    }

    public var events: [AuditEvent] {
        lock.lock(); defer { lock.unlock() }
        return storage
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        storage.removeAll()
    }
}

/// Fans an event out to several sinks (e.g. local JSONL + remote webhook).
public final class MultiAuditSink: AuditSink, @unchecked Sendable {
    private let sinks: [AuditSink]
    public init(_ sinks: [AuditSink]) { self.sinks = sinks }
    public func record(_ event: AuditEvent) { sinks.forEach { $0.record(event) } }
}

/// Formats events as ArcSight **CEF** (Common Event Format) for syslog-based
/// SIEMs. Exposed as a static formatter so callers can pick their transport.
public enum CEFFormatter {
    public static func format(_ e: AuditEvent, vendor: String = "Sentinel", product: String = "AIDLP", version: String = "1.0") -> String {
        // CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
        let sig = e.matchedRuleID ?? "default"
        let name = "AI-DLP \(e.action.displayName)"
        let sev = cefSeverity(e.topSeverity)
        var ext: [String] = [
            "rt=\(Int(e.timestamp.timeIntervalSince1970 * 1000))",
            "suser=\(escape(e.user))",
            "dhost=\(escape(e.destination))",
            "act=\(e.action.rawValue)",
            "cs1Label=tier", "cs1=\(e.destinationTier.rawValue)",
            "cs2Label=channel", "cs2=\(e.channel.rawValue)",
            "cn1Label=findings", "cn1=\(e.findings.count)",
            "cn2Label=riskScore", "cn2=\(Int(e.riskScore * 100))",
        ]
        if let app = e.sourceApp { ext.append("sproc=\(escape(app))") }
        let types = e.findings.map(\.typeID).joined(separator: ",")
        if !types.isEmpty { ext.append("cs3Label=dataTypes"); ext.append("cs3=\(escape(types))") }

        let header = ["CEF:0", vendor, product, version, sig, name, "\(sev)"]
            .map { headerEscape($0) }.joined(separator: "|")
        return header + "|" + ext.joined(separator: " ")
    }

    private static func cefSeverity(_ s: Severity) -> Int {
        switch s {
        case .info: return 1
        case .low: return 3
        case .medium: return 5
        case .high: return 7
        case .critical: return 10
        }
    }

    private static func headerEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "|", with: "\\|")
    }
    private static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "=", with: "\\=")
         .replacingOccurrences(of: "\n", with: " ")
    }
}
