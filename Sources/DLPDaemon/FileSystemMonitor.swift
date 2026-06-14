import Foundation
import DLPCore
import CoreServices

/// Watches one or more directory trees for newly written / modified files using
/// the **FSEvents** API, and inspects text-like files for sensitive content.
/// This covers the "user saves an export and uploads it" vector. It needs no
/// special entitlement for user-readable locations (e.g. `~/Downloads`); some
/// system locations would require Full Disk Access granted via MDM/TCC.
public final class FileSystemMonitor: Monitor, @unchecked Sendable {
    public let id = "filesystem"

    private let paths: [String]
    private let handler: @Sendable (MonitoredPayload) -> Void
    private let queue = DispatchQueue(label: "dlp.monitor.fs")
    private let maxFileSize: Int
    private let textExtensions: Set<String>

    /// Extension-less secret files matched by full name (dotfiles).
    static let secretDotfiles: Set<String> = [
        ".env", ".npmrc", ".pgpass", ".netrc", ".htpasswd", ".dockercfg",
    ]

    /// Whether a path should be read and scanned. Dotfiles (`.env`, `.npmrc`, …)
    /// have an empty `pathExtension`, so the extension allowlist alone would skip
    /// the most common environment-secret file; we also match the last path
    /// component, including `.env.local` / `.env.production` variants.
    static func isInspectable(path: String, textExtensions: Set<String>) -> Bool {
        let name = (path as NSString).lastPathComponent.lowercased()
        let ext = (path as NSString).pathExtension.lowercased()
        let isSecretDotfile = secretDotfiles.contains(name) || name.hasPrefix(".env.")
        return textExtensions.contains(ext) || isSecretDotfile
    }

    private var stream: FSEventStreamRef?
    private var selfRef: Unmanaged<FileSystemMonitor>?
    /// Per-path debounce: a pending delayed scan, rescheduled on each event so a
    /// burst (create → write …) collapses into one scan of the settled file.
    private var pendingScans: [String: DispatchWorkItem] = [:]
    /// How long a path must be quiet before we scan it.
    private let quietPeriod: TimeInterval = 0.8

    public init(
        paths: [String],
        maxFileSize: Int = 5_000_000,
        textExtensions: Set<String> = [
            "txt", "csv", "tsv", "json", "yaml", "yml", "xml", "log", "md",
            "env", "ini", "conf", "cfg", "properties", "sql", "html", "htm",
            "swift", "py", "js", "ts", "go", "rb", "java", "kt", "sh", "pem",
        ],
        handler: @escaping @Sendable (MonitoredPayload) -> Void
    ) {
        self.paths = paths
        self.maxFileSize = maxFileSize
        self.textExtensions = textExtensions
        self.handler = handler
    }

    public func start() throws {
        guard stream == nil else { return }
        let retained = Unmanaged.passRetained(self)
        self.selfRef = retained
        var context = FSEventStreamContext(
            version: 0,
            info: retained.toOpaque(),
            retain: nil, release: nil, copyDescription: nil
        )

        let callback: FSEventStreamCallback = { _, info, count, eventPaths, flags, _ in
            guard let info else { return }
            let monitor = Unmanaged<FileSystemMonitor>.fromOpaque(info).takeUnretainedValue()
            let nsPaths = unsafeBitCast(eventPaths, to: NSArray.self) as? [String] ?? []
            for i in 0..<count where i < nsPaths.count {
                monitor.handle(path: nsPaths[i], flags: flags[i])
            }
        }

        let flags = UInt32(
            kFSEventStreamCreateFlagUseCFTypes |   // eventPaths delivered as a CFArray<CFString>
            kFSEventStreamCreateFlagFileEvents |
            kFSEventStreamCreateFlagNoDefer |
            kFSEventStreamCreateFlagIgnoreSelf
        )

        guard let created = FSEventStreamCreate(
            kCFAllocatorDefault, callback, &context,
            paths as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            0.5, flags
        ) else {
            self.selfRef?.release()
            self.selfRef = nil
            throw MonitorError.failedToStartFSEvents
        }

        FSEventStreamSetDispatchQueue(created, queue)
        guard FSEventStreamStart(created) else {
            FSEventStreamInvalidate(created)
            FSEventStreamRelease(created)
            self.selfRef?.release()
            self.selfRef = nil
            throw MonitorError.failedToStartFSEvents
        }
        self.stream = created
    }

    public func stop() {
        guard let s = stream else { return }
        FSEventStreamStop(s)
        FSEventStreamInvalidate(s)
        FSEventStreamRelease(s)
        // Cancel any in-flight debounced scans (on the queue that owns them).
        queue.async { [weak self] in
            self?.pendingScans.values.forEach { $0.cancel() }
            self?.pendingScans.removeAll()
        }
        stream = nil
        selfRef?.release()
        selfRef = nil
    }

    // Runs on `queue` (the FSEvents dispatch queue), so per-path state needs no
    // extra lock.
    private func handle(path: String, flags: FSEventStreamEventFlags) {
        let isFile = flags & FSEventStreamEventFlags(kFSEventStreamEventFlagItemIsFile) != 0
        let mutated = flags & FSEventStreamEventFlags(
            kFSEventStreamEventFlagItemCreated |
            kFSEventStreamEventFlagItemModified |
            kFSEventStreamEventFlagItemRenamed
        ) != 0
        guard isFile, mutated else { return }
        guard Self.isInspectable(path: path, textExtensions: textExtensions) else { return }

        // Coalesce a burst of events for one path (create → truncate → write …)
        // into a SINGLE scan of the final contents, fired once the path goes
        // quiet. A previous "scan first, ignore for 2s" approach scanned the
        // initial empty/partial file and dropped the later event carrying the
        // real (secret-bearing) contents.
        pendingScans[path]?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.scanSettledFile(path) }
        pendingScans[path] = work
        queue.asyncAfter(deadline: .now() + quietPeriod, execute: work)
    }

    private func scanSettledFile(_ path: String) {
        pendingScans.removeValue(forKey: path)
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attrs[.size] as? Int, size > 0, size <= maxFileSize else { return }
        guard let data = FileManager.default.contents(atPath: path),
              let text = String(data: data, encoding: .utf8), !text.isEmpty else { return }
        handler(MonitoredPayload(text: text, channel: .file, sourceApp: nil, origin: path))
    }
}

public enum MonitorError: Error, CustomStringConvertible {
    case failedToStartFSEvents
    public var description: String {
        switch self {
        case .failedToStartFSEvents: return "Failed to start FSEvents stream"
        }
    }
}
