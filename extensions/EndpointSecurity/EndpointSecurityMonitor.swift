// EndpointSecurityMonitor.swift
//
// Reference implementation of the optional Endpoint Security vector. It is kept
// OUT of the SwiftPM build graph on purpose: `es_new_client` returns
// `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` unless the process carries the
// restricted `com.apple.developer.endpoint-security.client` entitlement AND runs
// as root inside a packaged, notarized system extension. It is provided here as
// correct, reviewable source to be compiled inside the Xcode system-extension
// target. See ./README.md.
//
// What it adds over the clipboard/file/network vectors:
//   • true *block-before-paste* (AUTH events can be denied synchronously)
//   • process-exec visibility (which app is about to talk to an AI service)
//   • file-open authorization for classified documents
//
// It feeds the SAME DLPCore engine used everywhere else — ES is just another
// source of plaintext + an enforcement point.

#if canImport(EndpointSecurity)
import Foundation
import EndpointSecurity
import DLPCore

public final class EndpointSecurityMonitor {

    public enum ESError: Error { case clientCreationFailed(es_new_client_result_t), subscribeFailed }

    private var client: OpaquePointer?
    private let engine: DLPEngine
    private let onVerdict: (DLPVerdict, String) -> Void

    public init(engine: DLPEngine, onVerdict: @escaping (DLPVerdict, String) -> Void) {
        self.engine = engine
        self.onVerdict = onVerdict
    }

    public func start() throws {
        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { [weak self] _, message in
            self?.handle(message)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient else {
            throw ESError.clientCreationFailed(result)
        }
        client = newClient

        // NOTIFY = observe; AUTH = must respond (allow/deny) within a deadline.
        var events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN,
        ]
        guard es_subscribe(newClient, &events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            throw ESError.subscribeFailed
        }
    }

    public func stop() {
        if let client {
            es_unsubscribe_all(client)
            es_delete_client(client)
            self.client = nil
        }
    }

    // MARK: - Event handling

    private func handle(_ message: UnsafePointer<es_message_t>) {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let path = Self.string(message.pointee.event.exec.target.pointee.executable.pointee.path)
            // Hook point: correlate the launching process with subsequent egress.
            _ = path

        case ES_EVENT_TYPE_AUTH_OPEN:
            // Authorize file opens; deny reads of sensitive files ONLY when the
            // opener is an unsanctioned uploader (browser / AI client). Must
            // always respond.
            let filePath = Self.string(message.pointee.event.open.file.pointee.path)
            let openerPath = Self.string(message.pointee.process.pointee.executable.pointee.path)
            let allow = shouldAllowOpen(filePath: filePath, openerPath: openerPath)
            if let client {
                es_respond_auth_result(client, message,
                                       allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY,
                                       false)
            }

        default:
            break
        }
    }

    /// Executable-path fragments of data-egress apps whose reads of sensitive
    /// files we gate. A developer opening a `.env` / private key / SSN fixture in
    /// an editor, IDE, or terminal is NEVER denied — only an uploader is.
    private static let uploaderProcesses: [String] = [
        "Google Chrome", "Chromium", "Microsoft Edge", "Brave Browser", "Arc",
        "Firefox", "Safari", "Opera", "Vivaldi",
        "ChatGPT", "Claude", "Perplexity", "Poe",
    ]

    private static func isUploaderProcess(_ executablePath: String) -> Bool {
        uploaderProcesses.contains { executablePath.contains($0) }
    }

    private static let maxScanBytes = 1_000_000

    private func shouldAllowOpen(filePath: String, openerPath: String) -> Bool {
        // Gate ONLY known uploaders (browsers / AI clients). Editors, IDEs and
        // terminals reading the same sensitive file are always allowed — denying
        // them would break normal local development system-wide.
        guard Self.isUploaderProcess(openerPath) else { return true }
        guard filePath.count < 4096 else { return true }

        // Stat the size BEFORE loading bytes. This runs inside an AUTH_OPEN
        // handler with a hard deadline, so reading a multi-GB file into memory
        // would exhaust memory or blow the deadline. Files over the cap are passed
        // (a documented residual at the ES enforcement point).
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: filePath),
              let size = attrs[.size] as? Int, size > 0, size < Self.maxScanBytes else { return true }
        guard let data = FileManager.default.contents(atPath: filePath),
              let text = String(data: data, encoding: .utf8) else { return true }

        // ES can neither show a justification prompt nor rewrite the file before
        // the uploader reads it, so it FAILS SAFE: any verdict that isn't
        // allow/audit (block/quarantine/warn/redact) denies the open — otherwise
        // a browser/AI client could upload the original sensitive file with no
        // warning/redaction applied.
        let verdict = engine.inspect(text, channel: .file, host: nil)
        if verdict.action != .allow, verdict.action != .audit {
            onVerdict(verdict, filePath)
            return false
        }
        return true
    }

    /// Convert an `es_string_token_t` to a Swift `String`.
    private static func string(_ token: es_string_token_t) -> String {
        guard token.length > 0, let data = token.data else { return "" }
        return String(decoding: UnsafeRawBufferPointer(start: data, count: token.length), as: UTF8.self)
    }
}
#endif
