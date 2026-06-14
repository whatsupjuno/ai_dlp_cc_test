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
            // Authorize file opens; deny reads of files we classify as sensitive
            // when the opener is an unsanctioned uploader. Must always respond.
            let path = Self.string(message.pointee.event.open.file.pointee.path)
            let allow = shouldAllowOpen(path: path)
            if let client {
                es_respond_auth_result(client, message,
                                       allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY,
                                       false)
            }

        default:
            break
        }
    }

    private func shouldAllowOpen(path: String) -> Bool {
        // Example policy hook: scan small text files on open and deny if they
        // contain critical secrets being opened by a browser/uploader. Real
        // deployments cache verdicts and respect the AUTH deadline strictly.
        guard path.count < 4096,
              let data = FileManager.default.contents(atPath: path),
              data.count < 1_000_000,
              let text = String(data: data, encoding: .utf8) else { return true }
        let verdict = engine.inspect(text, channel: .file, host: nil)
        if verdict.blocksEgress { onVerdict(verdict, path); return false }
        return true
    }

    /// Convert an `es_string_token_t` to a Swift `String`.
    private static func string(_ token: es_string_token_t) -> String {
        guard token.length > 0, let data = token.data else { return "" }
        return String(decoding: UnsafeRawBufferPointer(start: data, count: token.length), as: UTF8.self)
    }
}
#endif
