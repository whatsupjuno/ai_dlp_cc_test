import AppKit
import SwiftUI
import Combine
import DLPCore
import DLPDaemon
import SentinelNetworkFilter

final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AgentModel()
    private var statusItem: NSStatusItem!
    private var popover: NSPopover!
    private var service: DLPService!
    private var networkFilter: NetworkFilterController?
    private var cancellables = Set<AnyCancellable>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        setupPopover()
        startService()
        activateNetworkFilter()
        refreshStaticInfo()
    }

    func applicationWillTerminate(_ notification: Notification) {
        service?.stop()
    }

    /// Activate + enable the NetworkExtension content filter so the network vector
    /// is live (destination-tier enforcement). System-extension activation only
    /// works from a signed, installed `.app` with the right entitlements (or via
    /// MDM); when launched via `swift run` the executable isn't an `.app` bundle,
    /// so we skip it and continue with clipboard protection rather than failing.
    private func activateNetworkFilter() {
        guard Bundle.main.bundlePath.hasSuffix(".app") else {
            NSLog("Sentinel: network filter activation skipped — not running as a signed .app bundle")
            return
        }
        let controller = NetworkFilterController(extensionIdentifier: "com.sentinel.dlp.agent.networkfilter")
        controller.onStateChange = { state in
            NSLog("Sentinel: network filter state = \(state)")
        }
        controller.activate()
        networkFilter = controller
    }

    // MARK: - Status bar

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Sentinel AI-DLP")
            button.image?.isTemplate = true
            button.action = #selector(togglePopover(_:))
            button.target = self
        }
        // Refresh the status glyph whenever the model changes (on the main run loop).
        model.objectWillChange
            .receive(on: DispatchQueue.main)
            .sink { [weak self] in self?.updateStatusGlyph() }
            .store(in: &cancellables)
    }

    private func setupPopover() {
        let view = StatusView(
            onToggleEnforcement: { [weak self] in self?.toggleEnforcement() },
            onConfirmWarning: { [weak self] in self?.confirmPendingWarning() },
            onDismissWarning: { [weak self] in self?.model.pendingWarning = nil },
            onQuit: { NSApplication.shared.terminate(nil) }
        ).environmentObject(model)

        popover = NSPopover()
        popover.contentSize = NSSize(width: 380, height: 420)
        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: view)
    }

    @objc private func togglePopover(_ sender: Any?) {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    private func toggleEnforcement() {
        model.enforcing.toggle()
        service.setEnforcement(model.enforcing)
    }

    /// User justified a warned action → restore the original content to the
    /// clipboard so it can be pasted, and clear the pending prompt. Only restores
    /// if the clipboard hasn't moved on since the warning was raised, so we never
    /// overwrite a different clipboard item than the one the user is confirming.
    private func confirmPendingWarning() {
        guard let pending = model.pendingWarning else { return }
        defer { model.pendingWarning = nil }
        guard pending.changeCount == NSPasteboard.general.changeCount else { return }
        service?.confirmAndRestore(pending.text)
    }

    // MARK: - Service

    private func startService() {
        let auditSink = makeAuditSink()
        let engine = DLPEngine(configuration: DLPConfiguration(), auditSink: auditSink)
        let svc = DLPService(
            engine: engine,
            configuration: .init(enableClipboard: true, clipboardEnforcement: .enforce)
        )
        // Capture only the (Sendable) model; the glyph refresh is driven by the
        // Combine subscription above, so no non-Sendable `self` is captured here.
        svc.onVerdict = { [model] verdict, payload in
            DispatchQueue.main.async {
                model.record(verdict, payload: payload)
                // Every new clipboard verdict supersedes any older pending warning
                // (the clipboard has moved on), preventing a stale restore.
                model.pendingWarning = nil
                // A warn verdict already removed the value from the clipboard;
                // retain the original so the user can justify and restore it,
                // bound to the current pasteboard change-count.
                if verdict.action == .warn {
                    let types = Array(Set(verdict.findings.map(\.type.name))).sorted().joined(separator: ", ")
                    model.pendingWarning = AgentModel.PendingWarning(
                        text: payload.text,
                        summary: types.isEmpty ? verdict.reason : types,
                        destination: verdict.context.destination.displayName,
                        changeCount: NSPasteboard.general.changeCount)
                }
            }
        }
        do {
            try svc.start()
            model.running = true
        } catch {
            model.running = false
            NSLog("Sentinel: failed to start monitors: \(error)")
        }
        service = svc
    }

    private func makeAuditSink() -> AuditSink {
        let dir = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)
            .first?.appendingPathComponent("Logs/SentinelDLP", isDirectory: true)
        if let dir, let sink = try? JSONLFileAuditSink(url: dir.appendingPathComponent("audit.jsonl")) {
            return MultiAuditSink([sink, InMemoryAuditSink()])
        }
        return InMemoryAuditSink()
    }

    private func refreshStaticInfo() {
        model.enforcing = service?.isEnforcing ?? true
        model.policyName = Policy.enterpriseDefault().name
        model.patternCount = PatternLibrary.builtin.count
        model.serviceCount = AIServiceCatalog.builtin.entries.count
    }

    private func updateStatusGlyph() {
        guard let button = statusItem.button else { return }
        let symbol = model.statusSymbol
        button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: "Sentinel AI-DLP")
        button.image?.isTemplate = true
    }
}
