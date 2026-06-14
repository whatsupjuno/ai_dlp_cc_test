import AppKit
import SwiftUI
import Combine
import DLPCore
import DLPDaemon

final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AgentModel()
    private var statusItem: NSStatusItem!
    private var popover: NSPopover!
    private var service: DLPService!
    private var cancellables = Set<AnyCancellable>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        setupPopover()
        startService()
        refreshStaticInfo()
    }

    func applicationWillTerminate(_ notification: Notification) {
        service?.stop()
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
