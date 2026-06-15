import Foundation
import NetworkExtension
#if canImport(SystemExtensions)
import SystemExtensions
#endif

/// Drives the lifecycle of the content-filter **system extension**: requests
/// activation (which prompts the user / is auto-approved by an MDM
/// `SystemExtensions` payload), then installs and enables an `NEFilterManager`
/// configuration so the OS routes new flows to `FilterDataProvider`.
///
/// Invoked by the menu-bar app. Requires the app to be signed with the
/// `com.apple.developer.system-extension.install` and NetworkExtension
/// entitlements; see `packaging/`.
public final class NetworkFilterController: NSObject {

    public enum State: Equatable, Sendable {
        case idle
        case activating
        case needsApproval        // user must approve in System Settings
        case active
        case failed(String)
    }

    /// The bundle identifier of the embedded system extension target.
    public let extensionIdentifier: String
    /// Human-readable name shown in the filter configuration.
    public let localizedDescription: String

    public var onStateChange: ((State) -> Void)?
    public private(set) var state: State = .idle {
        didSet { onStateChange?(state) }
    }

    public init(extensionIdentifier: String, localizedDescription: String = "Sentinel AI-DLP") {
        self.extensionIdentifier = extensionIdentifier
        self.localizedDescription = localizedDescription
    }

    /// Step 1: activate the system extension.
    public func activate() {
        #if canImport(SystemExtensions)
        state = .activating
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        #else
        state = .failed("SystemExtensions framework unavailable on this platform")
        #endif
    }

    /// Step 2: install + enable the content-filter configuration. Call after the
    /// extension is active.
    public func enableFilter(completion: @escaping (Error?) -> Void) {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { [weak self] loadError in
            guard let self else { return }
            if let loadError { completion(loadError); return }

            let config = NEFilterProviderConfiguration()
            config.filterPackets = false
            config.filterSockets = true
            // Without this, macOS has no provider bundle to attach to the enabled
            // filter and outbound flows never reach FilterDataProvider on the
            // in-app activation path (the MDM profile sets the equivalent
            // FilterDataProviderBundleIdentifier key).
            config.filterDataProviderBundleIdentifier = self.extensionIdentifier
            manager.providerConfiguration = config
            manager.localizedDescription = self.localizedDescription
            manager.isEnabled = true

            manager.saveToPreferences { saveError in
                if saveError == nil { self.state = .active }
                completion(saveError)
            }
        }
    }

    /// Disable filtering (keeps the extension installed).
    public func disableFilter(completion: @escaping (Error?) -> Void) {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            if let error { completion(error); return }
            manager.isEnabled = false
            manager.saveToPreferences { completion($0) }
        }
    }
}

#if canImport(SystemExtensions)
extension NetworkFilterController: OSSystemExtensionRequestDelegate {
    public func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace // always take the newer bundled version
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        state = .needsApproval
    }

    public func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            enableFilter { [weak self] error in
                if let error { self?.state = .failed(error.localizedDescription) }
            }
        case .willCompleteAfterReboot:
            state = .needsApproval
        @unknown default:
            state = .active
        }
    }

    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        state = .failed(error.localizedDescription)
    }
}
#endif
