import AppKit

// Sentinel AI-DLP menu-bar agent.
//
// Runs as a background "accessory" app (no Dock icon), presenting a status-bar
// item and a SwiftUI popover. When packaged as a real .app bundle this is driven
// by `LSUIElement` in Info.plist; when launched directly via `swift run` we set
// the activation policy programmatically so it behaves identically.

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

let delegate = AppDelegate()
app.delegate = delegate
app.run()
