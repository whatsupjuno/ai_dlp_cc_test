import Foundation

/// Robust resource loader for the bundled pattern / service packs.
///
/// We deliberately do NOT use the SwiftPM-generated `Bundle.module`: its accessor
/// only checks `Bundle.main.bundleURL/<bundle>` and a hard-coded build path, then
/// **fatalErrors** if neither exists. That works for `swift run` (bundle sits next
/// to the executable) but a hand-assembled, notarized `Sentinel.app` would crash
/// at startup because the resource bundle lives in `Contents/Resources`, not next
/// to the executable. This loader searches every plausible location for both the
/// bare-executable and `.app` layouts and returns `nil` (→ caller's hard-coded
/// fallback) instead of crashing.
public enum DLPResources {
    private final class Token {}

    /// SwiftPM names the resource bundle `<PackageName>_<TargetName>.bundle`.
    private static let bundleName = "SentinelDLP_DLPCore"

    /// Load a bundled resource file's contents, or `nil` if it can't be found.
    public static func data(named name: String, withExtension ext: String) -> Data? {
        for url in candidateURLs(name: name, ext: ext) {
            if let data = try? Data(contentsOf: url) { return data }
        }
        return nil
    }

    private static func candidateURLs(name: String, ext: String) -> [URL] {
        let token = Bundle(for: Token.self)
        // Roots to search: app Resources, app/exec dir, the linked module's
        // resource/bundle dirs, AND their parent dirs — the SwiftPM resource
        // bundle is often a *sibling* of the main/module bundle (e.g. it sits next
        // to the .xctest bundle in tests, or next to the executable for
        // `swift run`). Covers tests, `swift run`, and a packaged .app.
        var roots: [URL] = []
        if let u = Bundle.main.resourceURL { roots.append(u) }
        roots.append(Bundle.main.bundleURL)
        roots.append(Bundle.main.bundleURL.deletingLastPathComponent())
        if let u = token.resourceURL { roots.append(u) }
        roots.append(token.bundleURL)
        roots.append(token.bundleURL.deletingLastPathComponent())

        var urls: [URL] = []
        for root in roots {
            // (a) inside the SwiftPM resource bundle …
            let bundleURL = root.appendingPathComponent("\(bundleName).bundle")
            if let bundle = Bundle(url: bundleURL),
               let inner = bundle.url(forResource: name, withExtension: ext) {
                urls.append(inner)
            }
            // (b) … or flattened directly into the root (Xcode-built apps).
            urls.append(root.appendingPathComponent("\(name).\(ext)"))
        }
        return urls
    }
}
