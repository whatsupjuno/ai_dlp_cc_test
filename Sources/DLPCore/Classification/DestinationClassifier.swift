import Foundation

/// The catalog of known AI services, loaded from the bundled `ai-services.json`
/// resource (20 services) and extensible at runtime.
public struct AIServiceCatalog: Sendable {

    public struct Entry: Codable, Hashable, Sendable {
        public let id: String
        public let name: String
        public let vendor: String
        public let defaultTier: RiskTier
        public let webDomains: [String]
        public let apiHosts: [String]
        public let notes: String

        public var service: AIService {
            AIService(id: id, name: name, vendor: vendor, defaultTier: defaultTier)
        }
    }

    private struct Pack: Decodable { let version: Int; let services: [Entry] }

    public let entries: [Entry]

    public init(entries: [Entry]) {
        self.entries = entries
    }

    /// The built-in catalog shipped as a resource (falls back to a tiny core set).
    public static let builtin: AIServiceCatalog = {
        guard let data = DLPResources.data(named: "ai-services", withExtension: "json"),
              let pack = try? JSONDecoder().decode(Pack.self, from: data),
              !pack.services.isEmpty else {
            return AIServiceCatalog(entries: coreFallback)
        }
        return AIServiceCatalog(entries: pack.services)
    }()

    static let coreFallback: [Entry] = [
        Entry(id: "openai-chatgpt", name: "ChatGPT", vendor: "OpenAI", defaultTier: .unsanctioned,
              webDomains: ["chatgpt.com", "chat.openai.com"], apiHosts: [], notes: ""),
        Entry(id: "openai-api", name: "OpenAI API", vendor: "OpenAI", defaultTier: .monitored,
              webDomains: [], apiHosts: ["api.openai.com"], notes: ""),
        Entry(id: "anthropic-claude", name: "Claude", vendor: "Anthropic", defaultTier: .unsanctioned,
              webDomains: ["claude.ai"], apiHosts: [], notes: ""),
        Entry(id: "anthropic-api", name: "Anthropic API", vendor: "Anthropic", defaultTier: .monitored,
              webDomains: [], apiHosts: ["api.anthropic.com"], notes: ""),
        Entry(id: "google-gemini", name: "Gemini", vendor: "Google", defaultTier: .monitored,
              webDomains: ["gemini.google.com"], apiHosts: ["generativelanguage.googleapis.com"], notes: ""),
    ]
}

/// Classifies an outbound hostname into a `Destination` (recognized service +
/// effective risk tier). Uses longest-suffix matching so `api.anthropic.com`
/// resolves more specifically than `anthropic.com`.
public struct DestinationClassifier: Sendable {

    private struct Index { let domain: String; let entryIndex: Int; let isAPI: Bool }

    private let entries: [AIServiceCatalog.Entry]
    private let index: [Index]
    /// Per-service tier overrides (e.g. an org that sanctions Anthropic API).
    private let overrides: [String: RiskTier]

    public init(catalog: AIServiceCatalog = .builtin, overrides: [String: RiskTier] = [:]) {
        self.entries = catalog.entries
        self.overrides = overrides
        var idx: [Index] = []
        for (i, e) in catalog.entries.enumerated() {
            for d in e.webDomains { idx.append(Index(domain: d.lowercased(), entryIndex: i, isAPI: false)) }
            for d in e.apiHosts { idx.append(Index(domain: d.lowercased(), entryIndex: i, isAPI: true)) }
        }
        // Longest domains first so the first match is the most specific.
        self.index = idx.sorted { $0.domain.count > $1.domain.count }
    }

    /// Classify a hostname (with or without port). Returns `.unknown`-style
    /// `Destination` when the host isn't a recognized AI service.
    public func classify(host rawHost: String) -> Destination {
        let host = Self.normalize(rawHost)
        guard !host.isEmpty else { return .unknown }

        for entry in index where Self.hostMatches(host, domain: entry.domain) {
            let e = entries[entry.entryIndex]
            let tier = overrides[e.id] ?? e.defaultTier
            let isAPI = entry.isAPI || host.hasPrefix("api.")
            return Destination(host: host, service: e.service, tier: tier, isAPIEndpoint: isAPI)
        }

        // Recognized as a host but not an AI service.
        return Destination(host: host, service: nil, tier: .unknown, isAPIEndpoint: host.hasPrefix("api."))
    }

    /// Classify a full URL string.
    public func classify(urlString: String) -> Destination {
        if let url = URL(string: urlString), let h = url.host { return classify(host: h) }
        return classify(host: urlString)
    }

    static func normalize(_ raw: String) -> String {
        var h = raw.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        if let colon = h.firstIndex(of: ":") { h = String(h[..<colon]) } // strip :port
        if h.hasSuffix(".") { h.removeLast() } // strip trailing dot (FQDN)
        return h
    }

    static func hostMatches(_ host: String, domain: String) -> Bool {
        host == domain || host.hasSuffix("." + domain)
    }
}
