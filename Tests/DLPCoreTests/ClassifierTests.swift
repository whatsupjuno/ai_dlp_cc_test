import XCTest
@testable import DLPCore

final class ClassifierTests: XCTestCase {

    let classifier = DestinationClassifier()

    func testCatalogLoads() {
        XCTAssertGreaterThanOrEqual(AIServiceCatalog.builtin.entries.count, 15)
    }

    func testChatGPTUnsanctioned() {
        let d = classifier.classify(host: "chatgpt.com")
        XCTAssertEqual(d.service?.id, "openai-chatgpt")
        XCTAssertEqual(d.tier, .unsanctioned)
    }

    func testSubdomainMatch() {
        let d = classifier.classify(host: "chat.openai.com")
        XCTAssertNotNil(d.service)
    }

    func testLongestSuffixWinsAPIvsWeb() {
        let d = classifier.classify(host: "api.anthropic.com")
        XCTAssertEqual(d.service?.vendor, "Anthropic")
        XCTAssertTrue(d.isAPIEndpoint)
        XCTAssertEqual(d.tier, .monitored) // anthropic-api default tier
    }

    func testBlockedTier() {
        let d = classifier.classify(host: "chat.deepseek.com")
        XCTAssertEqual(d.tier, .blocked)
    }

    func testUnknownHost() {
        let d = classifier.classify(host: "example.com")
        XCTAssertNil(d.service)
        XCTAssertEqual(d.tier, .unknown)
    }

    func testPortAndTrailingDotStripped() {
        let d = classifier.classify(host: "chatgpt.com.:443")
        XCTAssertEqual(d.service?.id, "openai-chatgpt")
    }

    func testURLClassification() {
        let d = classifier.classify(urlString: "https://claude.ai/chat/123")
        XCTAssertEqual(d.service?.vendor, "Anthropic")
    }

    func testTierOverride() {
        // An org that sanctions Claude.ai.
        let c = DestinationClassifier(overrides: ["anthropic-claude": .sanctioned])
        XCTAssertEqual(c.classify(host: "claude.ai").tier, .sanctioned)
    }

    func testNoSubstringFalsePositive() {
        // "notchatgpt.com" must NOT match "chatgpt.com".
        let d = classifier.classify(host: "notchatgpt.com")
        XCTAssertNil(d.service)
    }

    func testNoDuplicateDomainAcrossServices() {
        // A domain mapped to two services makes one service/tier unreachable
        // (classify returns the first suffix match).
        var owner: [String: String] = [:]
        for e in AIServiceCatalog.builtin.entries {
            // A domain may legitimately appear in both this entry's web and API
            // lists; collapse to a set so we only catch cross-*service* clashes.
            for key in Set((e.webDomains + e.apiHosts).map { $0.lowercased() }) {
                if let other = owner[key], other != e.id {
                    XCTFail("domain '\(key)' appears in both '\(other)' and '\(e.id)'")
                }
                owner[key] = e.id
            }
        }
    }

    func testSharedHostsNotClassifiedAsAI() {
        // Generic shared hosts must not be classified as AI egress (false positives).
        XCTAssertNil(classifier.classify(host: "storage.googleapis.com").service)
        XCTAssertNil(classifier.classify(host: "github.com").service)
        XCTAssertNil(classifier.classify(host: "discord.com").service)
    }

    func testAnthropicConsoleResolvesToAPIService() {
        // console.anthropic.com is platform/API traffic → monitored, not the
        // consumer Claude tier.
        let d = classifier.classify(host: "console.anthropic.com")
        XCTAssertEqual(d.service?.id, "anthropic-api")
        XCTAssertEqual(d.tier, .monitored)
    }
}
