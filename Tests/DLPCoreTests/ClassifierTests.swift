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
}
