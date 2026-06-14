import XCTest
import Foundation
@testable import SentinelNetworkFilter

/// Tests for the pure outbound decision logic (hold / drop / allow) that drives
/// the NEFilterDataProvider, without needing NetworkExtension flow objects.
final class FilterDecisionTests: XCTestCase {

    private let cap = 4096
    private let never: (String) -> Bool = { _ in false }
    private let always: (String) -> Bool = { _ in true }

    func testEmptyBufferHolds() {
        XCTAssertEqual(FilterDataProvider.decideOutbound(buffer: Data(), maxAccumulate: cap, isSensitive: never),
                       .hold(peekBytes: cap))
    }

    func testCiphertextAllows() {
        // A TLS-record-like byte sequence with many control bytes ⇒ not text ⇒ allow.
        let bin = Data([0x16, 0x03, 0x03, 0x01, 0x00, 0x01, 0x00, 0xfc] + Array(repeating: UInt8(0xAB), count: 8))
        XCTAssertEqual(FilterDataProvider.decideOutbound(buffer: bin, maxAccumulate: cap, isSensitive: never),
                       .allow)
    }

    func testCleanTextHolds() {
        // Clean plaintext under the cap must be HELD (pass 0), not released.
        let data = Data("POST /v1/chat HTTP/1.1\r\nhost: api.example\r\n\r\nhello".utf8)
        XCTAssertEqual(FilterDataProvider.decideOutbound(buffer: data, maxAccumulate: cap, isSensitive: never),
                       .hold(peekBytes: cap))
    }

    func testSensitiveDrops() {
        let data = Data("prompt with a secret".utf8)
        XCTAssertEqual(FilterDataProvider.decideOutbound(buffer: data, maxAccumulate: cap, isSensitive: always),
                       .drop)
    }

    func testCleanAtCapAllows() {
        let data = Data(repeating: 0x61, count: cap) // "a" * cap
        XCTAssertEqual(FilterDataProvider.decideOutbound(buffer: data, maxAccumulate: cap, isSensitive: never),
                       .allow)
    }

    func testSplitSecretNeverReleasesFirstFragment() {
        // codex P1: a secret split across callbacks. The first (clean-looking)
        // fragment must be HELD — decideOutbound returns .hold, and the provider
        // maps that to passBytes:0, so nothing is released before the combined
        // buffer is recognized and dropped.
        let fragment1 = Data("here is sk-ant-api03-AAAA1111BBBB2222CCCC333".utf8) // missing tail
        XCTAssertEqual(FilterDataProvider.decideOutbound(buffer: fragment1, maxAccumulate: cap, isSensitive: never),
                       .hold(peekBytes: cap), "first fragment must be held, not passed")

        let combined = fragment1 + Data("3DDDD4444EEEE".utf8) // now a complete secret
        XCTAssertEqual(FilterDataProvider.decideOutbound(buffer: combined, maxAccumulate: cap, isSensitive: always),
                       .drop, "combined buffer is dropped — the first fragment was never released")
    }
}
