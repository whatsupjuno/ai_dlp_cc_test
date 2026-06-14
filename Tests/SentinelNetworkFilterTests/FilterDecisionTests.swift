import XCTest
import Foundation
@testable import SentinelNetworkFilter

/// Tests for the pure outbound-flow decision logic (peek / drop / allow) that
/// drives the NEFilterDataProvider, without needing NetworkExtension flow objects.
final class FilterDecisionTests: XCTestCase {

    private let cap = 1024
    private let never: (String) -> Bool = { _ in false }
    private let always: (String) -> Bool = { _ in true }

    func testCiphertextFirstChunkAllows() {
        // Non-UTF-8 bytes on the first chunk ⇒ TLS ciphertext ⇒ allow.
        let bin = Data([0xFF, 0xFE, 0xFD, 0xFC, 0x80, 0x81])
        let d = FilterDataProvider.decideOutbound(buffer: bin, chunkBytes: bin.count, offset: 0,
                                                  maxAccumulate: cap, isSensitive: never)
        XCTAssertEqual(d, .allow)
    }

    func testCleanTextKeepsPeeking() {
        let data = Data("hello world".utf8)
        let d = FilterDataProvider.decideOutbound(buffer: data, chunkBytes: data.count, offset: 0,
                                                  maxAccumulate: cap, isSensitive: never)
        XCTAssertEqual(d, .keepPeeking(passBytes: data.count, peekBytes: cap - data.count))
    }

    func testSensitiveDrops() {
        let data = Data("here is a secret".utf8)
        let d = FilterDataProvider.decideOutbound(buffer: data, chunkBytes: data.count, offset: 0,
                                                  maxAccumulate: cap, isSensitive: always)
        XCTAssertEqual(d, .drop)
    }

    func testCleanAtCapAllows() {
        let data = Data(repeating: 0x61, count: cap) // "a" * cap
        let d = FilterDataProvider.decideOutbound(buffer: data, chunkBytes: data.count, offset: 0,
                                                  maxAccumulate: cap, isSensitive: never)
        XCTAssertEqual(d, .allow)
    }

    func testSensitiveInLaterChunkAfterCleanPrefixIsCaught() {
        // The exact bypass codex flagged: clean first chunk → keep peeking; the
        // secret arrives in a later chunk → it is still inspected and dropped.
        let prefix = Data("POST /v1/chat HTTP/1.1\r\nhost: x\r\n\r\n".utf8)
        let first = FilterDataProvider.decideOutbound(buffer: prefix, chunkBytes: prefix.count,
                                                      offset: 0, maxAccumulate: cap, isSensitive: never)
        XCTAssertEqual(first, .keepPeeking(passBytes: prefix.count, peekBytes: cap - prefix.count))

        let full = prefix + Data("prompt: SSN 123-45-6789".utf8)
        let second = FilterDataProvider.decideOutbound(buffer: full, chunkBytes: 23,
                                                       offset: prefix.count, maxAccumulate: cap,
                                                       isSensitive: always)
        XCTAssertEqual(second, .drop)
    }
}
