import XCTest
import Foundation
@testable import SentinelNetworkFilter

/// Tests for the pure outbound decision logic. The contract: release every
/// inspected window synchronously (never withhold an already-sent byte, so a
/// keep-alive upload can never deadlock), drop on detection, allow ciphertext
/// and over-cap bodies. Destination-tier enforcement (handleNewFlow) is the
/// actual guarantee; this is best-effort plaintext inspection beneath it.
final class FilterDecisionTests: XCTestCase {

    private let cap = 4096
    private let peek = 1024
    private let never: (String) -> Bool = { _ in false }
    private let always: (String) -> Bool = { _ in true }

    private func decide(_ buffer: Data, windowCount: Int? = nil,
                        sensitive: @escaping (String) -> Bool) -> FilterDataProvider.OutboundDecision {
        FilterDataProvider.decideOutbound(
            buffer: buffer, windowCount: windowCount ?? buffer.count,
            peekChunk: peek, maxAccumulate: cap, isSensitive: sensitive)
    }

    func testEmptyBufferAsksForMore() {
        XCTAssertEqual(decide(Data(), sensitive: never), .passWindow(passBytes: 0, peekBytes: peek))
    }

    func testCiphertextAllowsAll() {
        let bin = Data([0x16, 0x03, 0x03, 0x01, 0x00, 0x01, 0x00, 0xfc] + Array(repeating: UInt8(0xAB), count: 8))
        XCTAssertEqual(decide(bin, sensitive: never), .allowAll)
    }

    func testSensitiveDrops() {
        XCTAssertEqual(decide(Data("a secret prompt".utf8), sensitive: always), .drop)
    }

    func testCleanWindowReleasedWholeNotHeld() {
        // The entire current window is passed (no withheld tail → no deadlock).
        let data = Data("POST /v1/chat HTTP/1.1\r\n\r\nhello world".utf8)
        XCTAssertEqual(decide(data, sensitive: never),
                       .passWindow(passBytes: data.count, peekBytes: peek))
    }

    func testSmallFinalWindowStillFullyReleased() {
        // A short clean POST body must be released in full (regression for the
        // round-6 hold-all deadlock and round-7 tail stall).
        let data = Data("hi".utf8) // 2 bytes, well under any tail
        XCTAssertEqual(decide(data, sensitive: never),
                       .passWindow(passBytes: 2, peekBytes: peek))
    }

    func testCleanAtCapAllowsAll() {
        XCTAssertEqual(decide(Data(repeating: 0x61, count: cap), sensitive: never), .allowAll)
    }

    func testWindowCountDistinctFromBufferLength() {
        // Cumulative buffer is larger than the current window; passBytes tracks
        // the current window, not the whole buffer.
        let buffer = Data(repeating: 0x61, count: 100)
        XCTAssertEqual(decide(buffer, windowCount: 30, sensitive: never),
                       .passWindow(passBytes: 30, peekBytes: peek))
    }
}
