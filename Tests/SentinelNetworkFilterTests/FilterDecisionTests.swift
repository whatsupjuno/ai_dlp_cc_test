import XCTest
import Foundation
@testable import SentinelNetworkFilter

/// Tests for the pure outbound decision logic (tail-hold: release clean bulk,
/// hold a safe tail, drop on detection) without NetworkExtension flow objects.
final class FilterDecisionTests: XCTestCase {

    private let cap = 4096
    private let tail = 16
    private let never: (String) -> Bool = { _ in false }
    private let always: (String) -> Bool = { _ in true }

    private func decide(_ buffer: Data, released: Int = 0, start: Int = 0, count: Int? = nil,
                        sensitive: @escaping (String) -> Bool) -> FilterDataProvider.OutboundDecision {
        FilterDataProvider.decideOutbound(
            buffer: buffer, alreadyReleased: released, windowStart: start,
            windowCount: count ?? buffer.count, safeTail: tail, maxAccumulate: cap,
            isSensitive: sensitive)
    }

    func testEmptyBufferHolds() {
        XCTAssertEqual(decide(Data(), sensitive: never), .passPartial(passBytes: 0, peekBytes: tail))
    }

    func testCiphertextAllowsAll() {
        let bin = Data([0x16, 0x03, 0x03, 0x01, 0x00, 0x01, 0x00, 0xfc] + Array(repeating: UInt8(0xAB), count: 8))
        XCTAssertEqual(decide(bin, sensitive: never), .allowAll)
    }

    func testSensitiveDrops() {
        XCTAssertEqual(decide(Data("a secret prompt".utf8), sensitive: always), .drop)
    }

    func testSmallCleanBufferHeld() {
        // Under the safe tail ⇒ nothing released yet (passBytes 0).
        let data = Data("0123456789".utf8) // 10 bytes < tail(16)
        XCTAssertEqual(decide(data, sensitive: never), .passPartial(passBytes: 0, peekBytes: tail + cap))
    }

    func testLargeCleanBufferReleasesBulkButHoldsTail() {
        // 1000 clean bytes, tail 16 ⇒ release 984, hold 16 (no deadlock).
        let data = Data(repeating: 0x61, count: 1000)
        XCTAssertEqual(decide(data, sensitive: never), .passPartial(passBytes: 984, peekBytes: tail + cap))
    }

    func testIncrementalReleaseAcrossWindows() {
        // Already released 984; new window [984, 1004). Release 4 more, hold 16.
        let data = Data(repeating: 0x61, count: 1004)
        XCTAssertEqual(decide(data, released: 984, start: 984, count: 20, sensitive: never),
                       .passPartial(passBytes: 4, peekBytes: tail + cap))
    }

    func testCleanAtCapAllowsAll() {
        XCTAssertEqual(decide(Data(repeating: 0x61, count: cap), sensitive: never), .allowAll)
    }

    func testSplitSecretFirstFragmentNotReleased() {
        // codex P1 (round 5): a small first fragment of a secret must be held.
        let fragment1 = Data("0123456".utf8) // < tail
        XCTAssertEqual(decide(fragment1, sensitive: never), .passPartial(passBytes: 0, peekBytes: tail + cap),
                       "small first fragment must be held, not released")
        let combined = fragment1 + Data("789secret".utf8)
        XCTAssertEqual(decide(combined, sensitive: always), .drop,
                       "combined buffer dropped; the held fragment was never released")
    }
}
