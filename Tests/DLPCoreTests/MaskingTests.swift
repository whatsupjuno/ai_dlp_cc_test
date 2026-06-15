import XCTest
import CryptoKit
@testable import DLPCore

final class MaskingTests: XCTestCase {

    func testMaskHidesMiddleAndShortValues() {
        XCTAssertEqual(Masking.mask("4111111111111111"), "41••••••11")
        XCTAssertEqual(Masking.mask("ab"), "••") // too short to reveal anything
        XCTAssertFalse(Masking.mask("123-45-6789").contains("345"))
    }

    func testFingerprintDeterministicAndDistinct() {
        XCTAssertEqual(Masking.fingerprint("123-45-6789"), Masking.fingerprint("123-45-6789"))
        XCTAssertNotEqual(Masking.fingerprint("123-45-6789"), Masking.fingerprint("123-45-6780"))
        XCTAssertEqual(Masking.fingerprint("anything").count, 16) // 8 bytes hex
    }

    func testFingerprintIsKeyedNotPlainSHA256() {
        // With a known pepper the fingerprint must NOT equal the unsalted SHA-256
        // prefix — proving it is HMAC-keyed, so a low-entropy value (SSN/phone/NPI)
        // can't be recovered from the audit log by hashing the candidate space.
        Masking.setFingerprintPepper(Data(repeating: 0xAB, count: 32))
        let value = "123-45-6789"
        let plain = SHA256.hash(data: Data(value.utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
        XCTAssertNotEqual(Masking.fingerprint(value), plain)
        // Deterministic under a fixed pepper.
        XCTAssertEqual(Masking.fingerprint(value), Masking.fingerprint(value))
    }
}
