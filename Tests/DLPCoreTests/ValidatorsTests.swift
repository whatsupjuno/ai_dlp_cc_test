import XCTest
@testable import DLPCore

final class ValidatorsTests: XCTestCase {

    // MARK: Luhn

    func testLuhnKnownValid() {
        // Canonical test card numbers (all satisfy Luhn).
        for pan in ["4111111111111111", "5500005555555559", "340000000000009",
                    "6011000990139424", "4012888888881881"] {
            XCTAssertTrue(Validators.luhn(pan), "\(pan) should pass Luhn")
        }
    }

    func testLuhnKnownInvalid() {
        for pan in ["4111111111111112", "1234567812345678", "0000000000000001"] {
            XCTAssertFalse(Validators.luhn(pan), "\(pan) should fail Luhn")
        }
    }

    func testLuhnIgnoresSeparators() {
        XCTAssertTrue(Validators.luhn("4111 1111 1111 1111"))
        XCTAssertTrue(Validators.luhn("4111-1111-1111-1111"))
    }

    func testLuhnRejectsTooShort() {
        XCTAssertFalse(Validators.luhn("4"))
        XCTAssertFalse(Validators.luhn(""))
    }

    // MARK: IBAN mod-97

    func testIBANValid() {
        for iban in ["DE89370400440532013000", "GB29NWBK60161331926819",
                     "FR1420041010050500013M02606", "NL91ABNA0417164300"] {
            XCTAssertTrue(Validators.ibanMod97(iban), "\(iban) should be a valid IBAN")
        }
    }

    func testIBANInvalid() {
        XCTAssertFalse(Validators.ibanMod97("DE89370400440532013001")) // bad check
        XCTAssertFalse(Validators.ibanMod97("XX00")) // too short
        XCTAssertFalse(Validators.ibanMod97("DE89370400440532013000!")) // illegal char
    }

    func testIBANToleratesSpaces() {
        XCTAssertTrue(Validators.ibanMod97("GB29 NWBK 6016 1331 9268 19"))
    }

    // MARK: Korean RRN

    func testKRRRNChecksum() {
        // Synthetic numbers constructed to satisfy the legacy checksum.
        XCTAssertTrue(Validators.krRRNChecksum("900101-1234568"))
        XCTAssertFalse(Validators.krRRNChecksum("900101-1234567")) // wrong check digit
        XCTAssertFalse(Validators.krRRNChecksum("9001011234"))      // wrong length
    }

    // MARK: ABA routing

    func testABARouting() {
        for rtn in ["021000021", "011401533", "091000019"] {
            XCTAssertTrue(Validators.abaRouting(rtn), "\(rtn) should be a valid routing number")
        }
        XCTAssertFalse(Validators.abaRouting("021000020"))
        XCTAssertFalse(Validators.abaRouting("12345678")) // 8 digits
    }

    // MARK: NPI (Luhn with 80840 prefix)

    func testNPILuhn() {
        XCTAssertTrue(Validators.npiLuhn("1234567893"), "canonical valid NPI")
        XCTAssertFalse(Validators.npiLuhn("1234567890"))
        XCTAssertFalse(Validators.npiLuhn("123456789")) // 9 digits
    }

    // MARK: Shannon entropy

    func testEntropy() {
        XCTAssertLessThan(Validators.shannonEntropy("aaaaaaaa"), 0.1)
        XCTAssertGreaterThan(Validators.shannonEntropy("aB3xZ9qK1m"), 2.5)
    }

    func testHighEntropyGate() {
        XCTAssertTrue(Validators.isHighEntropy("xK3mNp7QvR2sT9wY4zB6dF8h")) // random-ish, long
        XCTAssertFalse(Validators.isHighEntropy("password"))                 // short + low entropy
        XCTAssertFalse(Validators.isHighEntropy("aaaaaaaaaaaaaaaaaaaaaaaa")) // long but low entropy
    }

    // MARK: Dispatch

    func testDispatchNonePasses() {
        XCTAssertTrue(Validators.run(.none, on: "anything"))
    }
}
