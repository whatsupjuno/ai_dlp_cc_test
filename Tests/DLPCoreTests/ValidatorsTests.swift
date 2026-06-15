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

    func testIBANRejectsUnassignedCountryEvenIfMod97Passes() {
        // codex round-39: `ZZ` is not a registered IBAN country, yet this string
        // satisfies the mod-97 check. Without a country-code/length check it would
        // become a high-confidence financial finding. Must be rejected.
        XCTAssertFalse(Validators.ibanMod97("ZZ73123456789012345678"))
    }

    func testIBANRejectsWrongCountryLength() {
        // DE is 22 chars; a mod-97-passing string of the wrong length for its
        // country must be rejected. Truncating a valid DE IBAN by removing the
        // last two digits and re-deriving check digits is awkward, so assert the
        // length guard directly: a 23-char "DE…" can never be a valid DE IBAN.
        XCTAssertFalse(Validators.ibanMod97("DE893704004405320130000")) // 23 chars, DE wants 22
        // A valid-length FR IBAN with FR replaced by an over-long count also fails.
        XCTAssertNil(Validators.ibanLengthByCountry["ZZ"])
        XCTAssertEqual(Validators.ibanLengthByCountry["DE"], 22)
    }

    func testIBANToleratesSpaces() {
        XCTAssertTrue(Validators.ibanMod97("GB29 NWBK 6016 1331 9268 19"))
    }

    func testIBANValidPrefixLengthTrimsTrailingText() {
        // codex round-42: the validator finds the exact IBAN boundary inside an
        // over-captured candidate using the country length, so trailing words are
        // excluded. "BE68 5390 0754 7034 by" -> the valid IBAN ends at "...7034".
        let prefixLen = Validators.ibanValidPrefixLength("BE68 5390 0754 7034 by")
        XCTAssertEqual(prefixLen, 19) // up to and including the last digit of 7034
        // A clean compact IBAN refines to its full length.
        XCTAssertEqual(Validators.ibanValidPrefixLength("DE89370400440532013000"), 22)
        // Not an IBAN at all -> nil.
        XCTAssertNil(Validators.ibanValidPrefixLength("ZZ73123456789012345678 hello"))
        // codex round-43: a valid IBAN immediately followed by another word char
        // (no separator) is a longer token, NOT an IBAN — must NOT be trimmed to the
        // 22-char prefix. Right boundary must be a separator/non-word or end.
        XCTAssertNil(Validators.ibanValidPrefixLength("DE89370400440532013000A"))
        XCTAssertNil(Validators.ibanValidPrefixLength("DE893704004405320130005"))
        // A separator after the IBAN is a real boundary -> still trims.
        XCTAssertEqual(Validators.ibanValidPrefixLength("DE89370400440532013000 ref"), 22)
    }

    func testIBANYemenRegistered() {
        // codex round-40: Yemen (YE, length 30) joined the ISO 13616 registry in
        // Jul-2024; the country/length gate must not reject real Yemeni IBANs.
        XCTAssertEqual(Validators.ibanLengthByCountry["YE"], 30)
        XCTAssertTrue(Validators.ibanMod97("YE15CBYE0001018861234567891234"))
    }

    // MARK: Korean RRN

    func testKRRRNChecksum() {
        // Synthetic numbers constructed to satisfy the legacy checksum.
        XCTAssertTrue(Validators.krRRNChecksum("900101-1234568"))
        XCTAssertFalse(Validators.krRRNChecksum("900101-1234567")) // wrong check digit
        XCTAssertFalse(Validators.krRRNChecksum("9001011234"))      // wrong length
    }

    func testKRRRNDateValidation() {
        XCTAssertTrue(Validators.krRRNDateValid("900101-1234568"))
        XCTAssertFalse(Validators.krRRNDateValid("990231-1234567")) // Feb 31 — impossible
        XCTAssertFalse(Validators.krRRNDateValid("900001-1234567")) // month 00
        // A valid-looking checksum can't rescue an impossible date.
        XCTAssertFalse(Validators.krRRNChecksum("990231-1234561"))
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
