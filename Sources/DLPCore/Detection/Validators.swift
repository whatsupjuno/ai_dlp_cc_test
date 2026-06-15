import Foundation

/// Checksum / statistical validators used to suppress false positives from the
/// regex layer. A regex says "this *looks* like a credit card"; the validator
/// confirms "...and it satisfies the Luhn checksum", which removes the vast
/// majority of incidental 16-digit numbers.
public enum Validators {

    // MARK: - Helpers

    /// Keep only ASCII digits.
    @inline(__always)
    public static func digits(of s: String) -> [Int] {
        s.unicodeScalars.compactMap { scalar in
            (scalar.value >= 48 && scalar.value <= 57) ? Int(scalar.value - 48) : nil
        }
    }

    /// Strip whitespace, hyphens and underscores — common separators in PANs/IBANs.
    @inline(__always)
    public static func compact(_ s: String) -> String {
        s.filter { !$0.isWhitespace && $0 != "-" && $0 != "_" }
    }

    // MARK: - Luhn (credit cards, IMEI, some national IDs)

    /// Validate a numeric string against the Luhn (mod-10) checksum. Separators
    /// are ignored. Returns false for inputs with fewer than 2 digits.
    public static func luhn(_ raw: String) -> Bool {
        let ds = digits(of: raw)
        guard ds.count >= 2 else { return false }
        var sum = 0
        var double = false
        for d in ds.reversed() {
            var v = d
            if double {
                v *= 2
                if v > 9 { v -= 9 }
            }
            sum += v
            double.toggle()
        }
        return sum % 10 == 0
    }

    // MARK: - Shannon entropy (generic high-entropy secrets)

    /// Shannon entropy in **bits per character** of `s`. A random base64 token
    /// approaches ~6 bits/char; English prose sits around ~2–3.
    public static func shannonEntropy(_ s: String) -> Double {
        guard !s.isEmpty else { return 0 }
        var freq: [Character: Int] = [:]
        for c in s { freq[c, default: 0] += 1 }
        let n = Double(s.count)
        var h = 0.0
        for (_, count) in freq {
            let p = Double(count) / n
            h -= p * log2(p)
        }
        return h
    }

    /// True when `s` is long enough and has entropy at/above `minBits` bits/char.
    /// Defaults are tuned to flag tokens like `xK3mNp...` while ignoring words.
    public static func isHighEntropy(_ s: String, minLength: Int = 20, minBits: Double = 3.5) -> Bool {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.count >= minLength else { return false }
        return shannonEntropy(t) >= minBits
    }

    // MARK: - IBAN (ISO 13616, mod-97)

    /// Official ISO 13616 IBAN registry: country code → exact total IBAN length.
    /// mod-97 alone accepts ~1 in 97 random strings and never rejects unassigned
    /// country codes (e.g. `ZZ…`), so we also require a registered country with
    /// its exact length before treating a match as a real IBAN.
    static let ibanLengthByCountry: [String: Int] = [
        "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
        "BG": 22, "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22,
        "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20,
        "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22,
        "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HN": 28, "HR": 21,
        "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30,
        "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20,
        "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
        "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23,
        "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
        "RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24,
        "SM": 27, "SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26,
        "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30
    ]

    /// Validate an IBAN: registered ISO country code, exact country-specific
    /// length, numeric check digits, then the ISO 7064 mod-97 check (remainder 1).
    public static func ibanMod97(_ raw: String) -> Bool {
        let s = compact(raw).uppercased()
        guard s.count >= 15, s.count <= 34 else { return false }
        // Positions 1-2 are the ISO 3166 country code; it must be registered and
        // the total length must match that country exactly (the pattern docs
        // promise per-country length validation). This rejects `ZZ…` and any
        // mod-97-coincidental string whose length is wrong for its country.
        let country = String(s.prefix(2))
        guard country.allSatisfy({ $0.isLetter }),
              let expectedLength = ibanLengthByCountry[country],
              s.count == expectedLength else { return false }
        // Positions 3-4 are the check digits and must be numeric.
        guard s.dropFirst(2).prefix(2).allSatisfy({ $0.isNumber }) else { return false }
        // Move the first four characters to the end.
        let rearranged = String(s.dropFirst(4)) + String(s.prefix(4))
        // Convert letters to numbers: A=10 ... Z=35.
        var numeric = ""
        for ch in rearranged {
            if ch.isNumber {
                numeric.append(ch)
            } else if let ascii = ch.asciiValue, ascii >= 65, ascii <= 90 {
                numeric += String(Int(ascii) - 55)
            } else {
                return false // illegal character
            }
        }
        // Compute mod 97 over the (possibly very long) numeric string piecewise.
        var remainder = 0
        for chunkStart in stride(from: 0, to: numeric.count, by: 7) {
            let start = numeric.index(numeric.startIndex, offsetBy: chunkStart)
            let end = numeric.index(start, offsetBy: min(7, numeric.count - chunkStart))
            let part = String(remainder) + String(numeric[start..<end])
            guard let value = Int(part) else { return false }
            remainder = value % 97
        }
        return remainder == 1
    }

    /// A grouped/printed IBAN is structurally indistinguishable from one followed
    /// by short words: `BE68 5390 0754 7034 by` looks like a longer grouped IBAN to
    /// any regex, so the matcher over-captures the trailing word. Only the
    /// country-specific length disambiguates. Given a (possibly over-captured) IBAN
    /// candidate, return the number of LEADING characters of `raw` (separators
    /// included) that form a valid IBAN, or nil if there is no valid IBAN prefix.
    /// The detector uses this to trim the match back to the real IBAN boundary.
    /// IBAN charset is ASCII, so the returned character count equals the UTF-16
    /// offset the detector needs.
    public static func ibanValidPrefixLength(_ raw: String) -> Int? {
        let chars = Array(raw)
        // Compact to alphanumerics, remembering each alnum's index in `chars`.
        var alnumOriginalIndex: [Int] = []
        var compactChars: [Character] = []
        for (i, c) in chars.enumerated() where c.isLetter || c.isNumber {
            compactChars.append(c); alnumOriginalIndex.append(i)
        }
        let up = String(compactChars).uppercased()
        guard up.count >= 15 else { return nil }
        let country = String(up.prefix(2))
        guard country.allSatisfy({ $0.isLetter }),
              let expectedLength = ibanLengthByCountry[country],
              up.count >= expectedLength else { return nil }
        // Validate exactly the country-length prefix; trailing alnum is not ours.
        guard ibanMod97(String(up.prefix(expectedLength))) else { return nil }
        // Original-string length up to and including the expectedLength-th alnum.
        return alnumOriginalIndex[expectedLength - 1] + 1
    }

    // MARK: - Korean Resident Registration Number (주민등록번호)

    /// Validate that the embedded birth date of a Korean RRN is a real calendar
    /// date. The century comes from the gender/century digit (1,2,5,6 → 1900s;
    /// 3,4,7,8 → 2000s; 9,0 → 1800s). Rejects impossible dates like `990231`.
    public static func krRRNDateValid(_ raw: String) -> Bool {
        let ds = digits(of: raw)
        guard ds.count == 13 else { return false }
        let yy = ds[0] * 10 + ds[1]
        let mm = ds[2] * 10 + ds[3]
        let dd = ds[4] * 10 + ds[5]
        guard (1...12).contains(mm) else { return false }
        let century: Int
        switch ds[6] {
        case 1, 2, 5, 6: century = 1900
        case 3, 4, 7, 8: century = 2000
        case 9, 0: century = 1800
        default: return false
        }
        let year = century + yy
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
        let daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        return (1...daysInMonth[mm - 1]).contains(dd)
    }

    /// Validate a Korean RRN (13 digits, possibly hyphenated `YYMMDD-SBBBBBC`).
    /// Requires a valid calendar date AND the legacy weighted checksum. The
    /// checksum still applies to numbers issued before the 2020 format change;
    /// numbers issued after are not checksum-verifiable, so callers treat a
    /// `false` (with a valid date) as "still a candidate, lower confidence" via
    /// `krRRNDateValid`.
    public static func krRRNChecksum(_ raw: String) -> Bool {
        let ds = digits(of: raw)
        guard ds.count == 13, krRRNDateValid(raw) else { return false }
        let weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
        var sum = 0
        for i in 0..<12 { sum += ds[i] * weights[i] }
        let check = (11 - (sum % 11)) % 10
        return check == ds[12]
    }

    // MARK: - US National Provider Identifier (NPI)

    /// Validate a 10-digit NPI. NPIs use the Luhn algorithm, but with the fixed
    /// prefix "80840" (the ISO issuer prefix for US health identifiers) prepended
    /// before the checksum is computed. Plain Luhn on the bare 10 digits is wrong.
    public static func npiLuhn(_ raw: String) -> Bool {
        let ds = digits(of: raw)
        guard ds.count == 10 else { return false }
        let joined = "80840" + ds.map(String.init).joined()
        return luhn(joined)
    }

    // MARK: - US ABA routing transit number

    /// Validate a 9-digit ABA routing number checksum.
    public static func abaRouting(_ raw: String) -> Bool {
        let ds = digits(of: raw)
        guard ds.count == 9 else { return false }
        let sum =
            3 * (ds[0] + ds[3] + ds[6]) +
            7 * (ds[1] + ds[4] + ds[7]) +
            1 * (ds[2] + ds[5] + ds[8])
        return sum % 10 == 0
    }

    // MARK: - Dispatch

    /// Run the named validator. `none` always passes (regex-only confidence).
    public static func run(_ kind: ValidatorKind, on value: String) -> Bool {
        switch kind {
        case .none: return true
        case .luhn: return luhn(value)
        case .shannonEntropy: return isHighEntropy(value)
        case .ibanMod97: return ibanMod97(value)
        case .krRRNChecksum: return krRRNChecksum(value)
        case .abaRouting: return abaRouting(value)
        case .npiLuhn: return npiLuhn(value)
        }
    }

    /// Some validators can determine the exact boundary of a match from the value
    /// itself, letting the detector trim trailing text a greedy regex captured.
    /// Returns the leading character count that forms a valid match, or nil when
    /// the validator has no boundary refinement (the detector then keeps the full
    /// regex span).
    public static func refinedPrefixLength(_ kind: ValidatorKind, on value: String) -> Int? {
        switch kind {
        case .ibanMod97: return ibanValidPrefixLength(value)
        default: return nil
        }
    }

    /// For a soft-failing validator, whether a checksum-failed match is still a
    /// plausible instance (kept at lower confidence) rather than noise (dropped).
    /// KR RRN: a checksum miss is only a candidate post-2020 RRN if its embedded
    /// date is a real calendar date — so `990231-…` is rejected, not downgraded.
    public static func softFailStillPlausible(_ kind: ValidatorKind, on value: String) -> Bool {
        switch kind {
        case .krRRNChecksum: return krRRNDateValid(value)
        default: return true
        }
    }
}

/// The validators a `PatternRule` can attach to its regex.
public enum ValidatorKind: String, Codable, CaseIterable, Sendable {
    case none
    case luhn
    case shannonEntropy = "shannon_entropy"
    case ibanMod97 = "iban_mod97"
    case krRRNChecksum = "kr_rrn_checksum"
    case abaRouting = "aba_routing"
    case npiLuhn = "npi_luhn"

    /// Whether a validation *failure* should DOWNGRADE confidence rather than
    /// drop the match. True only for the Korean RRN checksum: since the Oct-2020
    /// format change the trailing digits are randomized and no longer checksum-
    /// verifiable, so a checksum miss is frequently a real (post-2020) RRN that
    /// must still be reported — just at lower confidence. For Luhn/IBAN/ABA/NPI a
    /// failure means "not that data type", so those still drop.
    public var failureIsSoft: Bool {
        self == .krRRNChecksum
    }
}
