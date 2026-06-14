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

    /// Validate an IBAN via the ISO 7064 mod-97 check (expected remainder 1).
    public static func ibanMod97(_ raw: String) -> Bool {
        let s = compact(raw).uppercased()
        guard s.count >= 15, s.count <= 34 else { return false }
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

    // MARK: - Korean Resident Registration Number (주민등록번호)

    /// Validate a Korean RRN (13 digits, possibly hyphenated `YYMMDD-SBBBBBC`).
    /// Uses the legacy weighted checksum, which still applies to numbers issued
    /// before the 2020 format change; numbers issued after are not checksum-
    /// verifiable, so a `true` here is high-confidence and a `false` is treated
    /// by callers as "still a candidate, lower confidence".
    public static func krRRNChecksum(_ raw: String) -> Bool {
        let ds = digits(of: raw)
        guard ds.count == 13 else { return false }
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
}
