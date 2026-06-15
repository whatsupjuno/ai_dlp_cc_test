import Foundation
import CryptoKit

/// Utilities for turning a raw sensitive value into something safe to store in
/// findings, audit logs and UI — without ever persisting the plaintext.
public enum Masking {

    /// Produce a masked preview that reveals at most `keepLeading` leading and
    /// `keepTrailing` trailing characters, replacing the middle with a fixed
    /// number of bullets so the length of the secret is not leaked either.
    ///
    /// Examples:
    ///   "4111111111111111" -> "41••••••••1111"
    ///   "sk-ant-api03-abcd…" -> "sk•••••••cd"
    public static func mask(_ value: String, keepLeading: Int = 2, keepTrailing: Int = 2) -> String {
        let chars = Array(value)
        guard chars.count > keepLeading + keepTrailing else {
            // Too short to safely reveal anything — fully mask.
            return String(repeating: "•", count: max(chars.count, 1))
        }
        let lead = String(chars.prefix(keepLeading))
        let trail = String(chars.suffix(keepTrailing))
        return "\(lead)••••••\(trail)"
    }

    // Pepper for the fingerprint HMAC. A plain SHA-256 of a low-entropy value
    // (an SSN has ~10^9 possibilities, a phone/NPI similar) is trivially reversed
    // by hashing the candidate space — and these fingerprints are exported to the
    // audit log / JSONL / CEF / SIEM, so an unsalted hash would leak the exact raw
    // identifier despite masking. We therefore key the fingerprint with a pepper
    // that is NEVER written to the log.
    private static let pepperLock = NSLock()
    private static var pepper: SymmetricKey = Masking.makeDefaultPepper()

    private static func makeDefaultPepper() -> SymmetricKey {
        // A deployment that needs fingerprints to correlate across runs / endpoints
        // injects a persistent pepper (from keychain/MDM) via the env var or
        // setFingerprintPepper(_:). Otherwise we use a random per-process key:
        // fingerprints still correlate within a run, and the log alone reveals
        // nothing because the key never leaves memory.
        if let hex = ProcessInfo.processInfo.environment["SENTINEL_FINGERPRINT_PEPPER"],
           let data = Data(hexString: hex), data.count >= 16 {
            return SymmetricKey(data: data)
        }
        return SymmetricKey(size: .bits256)
    }

    /// Inject a persistent pepper (e.g. loaded from the keychain or pushed by MDM)
    /// so fingerprints correlate across runs and endpoints. Keep it OUT of the log.
    public static func setFingerprintPepper(_ key: Data) {
        pepperLock.lock(); pepper = SymmetricKey(data: key); pepperLock.unlock()
    }

    /// A short, stable, keyed fingerprint (64 bits of HMAC-SHA256) of the raw
    /// value. Lets us correlate "the same secret seen twice" across events without
    /// storing the secret or letting the log be brute-forced back to it.
    public static func fingerprint(_ value: String) -> String {
        pepperLock.lock(); let key = pepper; pepperLock.unlock()
        let mac = HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: key)
        return mac.prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}

private extension Data {
    /// Decode a hex string (odd length is left-padded with a zero nibble).
    init?(hexString: String) {
        let s = hexString.count % 2 == 0 ? hexString : "0" + hexString
        var data = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            guard let byte = UInt8(s[i..<j], radix: 16) else { return nil }
            data.append(byte); i = j
        }
        self = data
    }
}
