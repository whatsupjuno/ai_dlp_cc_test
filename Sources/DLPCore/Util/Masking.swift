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

    /// A short, stable fingerprint (first 16 hex chars / 64 bits of SHA-256) of
    /// the raw value. Lets us correlate "the same secret seen twice" across
    /// events without ever storing the secret itself.
    public static func fingerprint(_ value: String) -> String {
        let digest = SHA256.hash(data: Data(value.utf8))
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}
