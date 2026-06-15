import Foundation

/// Broad classification buckets for sensitive data. Map to compliance regimes
/// (PCI-DSS, HIPAA, GDPR, PII, secrets-management) for reporting.
public enum DataCategory: String, Codable, CaseIterable, Sendable {
    case financial          // PAN, IBAN, routing numbers — PCI-DSS scope
    case governmentID       // SSN, passport, national IDs — PII / GDPR special category
    case credential         // API keys, tokens, private keys — secrets management
    case pii                // email, phone, address, IP — GDPR / PII
    case health             // ICD-10, NPI, DEA — HIPAA / PHI
    case network            // connection strings, internal hosts
    case sourceSecret       // secrets embedded in source / config
    case identity           // NL-detected names / orgs / locations

    public var displayName: String {
        switch self {
        case .financial: return "Financial"
        case .governmentID: return "Government ID"
        case .credential: return "Credential / Secret"
        case .pii: return "Personal Information"
        case .health: return "Health / PHI"
        case .network: return "Network / Infrastructure"
        case .sourceSecret: return "Source Secret"
        case .identity: return "Identity Entity"
        }
    }

    /// The compliance regimes this category is typically relevant to.
    public var complianceTags: [String] {
        switch self {
        case .financial: return ["PCI-DSS"]
        case .governmentID: return ["PII", "GDPR", "CCPA", "K-PIPA"]
        case .credential, .sourceSecret: return ["SecretsMgmt", "SOC2"]
        case .pii: return ["PII", "GDPR", "CCPA", "K-PIPA"]
        case .health: return ["HIPAA", "PHI"]
        case .network: return ["SOC2"]
        case .identity: return ["PII", "GDPR"]
        }
    }
}

/// A specific, named type of sensitive datum (e.g. "Visa card number").
/// Identified by a stable id so policies and audit records remain meaningful
/// across pattern-library upgrades.
public struct SensitiveDataType: Codable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let category: DataCategory

    public init(id: String, name: String, category: DataCategory) {
        self.id = id
        self.name = name
        self.category = category
    }
}
