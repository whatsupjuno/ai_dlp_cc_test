import Foundation
import NaturalLanguage

/// On-device named-entity recognition using Apple's `NaturalLanguage` framework.
/// This is the "AI" tier of detection: it finds **person names, organizations
/// and locations** that no regex could enumerate, entirely on-device (no data
/// ever leaves the machine — a hard requirement for a privacy-preserving DLP).
///
/// Entities are lower-severity than hard identifiers (a name is less dangerous
/// than an SSN), but in aggregate — e.g. a customer list pasted into a chatbot —
/// they matter, which is why the policy engine can threshold on *count*.
public final class NLEntityDetector: Detector, @unchecked Sendable {
    public let id: String

    /// Only inspect up to this many characters; NER cost is roughly linear and
    /// clipboard/network payloads beyond this are sampled by their prefix.
    private let maxScanLength: Int
    /// Ignore entities shorter than this (cuts noise like single initials).
    private let minEntityLength: Int

    public init(id: String = "nl-ner", maxScanLength: Int = 50_000, minEntityLength: Int = 3) {
        self.id = id
        self.maxScanLength = maxScanLength
        self.minEntityLength = minEntityLength
    }

    public func scan(_ text: String, context: InspectionContext) -> [Finding] {
        guard !text.isEmpty else { return [] }
        let input = text.count > maxScanLength ? String(text.prefix(maxScanLength)) : text
        let ns = input as NSString

        let tagger = NLTagger(tagSchemes: [.nameType])
        tagger.string = input
        let options: NLTagger.Options = [.omitPunctuation, .omitWhitespace, .joinNames]

        var findings: [Finding] = []
        tagger.enumerateTags(
            in: input.startIndex..<input.endIndex,
            unit: .word,
            scheme: .nameType,
            options: options
        ) { tag, tokenRange in
            guard let tag, let mapped = Self.map(tag) else { return true }
            let value = String(input[tokenRange])
            guard value.count >= minEntityLength else { return true }

            let nsRange = NSRange(tokenRange, in: input)
            guard nsRange.location != NSNotFound, NSMaxRange(nsRange) <= ns.length else { return true }

            findings.append(Finding(
                type: mapped.type,
                detectorID: self.id,
                severity: mapped.severity,
                confidence: .medium,
                span: TextSpan(nsRange),
                maskedValue: Masking.mask(value, keepLeading: 1, keepTrailing: 1),
                valueFingerprint: Masking.fingerprint(value.lowercased()),
                note: "ner:\(tag.rawValue)"
            ))
            return true
        }
        return findings
    }

    private static func map(_ tag: NLTag) -> (type: SensitiveDataType, severity: Severity)? {
        switch tag {
        case .personalName:
            return (SensitiveDataType(id: "ner-person", name: "Person Name", category: .identity), .low)
        case .organizationName:
            return (SensitiveDataType(id: "ner-org", name: "Organization Name", category: .identity), .info)
        case .placeName:
            return (SensitiveDataType(id: "ner-place", name: "Location", category: .identity), .info)
        default:
            return nil
        }
    }
}
