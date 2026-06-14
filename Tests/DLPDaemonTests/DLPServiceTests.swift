import XCTest
@testable import DLPDaemon
import DLPCore

final class DLPServiceTests: XCTestCase {

    private func blockVerdict(channel: Channel) -> DLPVerdict {
        let finding = Finding(
            type: SensitiveDataType(id: "us-ssn", name: "US SSN", category: .governmentID),
            detectorID: "regex", severity: .critical, confidence: .high,
            span: TextSpan(location: 0, length: 11), maskedValue: "12••••••89", valueFingerprint: "abcd")
        return DLPVerdict(action: .block, findings: [finding], matchedRuleID: "block-gov-id-critical",
                          reason: "blocked", redactedContent: nil, riskScore: 0.9,
                          context: InspectionContext(channel: channel))
    }

    func testFileVerdictDowngradedToAudit() {
        // The filesystem vector is observe-only — a block must be reported as audit.
        let eff = DLPService.effectiveVerdict(blockVerdict(channel: .file), channel: .file)
        XCTAssertEqual(eff.action, .audit)
        XCTAssertEqual(eff.findings.count, 1, "findings are preserved")
        XCTAssertTrue(eff.reason.contains("audit-only"))
    }

    func testClipboardVerdictKeepsEnforcementAction() {
        // The clipboard vector actually enforces, so the action is unchanged.
        let eff = DLPService.effectiveVerdict(blockVerdict(channel: .clipboard), channel: .clipboard)
        XCTAssertEqual(eff.action, .block)
    }

    func testAuditAndAllowVerdictsUnchanged() {
        let audit = DLPVerdict(action: .audit, findings: [], matchedRuleID: nil, reason: "r",
                               redactedContent: nil, riskScore: 0, context: InspectionContext(channel: .file))
        XCTAssertEqual(DLPService.effectiveVerdict(audit, channel: .file).action, .audit)
    }
}
