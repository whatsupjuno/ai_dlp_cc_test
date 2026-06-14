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
        let eff = DLPService.effectiveVerdict(blockVerdict(channel: .file), channel: .file, enforced: false)
        XCTAssertEqual(eff.action, .audit)
        XCTAssertEqual(eff.findings.count, 1, "findings are preserved")
        XCTAssertTrue(eff.reason.contains("audit-only"))
    }

    func testClipboardEnforcedKeepsAction() {
        // Clipboard with enforcement ON actually applies the action.
        let eff = DLPService.effectiveVerdict(blockVerdict(channel: .clipboard), channel: .clipboard, enforced: true)
        XCTAssertEqual(eff.action, .block)
    }

    func testClipboardObserveModeDowngraded() {
        // Clipboard in observe mode (enforcement off) leaves the pasteboard
        // untouched, so the action must be reported as audit, not block.
        let eff = DLPService.effectiveVerdict(blockVerdict(channel: .clipboard), channel: .clipboard, enforced: false)
        XCTAssertEqual(eff.action, .audit)
        XCTAssertTrue(eff.reason.contains("observe mode"))
    }

    func testAuditAndAllowVerdictsUnchanged() {
        let audit = DLPVerdict(action: .audit, findings: [], matchedRuleID: nil, reason: "r",
                               redactedContent: nil, riskScore: 0, context: InspectionContext(channel: .file))
        XCTAssertEqual(DLPService.effectiveVerdict(audit, channel: .file, enforced: false).action, .audit)
    }
}
