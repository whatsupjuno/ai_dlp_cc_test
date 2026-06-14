import XCTest
@testable import DLPDaemon

final class FileSystemMonitorTests: XCTestCase {

    private let exts: Set<String> = ["txt", "csv", "json", "env", "sql"]

    func testTextExtensionInspectable() {
        XCTAssertTrue(FileSystemMonitor.isInspectable(path: "/tmp/report.csv", textExtensions: exts))
        XCTAssertTrue(FileSystemMonitor.isInspectable(path: "/a/b/data.JSON", textExtensions: exts))
    }

    func testDotEnvIsInspectableDespiteEmptyExtension() {
        // Regression: `.env` has an empty pathExtension and must still be scanned.
        XCTAssertTrue(FileSystemMonitor.isInspectable(path: "/repo/.env", textExtensions: exts))
        XCTAssertTrue(FileSystemMonitor.isInspectable(path: "/repo/.env.local", textExtensions: exts))
        XCTAssertTrue(FileSystemMonitor.isInspectable(path: "/repo/.env.production", textExtensions: exts))
    }

    func testOtherSecretDotfiles() {
        XCTAssertTrue(FileSystemMonitor.isInspectable(path: "/Users/x/.npmrc", textExtensions: exts))
        XCTAssertTrue(FileSystemMonitor.isInspectable(path: "/Users/x/.pgpass", textExtensions: exts))
    }

    func testBinaryAndUnknownExtensionsSkipped() {
        XCTAssertFalse(FileSystemMonitor.isInspectable(path: "/tmp/image.png", textExtensions: exts))
        XCTAssertFalse(FileSystemMonitor.isInspectable(path: "/tmp/archive.zip", textExtensions: exts))
        XCTAssertFalse(FileSystemMonitor.isInspectable(path: "/tmp/binary", textExtensions: exts))
    }
}
