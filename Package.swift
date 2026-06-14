// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SentinelDLP",
    platforms: [
        .macOS(.v14),
    ],
    products: [
        // The portable, fully-testable detection + policy core.
        .library(name: "DLPCore", targets: ["DLPCore"]),
        // The agent runtime: clipboard / filesystem monitors + orchestration.
        .library(name: "DLPDaemon", targets: ["DLPDaemon"]),
        // The NetworkExtension content-filter provider (deployed as a system extension).
        .library(name: "SentinelNetworkFilter", targets: ["SentinelNetworkFilter"]),
        // Command-line control & scanning tool.
        .executable(name: "dlpctl", targets: ["dlpctl"]),
        // Menu-bar agent application.
        .executable(name: "SentinelAgent", targets: ["SentinelAgent"]),
    ],
    targets: [
        .target(
            name: "DLPCore",
            resources: [
                .process("Resources"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ]
        ),
        .target(
            name: "DLPDaemon",
            dependencies: ["DLPCore"],
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ]
        ),
        .target(
            name: "SentinelNetworkFilter",
            dependencies: ["DLPCore"],
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ]
        ),
        .executableTarget(
            name: "dlpctl",
            dependencies: ["DLPCore", "DLPDaemon"],
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ]
        ),
        .executableTarget(
            name: "SentinelAgent",
            dependencies: ["DLPCore", "DLPDaemon"],
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ]
        ),
        .testTarget(
            name: "DLPCoreTests",
            dependencies: ["DLPCore"],
            resources: [.process("Resources")],
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ]
        ),
        .testTarget(
            name: "DLPDaemonTests",
            dependencies: ["DLPDaemon", "DLPCore"],
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ]
        ),
    ]
)
