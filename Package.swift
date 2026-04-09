// swift-tools-version: 6.3

import PackageDescription

let package = Package(
    name: "pscht",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/swiftlang/swift-subprocess.git", from: "0.4.0"),
    ],
    targets: [
        .executableTarget(
            name: "pscht",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Subprocess", package: "swift-subprocess"),
            ]
        ),
        .testTarget(
            name: "pschtTests",
            dependencies: ["pscht"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
