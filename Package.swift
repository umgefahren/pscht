// swift-tools-version: 6.3

import PackageDescription

let package = Package(
    name: "pscht",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/swiftlang/swift-subprocess.git", from: "0.4.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/LebJe/TOMLKit.git", from: "0.6.0"),
    ],
    targets: [
        .systemLibrary(
            name: "CArgon2",
            pkgConfig: "libargon2",
            providers: [
                .apt(["libargon2-dev"]),
                .yum(["libargon2-devel"]),
            ]
        ),
        .executableTarget(
            name: "pscht",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Subprocess", package: "swift-subprocess"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "TOMLKit", package: "TOMLKit"),
                .target(name: "CArgon2", condition: .when(platforms: [.linux])),
            ]
        ),
        .testTarget(
            name: "pschtTests",
            dependencies: ["pscht"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
