// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "fixture",
    dependencies: [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.1"),
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.1.4"),
    ],
    targets: [.target(name: "fixture", dependencies: [
        .product(name: "Logging", package: "swift-log"),
        .product(name: "Collections", package: "swift-collections"),
    ])]
)
