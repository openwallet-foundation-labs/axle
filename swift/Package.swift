// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "EudiWalletSDK",
    products: [
        .library(name: "CborCose", targets: ["CborCose"])
    ],
    targets: [
        .target(name: "CborCose"),
        .testTarget(name: "CborCoseTests", dependencies: ["CborCose"]),
    ]
)
