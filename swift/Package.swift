// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "EudiWalletSDK",
    platforms: [.macOS(.v13), .iOS(.v14)],
    products: [
        .library(name: "CborCose", targets: ["CborCose"]),
        .library(name: "WalletAPI", targets: ["WalletAPI"]),
        .library(name: "CredentialStore", targets: ["CredentialStore"]),
        .library(name: "SdJwt", targets: ["SdJwt"]),
        .library(name: "OpenID4VCI", targets: ["OpenID4VCI"]),
        .library(name: "WalletTestKit", targets: ["WalletTestKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "CborCose",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
        .target(name: "WalletAPI", dependencies: ["CborCose"]),
        .target(name: "CredentialStore", dependencies: ["WalletAPI"]),
        .target(
            name: "SdJwt",
            dependencies: ["WalletAPI", "CborCose", .product(name: "Crypto", package: "swift-crypto")]
        ),
        .target(
            name: "OpenID4VCI",
            dependencies: ["WalletAPI", "SdJwt", "CborCose", .product(name: "Crypto", package: "swift-crypto")]
        ),
        .target(
            name: "WalletTestKit",
            dependencies: ["WalletAPI", .product(name: "Crypto", package: "swift-crypto")]
        ),
        .testTarget(
            name: "CborCoseTests",
            dependencies: ["CborCose", .product(name: "Crypto", package: "swift-crypto")]
        ),
        .testTarget(name: "WalletAPITests", dependencies: ["WalletAPI"]),
        .testTarget(name: "WalletTestKitTests", dependencies: ["WalletTestKit"]),
        .testTarget(name: "CredentialStoreTests", dependencies: ["CredentialStore", "WalletTestKit"]),
        .testTarget(name: "SdJwtTests", dependencies: ["SdJwt", "WalletTestKit"]),
        .testTarget(name: "OpenID4VCITests", dependencies: ["OpenID4VCI", "WalletTestKit"]),
    ]
)
