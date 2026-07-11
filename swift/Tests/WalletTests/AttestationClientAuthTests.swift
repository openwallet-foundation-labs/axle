import XCTest
import WalletAPI
import OpenID4VCI
import WalletTestKit
@testable import Wallet

final class AttestationClientAuthTests: XCTestCase {
    /// A WUA provider that hands out a distinct token per fetch, so reuse-vs-refresh is observable.
    private actor CountingProvider: WalletAttestationProvider {
        private(set) var fetches = 0
        func walletAttestation(keyInfo: KeyInfo) async throws -> String { fetches += 1; return "wua-\(fetches)" }
        func keyAttestation(keys: [KeyInfo], nonce: String?) async throws -> String { "ka" }
    }

    private func wua(_ h: [(String, String)]) -> String? { h.first { $0.0 == "OAuth-Client-Attestation" }?.1 }
    private func pop(_ h: [(String, String)]) -> String? { h.first { $0.0 == "OAuth-Client-Attestation-PoP" }?.1 }

    func testFreshWuaPerIssuerReusedWithinIssuerFreshPop() async throws {
        let provider = CountingProvider()
        let auth = AttestationClientAuth(
            clientId: "wallet-dev", provider: provider, secureArea: SoftwareSecureArea(),
            storage: InMemoryStorageDriver(), rng: SystemRng(), clock: { 1000 })

        let a1 = try await auth.headers(audience: "https://issuer-a")
        let a2 = try await auth.headers(audience: "https://issuer-a") // same issuer → reuse
        let b = try await auth.headers(audience: "https://issuer-b")  // different issuer → fresh WUA

        XCTAssertEqual(a1.map { $0.0 }, ["OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP"])
        // HAIP §4.4.1: one WUA per issuer — A shares wua-1, B gets wua-2 → 2 fetches, not 3.
        let fetches = await provider.fetches
        XCTAssertEqual(fetches, 2)
        XCTAssertEqual(wua(a1), "wua-1")
        XCTAssertEqual(wua(a2), "wua-1")
        XCTAssertEqual(wua(b), "wua-2")
        XCTAssertNotEqual(pop(a1), pop(a2)) // fresh PoP every request
    }

    func testInstanceKeyPersisted() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let provider = CountingProvider()
        _ = try await AttestationClientAuth(clientId: "wallet-dev", provider: provider, secureArea: area,
                                            storage: storage, rng: SystemRng(), clock: { 1 }).headers(audience: "https://issuer")
        // The instance key's alias is remembered so the same cnf key is reused across restarts.
        let stored = try await storage.get(collection: "wallet-provider", key: "instance-key")
        XCTAssertNotNil(stored)
    }
}
