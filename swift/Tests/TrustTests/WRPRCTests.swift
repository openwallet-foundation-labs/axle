import Foundation
import SdJwt
import XCTest
@testable import Trust

/// Verifies a real WRPRC (rc-wrp+jwt, JAdES B-B) issued by the deployed registrar, bound to a real
/// WRPAC leaf from the same relying party. Fixtures live in `Resources/` (registrar CA, WRPAC leaf DER,
/// WRPRC compact JWS). `validAt` is inside the certificate + fixture validity window.
final class WRPRCTests: XCTestCase {
    // The fixtures were minted 2026-07-13; validate slightly after their `iat`.
    private let validAt = Date(timeIntervalSince1970: 1_784_000_000)

    private func bytes(_ name: String, _ ext: String) throws -> [UInt8] {
        let url = Bundle.module.url(forResource: name, withExtension: ext)!
        return [UInt8](try Data(contentsOf: url))
    }

    private func wrprcJwt() throws -> String {
        String(decoding: try bytes("wrprc", "jwt"), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func makeVerifier() throws -> WRPRCVerifier {
        let ca = try bytes("registrar_ca", "der")
        let validator = X509ChainValidator(
            anchors: try TrustAnchors.ofDer([ca]),
            validationTime: validAt
        )
        return WRPRCVerifier(validator: validator, time: JwtTimeValidator(now: { self.validAt }))
    }

    func testRealWRPRCVerifiesAndBindsToWRPAC() async throws {
        let verifier = try makeVerifier()
        let wrprc = try wrprcJwt()
        let wrpacLeaf = try bytes("wrpac_leaf", "der")

        let result = try await verifier.verify(wrprc, wrpacLeafDer: wrpacLeaf)

        XCTAssertEqual(result.subject, "VATLU-12345678")
        XCTAssertTrue(
            result.entitlements.contains("https://uri.etsi.org/19475/Entitlement/Service_Provider")
        )
        XCTAssertEqual(result.purpose.first?.value, "Age verification")
        XCTAssertNotNil(result.status, "WRPRC should carry a status-list reference")
        XCTAssertNil(result.intermediary, "a direct (non-intermediated) WRPRC has no intermediary")
        XCTAssertEqual(1, result.registeredCredentials.count, "the WRPRC declares its registered credentials")
        XCTAssertEqual("dc+sd-jwt", result.registeredCredentials.first?.format)
    }

    /// An intermediated WRPRC: the request is signed by the **intermediary's** WRPAC
    /// (organizationIdentifier `LEIXG-INTERMEDIARY01`), so the WRPRC binds to `intermediary.sub`/`act.sub`
    /// — not to `sub`, which stays the final RP (`VATLU-99998888`) for display (RPRC_04 / GEN-5.2.4-09).
    func testIntermediatedWRPRC() async throws {
        let verifier = try makeVerifier()
        let wrprc = String(decoding: try bytes("wrprc_intermediated", "jwt"), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let intermediaryLeaf = try bytes("wrpac_leaf_intermediary", "der")

        let result = try await verifier.verify(wrprc, wrpacLeafDer: intermediaryLeaf)

        XCTAssertEqual(result.subject, "VATLU-99998888", "sub stays the final RP")
        XCTAssertEqual(result.intermediary?.sub, "LEIXG-INTERMEDIARY01")
        XCTAssertEqual(result.intermediary?.name, "Mediator")
    }

    /// An intermediated request MUST be signed by the intermediary's WRPAC. Presenting it with the final
    /// RP's own WRPAC (organizationIdentifier `VATLU-99998888`, i.e. == `sub`) must be rejected: the sender
    /// is not the registered intermediary, so the presented WRPAC does not bind to `intermediary.sub`.
    func testIntermediatedWRPRCRejectsFinalRpWrpac() async throws {
        let verifier = try makeVerifier()
        let wrprc = String(decoding: try bytes("wrprc_intermediated", "jwt"), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let mediatedLeaf = try bytes("wrpac_leaf_mediated", "der")

        do {
            _ = try await verifier.verify(wrprc, wrpacLeafDer: mediatedLeaf)
            XCTFail("expected an intermediary-binding failure")
        } catch let error as TrustError {
            XCTAssertTrue(error.description.contains("organizationIdentifier"))
        }
    }

    /// Linkability: binding the WRPRC against a certificate that lacks the matching
    /// organizationIdentifier (here the CA cert) must be rejected (GEN-5.1.1-02).
    func testLinkabilityMismatchRejected() async throws {
        let verifier = try makeVerifier()
        let wrprc = try wrprcJwt()
        let caAsLeaf = try bytes("registrar_ca", "der")

        do {
            _ = try await verifier.verify(wrprc, wrpacLeafDer: caAsLeaf)
            XCTFail("expected a linkability failure")
        } catch let error as TrustError {
            XCTAssertTrue(error.description.contains("organizationIdentifier"))
        }
    }

    /// A tampered signature must be rejected.
    func testTamperedSignatureRejected() async throws {
        let verifier = try makeVerifier()
        var wrprc = try wrprcJwt()
        // Flip the last character of the signature segment.
        let last = wrprc.removeLast()
        wrprc.append(last == "A" ? "B" : "A")
        let wrpacLeaf = try bytes("wrpac_leaf", "der")

        do {
            _ = try await verifier.verify(wrprc, wrpacLeafDer: wrpacLeaf)
            XCTFail("expected a signature failure")
        } catch is TrustError {
            // expected
        }
    }
}
