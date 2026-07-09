import CborCose
import Foundation
import WalletAPI
import WalletTestKit
import XCTest
@testable import SdJwt

/// draft-ietf-oauth-sd-jwt-vc §2.2.1: "The Issuer MUST include the `typ` header parameter in the SD-JWT.
/// The `typ` value MUST use `dc+sd-jwt`."
///
/// The draft's non-normative note suggests also accepting the pre-2024-11 `vc+sd-jwt` "for a reasonable
/// transitional period". This SDK deliberately does not — these tests pin that decision so it cannot be
/// relaxed by accident.
final class SdJwtVcTypTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_780_000_000)

    private struct PinnedIssuerKey: IssuerKeyResolver {
        let key: EcPublicKey
        func resolve(iss: String, header: JsonValue) async throws -> IssuerSigningKey {
            IssuerSigningKey(publicKey: key, algorithm: .es256)
        }
    }

    private func verifier(_ issuerKey: EcPublicKey) -> SdJwtVcVerifier {
        SdJwtVcVerifier(issuerKeyResolver: PinnedIssuerKey(key: issuerKey),
                        timeValidator: JwtTimeValidator(now: { self.now }))
    }

    /// Issues a PID-shaped SD-JWT VC with the given `typ` header.
    private func issue(_ area: SoftwareSecureArea, typ: String) async throws -> (SdJwt, EcPublicKey) {
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        var n = 0
        let sdJwt = try await SdJwtIssuer(saltProvider: { n += 1; return "salt-\(n)" }).issue(
            signer: SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256),
            typ: typ
        ) { b in
            b.claim("iss", .str("https://issuer.example"))
            b.claim("vct", .str("urn:eudi:pid:1"))
            b.sd("family_name", .str("Han"))
        }
        return (sdJwt, issuerKey.publicKey)
    }

    func testAcceptsTheSpecifiedTyp() async throws {
        let area = SoftwareSecureArea()
        let (sdJwt, issuerKey) = try await issue(area, typ: "dc+sd-jwt")

        let verified = try await verifier(issuerKey).verify(sdJwt)

        XCTAssertEqual("urn:eudi:pid:1", verified.vct)
        XCTAssertEqual("https://issuer.example", verified.issuer)
    }

    /// The legacy value is rejected: the transition ended, and every accepted `typ` widens the type-confusion surface.
    func testRejectsTheLegacyVcSdJwtTyp() async throws {
        let area = SoftwareSecureArea()
        let (sdJwt, issuerKey) = try await issue(area, typ: "vc+sd-jwt")

        do {
            _ = try await verifier(issuerKey).verify(sdJwt)
            XCTFail("vc+sd-jwt must be rejected")
        } catch let error as SdJwtVcError {
            XCTAssertTrue("\(error)".contains("vc+sd-jwt"), "the error names the offending typ: \(error)")
        }
    }

    func testRejectsAnUnrelatedTyp() async throws {
        let area = SoftwareSecureArea()
        let (sdJwt, issuerKey) = try await issue(area, typ: "JWT")

        do {
            _ = try await verifier(issuerKey).verify(sdJwt)
            XCTFail("an unrelated typ must be rejected")
        } catch is SdJwtVcError {}
    }

    /// §2.2.1 makes `typ` mandatory, so an SD-JWT without one is not an SD-JWT VC.
    func testRejectsAMissingTyp() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let header = JsonValue.obj([("alg", .str("ES256"))]) // no typ
        let payload = JsonValue.obj([("iss", .str("https://issuer.example")), ("vct", .str("urn:eudi:pid:1"))])
        let jws = try await Jws.sign(
            header: header, payload: [UInt8](payload.serialize().utf8),
            signer: SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256)).compact()

        do {
            _ = try await verifier(issuerKey.publicKey).verify(try SdJwt.parse("\(jws)~"))
            XCTFail("a missing typ must be rejected")
        } catch is SdJwtVcError {}
    }
}
