import CborCose
import Foundation
import MDoc
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VP

/// OpenID4VP mdoc `deviceMac` (ISO 18013-7 B.4.5 / OpenID4VP §B.2.2). The wallet MACs the DeviceResponse
/// when the verifier requests it via `deviceauth_alg_values`, keyed by ECDH between the mdoc `DeviceKey`
/// and the verifier's `EReaderKey` (its response-encryption key) — otherwise it signs.
final class MdocDeviceMacTests: XCTestCase {

    private let docType = "org.iso.18013.5.1.mDL"
    private let namespace = "org.iso.18013.5.1"
    private let origin = "https://verifier.example"
    private let macP256: Int64 = -65537
    private let es256: Int64 = -7

    private struct NoHttp: HttpTransport {
        func execute(_ request: HttpRequest) async throws -> HttpResponse { throw VpError.responseFailed("DC API must not do HTTP") }
    }

    private struct Fixture {
        let area: SoftwareSecureArea
        let issuerSigned: IssuerSigned
        let deviceKeyHandle: KeyHandle
        let deviceKey: EcPublicKey

        func held(_ pref: MdocDeviceAuthMode, keyAgree: Bool = true) throws -> HeldMdoc {
            let area = self.area, handle = deviceKeyHandle
            var keyAgreement: MdocKeyAgreement?
            if keyAgree {
                keyAgreement = { peer in try await area.keyAgreement(key: handle, peerPublicKey: peer, hint: nil) }
            }
            return try HeldMdoc(
                credentialId: "mdl-1", issuerSigned: issuerSigned,
                deviceSigner: SecureAreaCoseSigner(area: area, key: handle, algorithm: .es256),
                deviceKeyAgreement: keyAgreement,
                deviceAuth: pref)
        }
    }

    private func fixture() async throws -> Fixture {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let bytes = try await MdocTestIssuer.issue(
            area: area, issuerKey: issuerKey, deviceKey: deviceKey.publicKey, docType: docType, namespace: namespace,
            elements: [("family_name", .text("Han")), ("given_name", .text("Jongho"))],
            x5chain: [[0x30, 0x01]],
            signed: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validFrom: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validUntil: MdocTestIssuer.isoFormatter.date(from: "2027-01-01T00:00:00Z")!)
        return Fixture(area: area, issuerSigned: try IssuerSigned.decode(bytes), deviceKeyHandle: deviceKey.handle, deviceKey: deviceKey.publicKey)
    }

    /// A standalone verifier encryption public key (the EReaderKey), on P-256.
    private func encKey() async throws -> EcPublicKey {
        let a = SoftwareSecureArea()
        return try await a.createKey(spec: KeySpec(secureArea: a.id, algorithm: .es256)).publicKey
    }

    private func ctx(_ fx: Fixture, encKey: EcPublicKey?, algs: [Int64]?) -> PresentationContext {
        PresentationContext(
            disclosedPaths: [[namespace, "family_name"], [namespace, "given_name"]],
            clientId: "verifier", nonce: "vp-nonce", responseUri: "https://verifier.example/cb",
            issuedAt: 1_700_000_000, transactionData: nil, verifierJwkThumbprint: nil, origin: nil,
            verifierEncryptionKey: encKey, deviceAuthAlgValues: algs)
    }

    private func field(_ c: Cbor, _ key: String) -> Cbor? {
        guard case let .map(entries) = c else { return nil }
        return entries.first { if case let .text(t) = $0.0 { return t == key }; return false }?.1
    }

    private func deviceAuth(_ presentation: String) throws -> Cbor {
        let deviceResponse = try CborDecoder.decode(Base64Url.decode(presentation))
        guard case let .array(documents)? = field(deviceResponse, "documents") else { throw VpError.responseFailed("no documents") }
        return field(field(documents[0], "deviceSigned")!, "deviceAuth")!
    }

    /// Reader-side check: recompute the EMacKey (ECDH is symmetric) and verify the deviceMac binds the transcript.
    private func assertDeviceMacVerifies(_ fx: Fixture, _ presentation: String, encKey: EcPublicKey) async throws {
        let da = try deviceAuth(presentation)
        XCTAssertNil(field(da, "deviceSignature"), "must not sign when the verifier requested deviceMac")
        let deviceMac = try CoseMac0.fromCbor(field(da, "deviceMac")!)

        let st = try Oid4vpSessionTranscript.build(clientId: "verifier", responseUri: "https://verifier.example/cb", nonce: "vp-nonce", verifierJwkThumbprint: nil)
        let deviceNsBytes = Cbor.tagged(24, .bytes(try CborEncoder.encode(.map([]))))
        let authArr = Cbor.array([.text("DeviceAuthentication"), st, .text(docType), deviceNsBytes])
        let deviceAuthBytes = try CborEncoder.encode(.tagged(24, .bytes(try CborEncoder.encode(authArr))))
        let zab = try await fx.area.keyAgreement(key: fx.deviceKeyHandle, peerPublicKey: encKey, hint: nil)
        let emacKey = try MdocDeviceAuth.emacKey(sharedSecret: zab, sessionTranscript: st)
        XCTAssertTrue(deviceMac.verify(key: emacKey, detachedPayload: deviceAuthBytes), "deviceMac must bind DeviceAuthentication")
    }

    func testProducesDeviceMacWhenVerifierRequestsIt() async throws {
        let fx = try await fixture()
        let enc = try await encKey()
        let presentation = try await fx.held(.mac).present(ctx(fx, encKey: enc, algs: [macP256, es256]))
        try await assertDeviceMacVerifies(fx, presentation, encKey: enc)
    }

    func testForcesDeviceMacWhenVerifierAcceptsOnlyMac() async throws {
        // Even with the default signature preference, an only-MAC verifier is satisfied with a deviceMac.
        let fx = try await fixture()
        let enc = try await encKey()
        let presentation = try await fx.held(.signature).present(ctx(fx, encKey: enc, algs: [macP256]))
        try await assertDeviceMacVerifies(fx, presentation, encKey: enc)
    }

    func testDefaultsToSignatureWhenBothAccepted() async throws {
        let fx = try await fixture()
        let enc = try await encKey()
        let presentation = try await fx.held(.signature).present(ctx(fx, encKey: enc, algs: [macP256, es256]))
        let da = try deviceAuth(presentation)
        XCTAssertNotNil(field(da, "deviceSignature"), "default preference signs when signature is accepted")
        XCTAssertNil(field(da, "deviceMac"))
    }

    func testFallsBackToSignatureWhenResponseUnencrypted() async throws {
        // No verifier encryption key → no EReaderKey → deviceMac impossible; the MAC preference still signs.
        let fx = try await fixture()
        let presentation = try await fx.held(.mac).present(ctx(fx, encKey: nil, algs: [macP256, es256]))
        XCTAssertNotNil(field(try deviceAuth(presentation), "deviceSignature"))
    }

    func testFailsWhenVerifierRequiresMacButKeyCannotAgree() async throws {
        // deviceauth_alg_values excludes any signature the wallet can produce, and the DeviceKey cannot ECDH.
        let fx = try await fixture()
        let enc = try await encKey()
        let held = try fx.held(.mac, keyAgree: false)
        do {
            _ = try await held.present(ctx(fx, encKey: enc, algs: [macP256]))
            XCTFail("expected unsupported")
        } catch VpError.unsupported {
            // expected
        }
    }

    func testClientPlumbsDeviceMacOverEncryptedDcApi() async throws {
        // End to end through Openid4VpClient: deviceauth_alg_values parsed, verifier enc key wired as EReaderKey,
        // response encrypted; decrypt and confirm the vp_token carries a deviceMac.
        let fx = try await fixture()
        let recipient = JweRecipientKey()
        let enc = recipient.publicKey
        let jwks = "{\"jwks\":{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"enc\",\"alg\":\"ECDH-ES\",\"kid\":\"enc-1\",\"x\":\"\(Base64Url.encode(enc.x))\",\"y\":\"\(Base64Url.encode(enc.y))\"}]},\"encrypted_response_enc_values_supported\":[\"A128GCM\"],\"vp_formats_supported\":{\"mso_mdoc\":{\"deviceauth_alg_values\":[\(macP256)]}}}"
        let requestJson = "{\"response_type\":\"vp_token\",\"response_mode\":\"dc_api.jwt\",\"nonce\":\"dcapi-nonce\",\"client_metadata\":\(jwks),\"dcql_query\":{\"credentials\":[{\"id\":\"query_0\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"\(docType)\"},\"claims\":[{\"path\":[\"\(namespace)\",\"family_name\"]},{\"path\":[\"\(namespace)\",\"given_name\"]}]}]}}"

        let client = Openid4VpClient(http: NoHttp(), clock: { 1_700_000_000 })
        let request = try await client.resolveDcApiRequest(requestJson, origin: origin)
        let held = try fx.held(.signature)  // preference irrelevant: only MAC is accepted → forced
        let matches = client.match(request, held: [held])
        let response = try await client.respondDcApi(request: request, matches: matches, selection: PresentationSelection.auto(matches), held: [held])

        guard case let .str(jwe)? = response["response"] else { return XCTFail("no encrypted response") }
        let plaintext = String(decoding: try recipient.decrypt(jwe), as: UTF8.self)
        guard case let .arr(arr)? = try JsonValue.parse(plaintext)["vp_token"]?["query_0"], case let .str(presentation) = arr[0] else {
            return XCTFail("no vp_token")
        }
        XCTAssertNotNil(field(try deviceAuth(presentation), "deviceMac"), "encrypted DC API response carries a deviceMac")
    }
}
