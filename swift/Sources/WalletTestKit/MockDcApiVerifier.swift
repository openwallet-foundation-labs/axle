import CborCose
import Foundation
import MDoc
import OpenID4VP
import SdJwt
import WalletAPI

/// A mock Digital Credentials API verifier for mdoc: builds the request object handed to the wallet by
/// the platform (no HTTP) and verifies the returned response — device signature over the origin-bound
/// DC API SessionTranscript, using the deviceKey from the MSO.
public struct MockDcApiVerifier {
    public let docType: String
    public let namespace: String
    public let origin: String
    public let nonce: String

    public init(docType: String = "org.iso.18013.5.1.mDL", namespace: String = "org.iso.18013.5.1",
                origin: String = "https://verifier.example", nonce: String = "dcapi-nonce") {
        self.docType = docType
        self.namespace = namespace
        self.origin = origin
        self.nonce = nonce
    }

    public func requestObject() -> String {
        "{\"response_type\":\"vp_token\",\"response_mode\":\"dc_api\",\"nonce\":\"\(nonce)\"," +
            "\"dcql_query\":{\"credentials\":[{\"id\":\"query_0\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"\(docType)\"}," +
            "\"claims\":[{\"path\":[\"\(namespace)\",\"family_name\"]},{\"path\":[\"\(namespace)\",\"given_name\"]}]}]}}"
    }

    /// Verifies the DC API response object and returns the disclosed element identifiers.
    public func verify(_ responseJson: String) throws -> Set<String> {
        let response = try JsonValue.parse(responseJson)
        guard let vpToken = response["vp_token"], case let .arr(items)? = vpToken["query_0"], case let .str(presentation) = items[0] else {
            throw VpError.responseFailed("no query_0 presentation")
        }
        let deviceResponse = try CborDecoder.decode(Base64Url.decode(presentation))
        guard case let .array(documents)? = field(deviceResponse, "documents") else {
            throw VpError.responseFailed("no documents")
        }
        let document = documents[0]
        let issuerSigned = try IssuerSigned.fromCbor(field(document, "issuerSigned")!)
        let deviceKey = try issuerSigned.parseMso().deviceKey

        let deviceSigned = field(document, "deviceSigned")!
        let deviceSignature = try CoseSign1.fromCbor(field(field(deviceSigned, "deviceAuth")!, "deviceSignature")!)
        let st = try Oid4vpSessionTranscript.dcApi(origin: origin, nonce: nonce, verifierJwkThumbprint: nil)
        let deviceNameSpacesBytes = field(deviceSigned, "nameSpaces")!
        let deviceAuth = Cbor.array([.text("DeviceAuthentication"), st, .text(docType), deviceNameSpacesBytes])
        let deviceAuthBytes = try CborEncoder.encode(.tagged(24, .bytes(try CborEncoder.encode(deviceAuth))))
        guard deviceSignature.verify(publicKey: deviceKey, detachedPayload: deviceAuthBytes) else {
            throw VpError.responseFailed("device signature must bind the DC API origin")
        }

        return Set(issuerSigned.nameSpaces.first(where: { $0.0 == namespace })?.1.map { $0.item.elementIdentifier } ?? [])
    }

    private func field(_ c: Cbor, _ key: String) -> Cbor? {
        guard case let .map(entries) = c else { return nil }
        return entries.first(where: { if case let .text(k) = $0.0 { return k == key }; return false })?.1
    }
}
