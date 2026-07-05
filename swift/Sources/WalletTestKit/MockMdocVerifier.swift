import CborCose
import Foundation
import MDoc
import OpenID4VP
import SdJwt
import WalletAPI

/// A mock OpenID4VP verifier for mdoc: serves an mso_mdoc DCQL query and verifies the returned
/// DeviceResponse — device signature over the OID4VP SessionTranscript, using the deviceKey from the MSO.
/// Unencrypted (`direct_post`).
public actor MockMdocVerifier: HttpTransport {
    public let docType: String
    public let namespace: String
    public let clientId = "verifier.example"
    public let nonce = "vp-nonce-mdoc"
    public let responseUri = "https://verifier.example/response"
    public private(set) var disclosedElements: Set<String>?

    public init(docType: String = "org.iso.18013.5.1.mDL", namespace: String = "org.iso.18013.5.1") {
        self.docType = docType
        self.namespace = namespace
    }

    public func requestUri() -> String {
        let dcql = "{\"credentials\":[{\"id\":\"mdl\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"\(docType)\"}," +
            "\"claims\":[{\"path\":[\"\(namespace)\",\"family_name\"]},{\"path\":[\"\(namespace)\",\"given_name\"]}]}]}"
        return "openid4vp://?client_id=\(enc(clientId))&nonce=\(enc(nonce))&response_mode=direct_post" +
            "&response_uri=\(enc(responseUri))&state=xyz&dcql_query=\(enc(dcql))"
    }

    public func execute(_ request: HttpRequest) async throws -> HttpResponse {
        guard request.url == responseUri, request.method == .post else {
            return HttpResponse(status: 404, headers: [], body: [])
        }
        let bodyStr = String(bytes: request.body ?? [], encoding: .utf8) ?? ""
        var form: [String: String] = [:]
        for pair in bodyStr.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            form[String(kv[0]).removingPercentEncoding ?? ""] = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? "") : ""
        }
        let vpToken = try JsonValue.parse(form["vp_token"]!)
        guard case let .arr(items)? = vpToken["mdl"], case let .str(presentation) = items[0] else {
            throw VpError.responseFailed("no mdl presentation")
        }
        let deviceResponse = try CborDecoder.decode(Base64Url.decode(presentation))
        guard case let .array(documents)? = field(deviceResponse, "documents") else {
            throw VpError.responseFailed("no documents")
        }
        let document = documents[0]
        let issuerSigned = try IssuerSigned.fromCbor(field(document, "issuerSigned")!)
        let deviceKey = try issuerSigned.parseMso().deviceKey

        // device signature over the reconstructed DeviceAuthenticationBytes (thumbprint nil for direct_post)
        let deviceSigned = field(document, "deviceSigned")!
        let deviceSignature = try CoseSign1.fromCbor(field(field(deviceSigned, "deviceAuth")!, "deviceSignature")!)
        let st = try Oid4vpSessionTranscript.build(clientId: clientId, responseUri: responseUri, nonce: nonce, verifierJwkThumbprint: nil)
        let deviceNameSpacesBytes = field(deviceSigned, "nameSpaces")!
        let deviceAuth = Cbor.array([.text("DeviceAuthentication"), st, .text(docType), deviceNameSpacesBytes])
        let deviceAuthBytes = try CborEncoder.encode(.tagged(24, .bytes(try CborEncoder.encode(deviceAuth))))
        guard deviceSignature.verify(publicKey: deviceKey, detachedPayload: deviceAuthBytes) else {
            throw VpError.responseFailed("device signature failed")
        }

        disclosedElements = Set(issuerSigned.nameSpaces.first(where: { $0.0 == namespace })?.1.map { $0.item.elementIdentifier } ?? [])
        return HttpResponse(status: 200, headers: [("Content-Type", "application/json")],
                            body: [UInt8](#"{"redirect_uri":"https://verifier.example/done"}"#.utf8))
    }

    private func field(_ c: Cbor, _ key: String) -> Cbor? {
        guard case let .map(entries) = c else { return nil }
        return entries.first(where: { if case let .text(k) = $0.0 { return k == key }; return false })?.1
    }

    private nonisolated func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s
    }
}
