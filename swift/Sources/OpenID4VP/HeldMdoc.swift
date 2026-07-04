import CborCose
import MDoc
import SdJwt
import WalletAPI

/// A held mdoc (ISO 18013-5) exposed to DCQL as a `QueryableCredential` and presentable via
/// OpenID4VP. mdoc claims are a two-level tree `{ namespace: { elementIdentifier: value } }`,
/// so a DCQL claim path is `[namespace, element]` (both strings). The `deviceSigner` holds the
/// private key bound as the MSO `deviceKey`.
public struct HeldMdoc: PresentableCredential {
    public let credentialId: String
    public let issuerSigned: IssuerSigned
    public let format = "mso_mdoc"
    public let vct: String? = nil
    public let docType: String?
    public let claims: JsonValue
    private let deviceSigner: (any CoseSigner)?
    private let deviceSignAlgorithm: SigningAlgorithm

    public init(credentialId: String, issuerSigned: IssuerSigned,
                deviceSigner: (any CoseSigner)? = nil, deviceSignAlgorithm: SigningAlgorithm = .es256) throws {
        self.credentialId = credentialId
        self.issuerSigned = issuerSigned
        self.deviceSigner = deviceSigner
        self.deviceSignAlgorithm = deviceSignAlgorithm
        self.docType = try issuerSigned.parseMso().docType
        self.claims = .obj(issuerSigned.elements().map { ns, elements in
            (ns, .obj(elements.map { ($0.0, CborJson.toJson($0.1)) }))
        })
    }

    /// Builds a base64url `DeviceResponse` disclosing the selected [namespace, element] paths.
    public func present(_ ctx: PresentationContext) async throws -> String {
        guard let signer = deviceSigner else { throw VpError.unsupported("mdoc presentation requires a device signer") }
        var disclosed: [String: [String]] = [:]
        for path in ctx.disclosedPaths where path.count >= 2 { disclosed[path[0], default: []].append(path[1]) }
        // DC API presentations bind the caller origin; the URL/QR flow binds client_id + response_uri.
        let sessionTranscript: Cbor
        if let origin = ctx.origin {
            sessionTranscript = try Oid4vpSessionTranscript.dcApi(origin: origin, nonce: ctx.nonce, verifierJwkThumbprint: ctx.verifierJwkThumbprint)
        } else {
            sessionTranscript = try Oid4vpSessionTranscript.build(
                clientId: ctx.clientId, responseUri: ctx.responseUri, nonce: ctx.nonce, verifierJwkThumbprint: ctx.verifierJwkThumbprint)
        }
        let deviceResponse = try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docType ?? "", disclosed: disclosed,
            sessionTranscript: sessionTranscript, deviceSigner: signer, deviceSignAlgorithm: deviceSignAlgorithm)
        return Base64Url.encode(deviceResponse)
    }
}
