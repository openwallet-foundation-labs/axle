import CborCose
import MDoc
import SdJwt
import WalletAPI

/// A held mdoc (ISO 18013-5) exposed to DCQL as a `QueryableCredential` and presentable via
/// OpenID4VP. mdoc claims are a two-level tree `{ namespace: { elementIdentifier: value } }`,
/// so a DCQL claim path is `[namespace, element]` (both strings). The `deviceSigner` holds the
/// private key bound as the MSO `deviceKey`.
///
/// Device authentication (ISO 18013-5 §9.1.3.5) is a `deviceSignature` by default. When the verifier
/// requests `deviceMac` via `deviceauth_alg_values`, the response is encrypted (so there is a verifier
/// `EReaderKey`), the `deviceKeyAgreement` bridge is present, and `deviceAuth` permits it, this instead
/// produces a `deviceMac` keyed by the DeviceKey/EReaderKey ECDH — see `present`.
public struct HeldMdoc: PresentableCredential {
    public let credentialId: String
    public let issuerSigned: IssuerSigned
    public let format = "mso_mdoc"
    public let vct: String? = nil
    public let docType: String?
    public let claims: JsonValue
    private let deviceSigner: (any CoseSigner)?
    private let deviceSignAlgorithm: SigningAlgorithm
    private let deviceKeyAgreement: MdocKeyAgreement?
    private let deviceAuthMode: MdocDeviceAuthMode

    public init(credentialId: String, issuerSigned: IssuerSigned,
                deviceSigner: (any CoseSigner)? = nil, deviceSignAlgorithm: SigningAlgorithm = .es256,
                deviceKeyAgreement: MdocKeyAgreement? = nil, deviceAuth: MdocDeviceAuthMode = .signature) throws {
        self.credentialId = credentialId
        self.issuerSigned = issuerSigned
        self.deviceSigner = deviceSigner
        self.deviceSignAlgorithm = deviceSignAlgorithm
        self.deviceKeyAgreement = deviceKeyAgreement
        self.deviceAuthMode = deviceAuth
        self.docType = try issuerSigned.parseMso().docType
        self.claims = .obj(issuerSigned.elements().map { ns, elements in
            (ns, .obj(elements.map { ($0.0, CborJson.toJson($0.1)) }))
        })
    }

    /// Builds a base64url `DeviceResponse` disclosing the selected [namespace, element] paths.
    public func present(_ ctx: PresentationContext) async throws -> String {
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
        let deviceAuth = try await selectDeviceAuth(ctx, sessionTranscript: sessionTranscript)
        let deviceResponse = try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docType ?? "", disclosed: disclosed,
            sessionTranscript: sessionTranscript, deviceAuth: deviceAuth)
        return Base64Url.encode(deviceResponse)
    }

    /// Picks `deviceSignature` or `deviceMac` (ISO 18013-5 §9.1.3.5). `deviceMac` needs all of: a
    /// key-agreement DeviceKey (`deviceKeyAgreement`), a verifier `EReaderKey` on the same curve
    /// (`PresentationContext.verifierEncryptionKey`, present only for encrypted responses), and the
    /// verifier listing our MAC algorithm in `deviceauth_alg_values`. When both forms are acceptable the
    /// `deviceAuth` preference decides; when only `deviceMac` is acceptable it is forced (or we fail if
    /// it cannot be produced).
    private func selectDeviceAuth(_ ctx: PresentationContext, sessionTranscript: Cbor) async throws -> DeviceAuth {
        let deviceCurve = try issuerSigned.parseMso().deviceKey.curve
        let accepts = ctx.deviceAuthAlgValues
        let verifierAcceptsMac = accepts == nil || accepts!.contains(MdocDeviceAuth.macAlgForCurve(deviceCurve))
        let verifierAcceptsSig = accepts == nil || accepts!.contains { signatureAlgIds.contains($0) }
        let encKey = ctx.verifierEncryptionKey

        let canMac = deviceKeyAgreement != nil && encKey != nil && encKey!.curve == deviceCurve && verifierAcceptsMac
        let useMac: Bool
        if !canMac { useMac = false }
        else if !verifierAcceptsSig { useMac = true }            // verifier accepts only deviceMac → must MAC
        else { useMac = deviceAuthMode == .mac }                 // both acceptable → honor the wallet preference

        if useMac {
            let zab = try await deviceKeyAgreement!(encKey!)
            return .mac(emacKey: try MdocDeviceAuth.emacKey(sharedSecret: zab, sessionTranscript: sessionTranscript))
        }
        guard let signer = deviceSigner else { throw VpError.unsupported("mdoc presentation requires a device signer") }
        if let accepts, !verifierAcceptsSig {
            throw VpError.unsupported(
                "verifier requires deviceMac (deviceauth_alg_values=\(accepts)) but this DeviceKey cannot " +
                "key-agree with the verifier's encryption key")
        }
        return .signature(signer: signer, algorithm: deviceSignAlgorithm)
    }

    // COSE identifiers for the signature the DeviceKey can produce: the RFC 9053 alg and its
    // fully-specified (curve-pinned) variant, either of which the verifier may list.
    private var signatureAlgIds: Set<Int64> {
        switch deviceSignAlgorithm {
        case .es256: return [-7, -9]
        case .es384: return [-35, -51]
        case .es512: return [-36, -50]
        }
    }
}
