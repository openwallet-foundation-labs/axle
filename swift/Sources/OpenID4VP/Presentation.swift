/// Everything a held credential needs to build its OpenID4VP presentation for one query.
public struct PresentationContext {
    /// Concrete leaf paths DCQL selected (SD-JWT VC claim paths / mdoc [ns, element]).
    public let disclosedPaths: [[String]]
    public let clientId: String
    public let nonce: String
    public let responseUri: String?
    public let issuedAt: Int64
    public let transactionData: [String]?
    /// RFC 7638 thumbprint of the verifier's encryption key, for the mdoc OpenID4VP handover (nil if unencrypted).
    public let verifierJwkThumbprint: [UInt8]?
    /// Caller web origin for a Digital Credentials API presentation; non-nil selects the DC API handover.
    public let origin: String?

    public init(disclosedPaths: [[String]], clientId: String, nonce: String, responseUri: String?,
                issuedAt: Int64, transactionData: [String]?, verifierJwkThumbprint: [UInt8]?, origin: String? = nil) {
        self.disclosedPaths = disclosedPaths
        self.clientId = clientId
        self.nonce = nonce
        self.responseUri = responseUri
        self.issuedAt = issuedAt
        self.transactionData = transactionData
        self.verifierJwkThumbprint = verifierJwkThumbprint
        self.origin = origin
    }
}

/// A held credential that can produce an OpenID4VP `vp_token` entry. Both SD-JWT VC
/// (`HeldSdJwtVc`) and mdoc (`HeldMdoc`) conform so `Openid4VpClient` presents either.
public protocol PresentableCredential: QueryableCredential {
    func present(_ ctx: PresentationContext) async throws -> String
}
