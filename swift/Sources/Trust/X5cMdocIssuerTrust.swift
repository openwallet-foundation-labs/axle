import CborCose
import Foundation
import MDoc

/// Resolves an mdoc issuer key from the `issuerAuth` x5chain, validating the chain to a trust
/// anchor (the mdoc counterpart of `X5cIssuerKeyResolver`). This is how the real EUDI mdoc
/// issuer signs — a COSE x5chain leaf chaining to `PID Issuer CA`.
public struct X5cMdocIssuerTrust: MdocIssuerTrust {
    private let validator: X509ChainValidator

    public init(validator: X509ChainValidator) {
        self.validator = validator
    }

    public func issuerKey(x5chain: [[UInt8]]) async throws -> MdocIssuerKey {
        let chain = try await validator.validate(x5chain) // throws if not trusted
        let leaf = chain[0]
        // The Document Signer's own window, so MdocVerifier can apply §9.3.1 step 5 to the MSO 'signed' date.
        return MdocIssuerKey(key: try X509Support.ecPublicKey(leaf),
                             notBefore: leaf.notValidBefore, notAfter: leaf.notValidAfter)
    }
}
