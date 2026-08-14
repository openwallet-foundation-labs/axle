import CborCose
import Crypto
import Foundation

/// The Document Signer resolved from an mdoc `issuerAuth` x5chain: the key that signed the MSO, plus the
/// validity window of the certificate carrying it.
///
/// `notBefore`/`notAfter` exist for ISO 18013-5 §9.3.1 step 5 — "the 'signed' date is within the validity
/// period of the certificate in the MSO header" — a check on the *signing moment*, distinct from the chain
/// validation of step 1, which runs at the verifier's own clock. Nil means the trust implementation could not
/// supply the window, and the check is skipped; the shipped `X5cMdocIssuerTrust` always supplies it.
public struct MdocIssuerKey: Sendable {
    public let key: EcPublicKey
    public let notBefore: Date?
    public let notAfter: Date?

    public init(key: EcPublicKey, notBefore: Date? = nil, notAfter: Date? = nil) {
        self.key = key
        self.notBefore = notBefore
        self.notAfter = notAfter
    }
}

/// Resolves the mdoc issuer's Document Signer from the `issuerAuth` x5chain, validating the chain to
/// a trust anchor. Implemented by the `Trust` module (mirrors SD-JWT VC's IssuerKeyResolver).
public protocol MdocIssuerTrust: Sendable {
    func issuerKey(x5chain: [[UInt8]]) async throws -> MdocIssuerKey
}

/// A verified mdoc: integrity-checked disclosed elements plus the holder (device) binding.
public struct VerifiedMdoc {
    public let docType: String
    public let deviceKey: EcPublicKey
    /// namespace -> (elementIdentifier -> value).
    public let elements: [String: [String: Cbor]]
    public let signed: Date
    public let validFrom: Date
    public let validUntil: Date
}

/// Verifies an mdoc `IssuerSigned` (ISO 18013-5 §9.1.2): resolves + trusts the issuer key from
/// the COSE x5chain, verifies the `issuerAuth` COSE_Sign1 over the MSO, checks every disclosed
/// element's digest against the MSO `valueDigests`, and enforces `validityInfo`.
public struct MdocVerifier {
    private let trust: any MdocIssuerTrust
    private let now: () -> Date

    public init(trust: any MdocIssuerTrust, now: @escaping () -> Date = { Date() }) {
        self.trust = trust
        self.now = now
    }

    public func verify(_ issuerSigned: IssuerSigned) async throws -> VerifiedMdoc {
        guard let x5chain = issuerSigned.issuerCertChain else { throw MdocError("issuerAuth has no x5chain") }
        let issuer = try await trust.issuerKey(x5chain: x5chain) // §9.3.1 step 1: chain validated to a trust anchor

        let cose = issuerSigned.issuerAuth
        guard cose.verify(publicKey: issuer.key) else { throw MdocError("issuerAuth signature invalid") } // step 2

        let mso = try issuerSigned.parseMso()

        // ISO 18013-5 §9.1.2.5 / Table 21: readers must support SHA-256, SHA-384 and SHA-512.
        guard let digestOf = Self.digester(mso.digestAlgorithm) else {
            throw MdocError("unsupported MSO digest algorithm \(mso.digestAlgorithm)")
        }

        // §9.3.1 step 5: validate ValidityInfo. The 'signed' date must fall inside the Document Signer
        // certificate's own validity period — an MSO signed before the DS existed, or after it expired, is not
        // something that certificate ever vouched for, however the chain validates at the verifier's clock.
        if let notBefore = issuer.notBefore, mso.signed < notBefore {
            throw MdocError("MSO signed=\(mso.signed) predates the DS certificate (notBefore=\(notBefore))")
        }
        if let notAfter = issuer.notAfter, mso.signed > notAfter {
            throw MdocError("MSO signed=\(mso.signed) postdates the DS certificate (notAfter=\(notAfter))")
        }
        let instant = now()
        if instant < mso.validFrom { throw MdocError("mdoc not yet valid (validFrom=\(mso.validFrom))") }
        if instant > mso.validUntil { throw MdocError("mdoc expired (validUntil=\(mso.validUntil))") }

        var elements: [String: [String: Cbor]] = [:]
        for (namespace, items) in issuerSigned.nameSpaces {
            guard let nsDigests = mso.valueDigests[namespace] else {
                throw MdocError("MSO has no digests for namespace '\(namespace)'")
            }
            for entry in items {
                guard let expected = nsDigests[entry.item.digestId] else {
                    throw MdocError("no MSO digest for \(namespace)/\(entry.item.digestId)")
                }
                let actual = digestOf(entry.itemBytes)
                guard actual == expected else {
                    throw MdocError("digest mismatch for \(namespace)/\(entry.item.elementIdentifier)")
                }
                elements[namespace, default: [:]][entry.item.elementIdentifier] = entry.item.elementValue
            }
        }

        return VerifiedMdoc(
            docType: mso.docType, deviceKey: mso.deviceKey, elements: elements,
            signed: mso.signed, validFrom: mso.validFrom, validUntil: mso.validUntil
        )
    }

    /// The digest function named by the MSO `digestAlgorithm` (§9.1.2.5), or nil if unsupported.
    private static func digester(_ algorithm: String) -> (([UInt8]) -> [UInt8])? {
        switch algorithm.uppercased() {
        case "SHA-256": return { [UInt8](SHA256.hash(data: Data($0))) }
        case "SHA-384": return { [UInt8](SHA384.hash(data: Data($0))) }
        case "SHA-512": return { [UInt8](SHA512.hash(data: Data($0))) }
        default: return nil
        }
    }
}
