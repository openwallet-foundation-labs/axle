import CborCose
import Foundation
import WalletAPI

/// A document (and its elements) the reader wants from a wallet.
public struct RequestedDocument {
    public let docType: String
    public let elements: [(String, [String])]
    public let intentToRetain: Bool
    public init(docType: String, elements: [(String, [String])], intentToRetain: Bool = false) {
        self.docType = docType; self.elements = elements; self.intentToRetain = intentToRetain
    }
}

/// Reader authentication material: signs `readerAuth` and presents the reader certificate chain.
public struct ReaderAuthSigner {
    public let signer: any CoseSigner
    public let x5chain: [[UInt8]]
    public let algorithm: SigningAlgorithm
    public init(signer: any CoseSigner, x5chain: [[UInt8]], algorithm: SigningAlgorithm = .es256) {
        self.signer = signer; self.x5chain = x5chain; self.algorithm = algorithm
    }
}

/// A reader-verified document: integrity- and holder-authenticated disclosed elements.
public struct VerifiedDocument {
    public let docType: String
    public let elements: [String: [String: Cbor]]
    /// True once the `deviceSignature` bound to this SessionTranscript verified (holder binding).
    public let deviceAuthenticated: Bool

    public init(docType: String, elements: [String: [String: Cbor]], deviceAuthenticated: Bool) {
        self.docType = docType
        self.elements = elements
        self.deviceAuthenticated = deviceAuthenticated
    }
}

/// The verifier/reader side of mdoc (ISO 18013-5): builds `DeviceRequest`s (optionally signing
/// `readerAuth`) and verifies `DeviceResponse`s — issuer trust + digest integrity **and** the
/// `deviceSignature` holder binding over the SessionTranscript. Symmetric counterpart to
/// `MdocPresenter` / `MdocVerifier` (the wallet side) for a reader/verifier app.
public struct MdocReader {
    private let readerAuth: ReaderAuthSigner?
    private let issuerTrust: (any MdocIssuerTrust)?
    private let now: () -> Date
    private let tag24: UInt64 = 24

    public init(readerAuth: ReaderAuthSigner? = nil, issuerTrust: (any MdocIssuerTrust)? = nil, now: @escaping () -> Date = { Date() }) {
        self.readerAuth = readerAuth; self.issuerTrust = issuerTrust; self.now = now
    }

    public func buildDeviceRequest(_ documents: [RequestedDocument], sessionTranscript: Cbor) async throws -> [UInt8] {
        var docRequests: [Cbor] = []
        for doc in documents {
            let nameSpaces = Cbor.map(doc.elements.map { ns, elems in
                (.text(ns), .map(elems.map { (.text($0), .bool(doc.intentToRetain)) }))
            })
            let itemsRequest = Cbor.map([(.text("docType"), .text(doc.docType)), (.text("nameSpaces"), nameSpaces)])
            let itemsRequestBytes = Cbor.tagged(tag24, .bytes(try CborEncoder.encode(itemsRequest)))

            var entries: [(Cbor, Cbor)] = [(.text("itemsRequest"), itemsRequestBytes)]
            if let ra = readerAuth {
                let readerAuthentication = Cbor.array([.text("ReaderAuthentication"), sessionTranscript, itemsRequestBytes])
                let readerAuthBytes = try CborEncoder.encode(.tagged(tag24, .bytes(try CborEncoder.encode(readerAuthentication))))
                let sig = try await CoseSign1.sign(
                    protected: CoseHeaders.of(algorithm: ra.algorithm.coseAlgorithm),
                    unprotected: CoseHeaders([(.int(33), .array(ra.x5chain.map { .bytes($0) }))]),
                    payload: nil, detachedPayload: readerAuthBytes, signer: ra.signer)
                entries.append((.text("readerAuth"), sig.toCbor(tagged: false)))
            }
            docRequests.append(.map(entries))
        }
        return try CborEncoder.encode(.map([(.text("version"), .text("1.0")), (.text("docRequests"), .array(docRequests))]))
    }

    /// Verifies each document in a `DeviceResponse`: the issuer signature + digests + validity
    /// and the `deviceSignature` over `DeviceAuthentication` bound to `sessionTranscript`
    /// (proving the response came from the credential's holder, this session).
    public func verifyDeviceResponse(_ deviceResponse: [UInt8], sessionTranscript: Cbor) async throws -> [VerifiedDocument] {
        guard let trust = issuerTrust else { throw MdocError("verifyDeviceResponse requires an issuer trust") }
        let verifier = MdocVerifier(trust: trust, now: now)
        var out: [VerifiedDocument] = []
        for doc in try DeviceResponse.decode(deviceResponse).documents {
            let verified = try await verifier.verify(doc.issuerSigned) // issuerAuth + digests + validity
            let deviceAuthentication = Cbor.array([.text("DeviceAuthentication"), sessionTranscript, .text(doc.docType), doc.deviceNameSpacesBytes])
            let deviceAuthBytes = try CborEncoder.encode(.tagged(tag24, .bytes(try CborEncoder.encode(deviceAuthentication))))
            guard doc.deviceSignature.verify(publicKey: verified.deviceKey, detachedPayload: deviceAuthBytes) else {
                throw MdocError("deviceSignature invalid — holder binding failed for \(doc.docType)")
            }
            out.append(VerifiedDocument(docType: verified.docType, elements: verified.elements, deviceAuthenticated: true))
        }
        return out
    }
}
