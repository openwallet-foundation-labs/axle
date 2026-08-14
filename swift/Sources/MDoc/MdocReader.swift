import CborCose
import Foundation
import WalletAPI

/// A document (and its elements) the reader wants from a wallet.
///
/// `intentToRetain` is the default flag for every requested element; `retainedElements` overrides it per element
/// (namespace -> identifiers), which is the granularity ISO 18013-5 §8.3.2.1.2.1 actually defines — the CDDL is
/// `DataElementIdentifier => IntentToRetain`, so a reader that keeps the customer's name but only glances at
/// their photo has to say so element by element.
public struct RequestedDocument {
    public let docType: String
    public let elements: [(String, [String])]
    public let intentToRetain: Bool
    public let retainedElements: [String: Set<String>]
    public init(docType: String, elements: [(String, [String])], intentToRetain: Bool = false,
                retainedElements: [String: Set<String>] = [:]) {
        self.docType = docType; self.elements = elements; self.intentToRetain = intentToRetain
        self.retainedElements = retainedElements
    }

    /// The `IntentToRetain` value to emit for `elementId` in `namespace`.
    func retains(_ namespace: String, _ elementId: String) -> Bool {
        retainedElements[namespace]?.contains(elementId) ?? intentToRetain
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
    /// Why verification did not complete, when `deviceAuthenticated` is false — e.g. `"digest mismatch for
    /// org.iso.18013.5.1/portrait"`, `"issuerAuth signature invalid"`, `"mdoc expired (validUntil=…)"`. Nil
    /// when the document verified, or when the reader was configured without an issuer trust and never tried.
    ///
    /// "Untrusted issuer" and "forged response" are not the same finding: a caller that treats every
    /// unverified document alike cannot tell a missing trust anchor from a tampered digest, so the reason
    /// travels with the document rather than being swallowed where verification failed.
    public let verificationError: String?

    public init(docType: String, elements: [String: [String: Cbor]], deviceAuthenticated: Bool,
                verificationError: String? = nil) {
        self.docType = docType
        self.elements = elements
        self.deviceAuthenticated = deviceAuthenticated
        self.verificationError = verificationError
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
            // ISO 18013-5 §7.2.5: "an mDL reader shall not request more than two age_over_NN data elements".
            // Scoped per document — the clause governs a data model's own age attestations, and a request for
            // several doctypes that each carry one is not the ladder (16/18/21/25) the cap exists to stop.
            let ageElements = doc.elements.reduce(0) { $0 + AgeAttestation.requestedCount($1.1) }
            guard ageElements <= AgeAttestation.maxRequested else {
                throw MdocError("ISO 18013-5 §7.2.5 allows at most \(AgeAttestation.maxRequested) age_over_NN " +
                                "elements per request; \(doc.docType) asks for \(ageElements)")
            }
            let nameSpaces = Cbor.map(doc.elements.map { ns, elems in
                (.text(ns), .map(elems.map { (.text($0), .bool(doc.retains(ns, $0))) }))
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
    /// - Parameter emacKey: Derives the ISO 18013-5 §9.1.3.5 `EMacKey` from the mdoc `DeviceKey` (ECDH with the
    ///   reader's EReaderKey, then HKDF over the SessionTranscript). Required to verify `deviceMac`.
    public func verifyDeviceResponse(
        _ deviceResponse: [UInt8],
        sessionTranscript: Cbor,
        emacKey: ((EcPublicKey) throws -> [UInt8])? = nil
    ) async throws -> [VerifiedDocument] {
        let response = try DeviceResponse.decode(deviceResponse)
        // §8.3.2.1.2.3 Table 8: a non-zero status means the mdoc returned no documents, with a reason
        // (10 general / 11 CBOR-decode / 12 CBOR-validation). Surface it rather than reporting an empty list.
        guard response.status == 0 else { throw MdocError("mdoc returned DeviceResponse status \(response.status)") }
        guard let trust = issuerTrust else { throw MdocError("verifyDeviceResponse requires an issuer trust") }
        let verifier = MdocVerifier(trust: trust, now: now)
        var out: [VerifiedDocument] = []
        for doc in response.documents {
            let verified = try await verifier.verify(doc.issuerSigned) // issuerAuth + digests + validity
            // §9.3.1 step 4: "verify that the DocType in the MSO matches the relevant DocType in the Documents
            // structure". DeviceAuthentication is signed over the *Document's* docType while the elements are
            // vouched for by the *MSO's*; if they disagree, the two halves describe different credentials.
            guard verified.docType == doc.docType else {
                throw MdocError("docType mismatch: MSO says '\(verified.docType)', Document says '\(doc.docType)'")
            }
            let deviceAuthentication = Cbor.array([.text("DeviceAuthentication"), sessionTranscript, .text(doc.docType), doc.deviceNameSpacesBytes])
            let deviceAuthBytes = try CborEncoder.encode(.tagged(tag24, .bytes(try CborEncoder.encode(deviceAuthentication))))
            let bound: Bool
            if let sig = doc.deviceSignature {
                bound = sig.verify(publicKey: verified.deviceKey, detachedPayload: deviceAuthBytes)
            } else if let mac = doc.deviceMac {
                guard let emacKey else { throw MdocError("deviceMac verification requires the reader ephemeral key (emacKey)") }
                bound = mac.verify(key: try emacKey(verified.deviceKey), detachedPayload: deviceAuthBytes)
            } else {
                throw MdocError("no device authentication for \(doc.docType)")
            }
            guard bound else { throw MdocError("device authentication invalid — holder binding failed for \(doc.docType)") }
            out.append(VerifiedDocument(docType: verified.docType, elements: verified.elements, deviceAuthenticated: true))
        }
        return out
    }
}
