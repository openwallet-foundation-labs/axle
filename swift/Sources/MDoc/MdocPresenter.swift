import CborCose
import Foundation
import WalletAPI

/// How the mdoc authenticates its response (ISO 18013-5 §9.1.3.5). A wallet whose `DeviceKey` is a
/// signing key produces a `deviceSignature`; one whose `DeviceKey` is a key-agreement key produces a
/// `deviceMac` instead. Readers must accept either — see `MdocReader.verifyDeviceResponse`.
public enum DeviceAuth {
    /// `deviceSignature`: an ECDSA COSE_Sign1 over `DeviceAuthentication`.
    case signature(signer: any CoseSigner, algorithm: SigningAlgorithm = .es256)

    /// `deviceMac`: HMAC-256/256 over `DeviceAuthentication` keyed by the `EMacKey` — HKDF over the ECDH
    /// secret of the mdoc's `DeviceKey` and the reader's `EReaderKey`, salted by the SessionTranscript.
    /// The mdoc computes that secret inside its secure area, so the MAC proves possession of `DeviceKey`
    /// to *this reader only* — unlike a signature, it is not transferable to a third party.
    case mac(emacKey: [UInt8])
}

/// One document of a (possibly multi-document) `DeviceResponse`: which issuer-signed credential to
/// present, which elements to disclose, and how the device authenticates it. Each document carries
/// its own `DeviceAuth` — `DeviceAuthentication` is per-docType and each mdoc has its own DeviceKey.
public struct PresentedDocument {
    public let issuerSigned: IssuerSigned
    public let docType: String
    /// namespace -> element identifiers to disclose.
    public let disclosed: [String: [String]]
    public let deviceAuth: DeviceAuth
    /// Device-signed data elements (namespace -> id -> value), e.g. OpenID4VP mdoc transaction data (B.2.1).
    public let deviceSignedNamespaces: [String: [String: Cbor]]

    public init(
        issuerSigned: IssuerSigned,
        docType: String,
        disclosed: [String: [String]],
        deviceAuth: DeviceAuth,
        deviceSignedNamespaces: [String: [String: Cbor]] = [:]
    ) {
        self.issuerSigned = issuerSigned
        self.docType = docType
        self.disclosed = disclosed
        self.deviceAuth = deviceAuth
        self.deviceSignedNamespaces = deviceSignedNamespaces
    }
}

/// Builds an mdoc `DeviceResponse` (ISO 18013-5 §8.3.2.1.2.2) for presentation: keeps only the
/// disclosed issuer-signed items and produces `DeviceSigned` — a `deviceSignature` or a `deviceMac`
/// over the `DeviceAuthentication` structure (detached payload) bound to the `sessionTranscript`.
public enum MdocPresenter {

    private static let tagEncodedCbor: UInt64 = 24

    /// Convenience for the signature form; equivalent to passing `.signature`.
    public static func deviceResponse(
        issuerSigned: IssuerSigned,
        docType: String,
        disclosed: [String: [String]],
        sessionTranscript: Cbor,
        deviceSigner: any CoseSigner,
        deviceSignAlgorithm: SigningAlgorithm = .es256
    ) async throws -> [UInt8] {
        try await deviceResponse(
            issuerSigned: issuerSigned, docType: docType, disclosed: disclosed,
            sessionTranscript: sessionTranscript,
            deviceAuth: .signature(signer: deviceSigner, algorithm: deviceSignAlgorithm))
    }

    /// Convenience for the single-document response (one `DocRequest` answered).
    public static func deviceResponse(
        issuerSigned: IssuerSigned,
        docType: String,
        disclosed: [String: [String]], // namespace -> element identifiers to disclose
        sessionTranscript: Cbor,
        deviceAuth: DeviceAuth,
        /// Device-signed data elements (namespace -> id -> value), e.g. OpenID4VP mdoc transaction data (B.2.1).
        deviceSignedNamespaces: [String: [String: Cbor]] = [:]
    ) async throws -> [UInt8] {
        try await deviceResponse(
            documents: [PresentedDocument(
                issuerSigned: issuerSigned, docType: docType, disclosed: disclosed,
                deviceAuth: deviceAuth, deviceSignedNamespaces: deviceSignedNamespaces)],
            sessionTranscript: sessionTranscript)
    }

    /// A `DeviceResponse` answering several `DocRequest`s at once — one `Document` per `documents` entry.
    public static func deviceResponse(documents: [PresentedDocument], sessionTranscript: Cbor) async throws -> [UInt8] {
        guard !documents.isEmpty else { throw MdocError("a DeviceResponse needs at least one document") }
        var docs: [Cbor] = []
        for presented in documents {
            docs.append(try await document(presented, sessionTranscript: sessionTranscript))
        }
        let deviceResponse = Cbor.map([
            (.text("version"), .text("1.0")),
            (.text("documents"), .array(docs)),
            (.text("status"), .int(0)),
        ])
        return try CborEncoder.encode(deviceResponse)
    }

    private static func document(_ presented: PresentedDocument, sessionTranscript: Cbor) async throws -> Cbor {
        let issuerSigned = presented.issuerSigned
        let docType = presented.docType
        let disclosed = presented.disclosed
        let deviceAuth = presented.deviceAuth
        let deviceSignedNamespaces = presented.deviceSignedNamespaces
        // Keep only the disclosed items, re-emitting their exact IssuerSignedItemBytes (#6.24).
        var filteredNs: [(Cbor, Cbor)] = []
        for (ns, items) in issuerSigned.nameSpaces {
            guard let ids = disclosed[ns] else { continue }
            let kept = try items.filter { ids.contains($0.item.elementIdentifier) }.map { try CborDecoder.decode($0.itemBytes) }
            if !kept.isEmpty { filteredNs.append((.text(ns), .array(kept))) }
        }
        let issuerSignedCbor = Cbor.map([
            (.text("nameSpaces"), .map(filteredNs)),
            (.text("issuerAuth"), issuerSigned.issuerAuth.toCbor(tagged: false)),
        ])

        // DeviceNameSpaces: empty for a basic presentation, or the provided device-signed data elements.
        let deviceNsMap = Cbor.map(deviceSignedNamespaces.map { (ns, elements) in
            (Cbor.text(ns), Cbor.map(elements.map { (Cbor.text($0.key), $0.value) }))
        })
        let deviceNameSpacesBytes = Cbor.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(deviceNsMap)))

        let deviceAuthentication = Cbor.array([.text("DeviceAuthentication"), sessionTranscript, .text(docType), deviceNameSpacesBytes])
        let deviceAuthBytes = try CborEncoder.encode(.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(deviceAuthentication))))

        let deviceAuthEntry: (Cbor, Cbor)
        switch deviceAuth {
        case let .signature(signer, algorithm):
            let deviceSignature = try await CoseSign1.sign(
                protected: CoseHeaders.of(algorithm: algorithm.coseAlgorithm),
                payload: nil,
                detachedPayload: deviceAuthBytes,
                signer: signer)
            deviceAuthEntry = (.text("deviceSignature"), deviceSignature.toCbor(tagged: false))
        case let .mac(emacKey):
            let deviceMac = try CoseMac0.create(key: emacKey, detachedPayload: deviceAuthBytes)
            deviceAuthEntry = (.text("deviceMac"), deviceMac.toCbor(tagged: false))
        }

        let deviceSigned = Cbor.map([
            (.text("nameSpaces"), deviceNameSpacesBytes),
            (.text("deviceAuth"), .map([deviceAuthEntry])),
        ])

        return Cbor.map([
            (.text("docType"), .text(docType)),
            (.text("issuerSigned"), issuerSignedCbor),
            (.text("deviceSigned"), deviceSigned),
        ])
    }
}
