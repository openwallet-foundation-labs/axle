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

    public static func deviceResponse(
        issuerSigned: IssuerSigned,
        docType: String,
        disclosed: [String: [String]], // namespace -> element identifiers to disclose
        sessionTranscript: Cbor,
        deviceAuth: DeviceAuth
    ) async throws -> [UInt8] {
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

        // DeviceNameSpaces is empty for a basic presentation.
        let deviceNameSpacesBytes = Cbor.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(.map([]))))

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

        let document = Cbor.map([
            (.text("docType"), .text(docType)),
            (.text("issuerSigned"), issuerSignedCbor),
            (.text("deviceSigned"), deviceSigned),
        ])
        let deviceResponse = Cbor.map([
            (.text("version"), .text("1.0")),
            (.text("documents"), .array([document])),
            (.text("status"), .int(0)),
        ])
        return try CborEncoder.encode(deviceResponse)
    }
}
