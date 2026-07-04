import CborCose
import Crypto
import Foundation
import WalletAPI
@testable import MDoc

/// Builds a signed mdoc `IssuerSigned` for tests (the wallet only ever consumes these).
enum MdocTestIssuer {

    static func issue(
        area: any SecureArea,
        issuerKey: KeyInfo,
        deviceKey: EcPublicKey,
        docType: String,
        namespace: String,
        elements: [(String, Cbor)],
        x5chain: [[UInt8]],
        signed: Date,
        validFrom: Date,
        validUntil: Date
    ) async throws -> [UInt8] {
        var itemEntries: [Cbor] = []
        var digests: [(Cbor, Cbor)] = []
        for (index, element) in elements.enumerated() {
            let digestId = Int64(index)
            let itemMap = Cbor.map([
                (.text("digestID"), .int(digestId)),
                (.text("random"), .bytes((0..<16).map { UInt8((index + $0) & 0xff) })),
                (.text("elementIdentifier"), .text(element.0)),
                (.text("elementValue"), element.1),
            ])
            let tagged = Cbor.tagged(TAG_ENCODED_CBOR, .bytes(try CborEncoder.encode(itemMap)))
            itemEntries.append(tagged)
            digests.append((.int(digestId), .bytes([UInt8](SHA256.hash(data: Data(try CborEncoder.encode(tagged)))))))
        }

        let mso = Cbor.map([
            (.text("version"), .text("1.0")),
            (.text("digestAlgorithm"), .text("SHA-256")),
            (.text("valueDigests"), .map([(.text(namespace), .map(digests))])),
            (.text("deviceKeyInfo"), .map([(.text("deviceKey"), CoseKey.encode(deviceKey))])),
            (.text("docType"), .text(docType)),
            (.text("validityInfo"), .map([
                (.text("signed"), tdate(signed)),
                (.text("validFrom"), tdate(validFrom)),
                (.text("validUntil"), tdate(validUntil)),
            ])),
        ])
        let msoBytes = try CborEncoder.encode(.tagged(TAG_ENCODED_CBOR, .bytes(try CborEncoder.encode(mso))))

        let unprotected = CoseHeaders([(.int(33), .array(x5chain.map { .bytes($0) }))])
        let issuerAuth = try await CoseSign1.sign(
            protected: CoseHeaders.of(algorithm: SigningAlgorithm.es256.coseAlgorithm),
            unprotected: unprotected,
            payload: msoBytes,
            signer: SecureAreaCoseSigner(area: area, key: issuerKey.handle, algorithm: .es256)
        )

        let issuerSigned = Cbor.map([
            (.text("nameSpaces"), .map([(.text(namespace), .array(itemEntries))])),
            (.text("issuerAuth"), issuerAuth.toCbor()),
        ])
        return try CborEncoder.encode(issuerSigned)
    }

    static func tdate(_ date: Date) -> Cbor { .tagged(TAG_TDATE, .text(MsoCodec.isoFormatter.string(from: date))) }
}
