import CborCose
import MDoc
import Proximity
import WalletAPI

/// The reader/verifier side of ISO 18013-5 proximity: drives a `ProximityTransport` to request documents
/// from a wallet and verify the returned `DeviceResponse`. Symmetric to `ProximityService.present`; the
/// host supplies the transport (BLE central) and the scanned QR `DeviceEngagement`.
public struct ProximityReaderService: Sendable {
    private let issuerTrust: (any MdocIssuerTrust)?
    private let readerAuth: ReaderAuthSigner?

    init(issuerTrust: (any MdocIssuerTrust)?, readerAuth: ReaderAuthSigner? = nil) {
        self.issuerTrust = issuerTrust
        self.readerAuth = readerAuth
    }

    /// Requests `documents` from a wallet over `transport` (the reader is the BLE central) and verifies the
    /// response against `engagement` (the scanned QR). Fully verified when issuer trust + holder binding
    /// check out (`deviceAuthenticated == true`); otherwise the disclosed elements are still returned, unverified.
    public func read(
        transport: any ProximityTransport,
        engagement: [UInt8],
        documents: [RequestedDocument]
    ) async throws -> [VerifiedDocument] {
        do {
            let docs = try await exchange(transport, engagement, documents)
            await transport.close()
            return docs
        } catch {
            await transport.close()
            throw error
        }
    }

    private func exchange(
        _ transport: any ProximityTransport,
        _ engagement: [UInt8],
        _ documents: [RequestedDocument]
    ) async throws -> [VerifiedDocument] {
        let eDeviceKey = try DeviceEngagement.parseEDeviceKey(engagement)
        let eReader = EphemeralKeyPair()
        let transcript = try ProximitySessionTranscript.build(deviceEngagement: engagement, eReaderKey: eReader.publicKey)
        let enc = try SessionEncryption.forReader(
            ephemeral: eReader, devicePublicKey: eDeviceKey,
            sessionTranscriptBytes: try ProximitySessionTranscript.encode(transcript))
        let reader = MdocReader(readerAuth: readerAuth, issuerTrust: issuerTrust)

        let deviceRequest = try await reader.buildDeviceRequest(documents, sessionTranscript: transcript)
        try await transport.send(try SessionMessages.encodeEstablishment(
            eReaderKey: eReader.publicKey, encryptedDeviceRequest: try enc.encrypt(deviceRequest)))
        let deviceResponse = try enc.decrypt(try SessionMessages.decodeData(try await transport.receive()))

        do {
            if issuerTrust != nil { return try await reader.verifyDeviceResponse(deviceResponse, sessionTranscript: transcript) }
            return try parseUnverified(deviceResponse)
        } catch {
            // Untrusted issuer or holder-binding failure — still surface what the wallet disclosed, unverified.
            return try parseUnverified(deviceResponse)
        }
    }

    private func parseUnverified(_ deviceResponse: [UInt8]) throws -> [VerifiedDocument] {
        try DeviceResponse.decode(deviceResponse).documents.map { doc in
            var elements: [String: [String: Cbor]] = [:]
            for (ns, items) in doc.issuerSigned.nameSpaces {
                var m: [String: Cbor] = [:]
                for e in items { m[e.item.elementIdentifier] = e.item.elementValue }
                elements[ns] = m
            }
            return VerifiedDocument(docType: doc.docType, elements: elements, deviceAuthenticated: false)
        }
    }
}
