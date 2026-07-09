import CborCose
import CredentialStore
import Foundation
import MDoc
import Proximity
import SdJwt
import TransactionLog
import Trust
import WalletAPI

/// ISO 18013-5 proximity presentation. Generates device engagement, establishes the
/// encrypted session over the app-provided `ProximityTransport`, and replies with a device-signed DeviceResponse.
public struct ProximityService {
    let store: DefaultCredentialStore
    let txlog: TransactionLog
    let secureAreas: [any SecureArea]
    /// Verifies reader authentication against configured reader anchors; nil = no anchors, readers stay untrusted.
    let readerTrust: (any MdocReaderTrust)?
    /// When true, a failed final submission is recorded with `.error` status (opt-in via config).
    var recordFailures: Bool = false
    /// ISO 18013-5 §9.1.3.5: sign the DeviceResponse, or MAC it with the DeviceKey/EReaderKey EMacKey.
    var deviceAuthMode: ProximityDeviceAuth = .signature

    /// Starts a proximity session over `transport`: engage → session → reader request → consent → reply.
    /// With `nfc` = true the engagement is delivered via ISO 18013-5 NFC static handover (the app serves the
    /// Handover Select message from `engagementReady`'s `handoverNdef`); otherwise it's a QR code.
    public func present(_ transport: any ProximityTransport, nfc: Bool = false) -> ProximitySession {
        let session = ProximitySession { s in
            s.emit(.generatingEngagement)
            let eDevice = EphemeralKeyPair()
            let engagement: [UInt8]
            let handover: Cbor
            let handoverNdef: [UInt8]?
            if nfc {
                guard let carrier = transport.nfcCarrier() else { throw ProximityError.sessionFailed("transport offers no NFC carrier") }
                engagement = try DeviceEngagement.qr(eDeviceKey: eDevice.publicKey)
                handoverNdef = MdocNfcEngagement.buildHandoverSelect(deviceEngagement: engagement, serviceUuid: carrier.serviceUuid, peripheralServerMode: carrier.peripheralServerMode)
                handover = ProximitySessionTranscript.nfcHandover(handoverNdef!)
            } else {
                engagement = try DeviceEngagement.qr(eDeviceKey: eDevice.publicKey, retrievalMethods: transport.retrievalMethods())
                handover = .null
                handoverNdef = nil
            }
            // engagementReady stays the current state while blocked on receive() — the reader-waiting state.
            s.emit(.engagementReady(deviceEngagement: engagement, handoverNdef: handoverNdef))

            let establishment = try await catchingProximity { try SessionMessages.decodeEstablishment(try await transport.receive()) }
            let transcript = try ProximitySessionTranscript.build(deviceEngagement: engagement, eReaderKey: establishment.eReaderKey, handover: handover)
            let enc = try SessionEncryption.forMdoc(
                ephemeral: eDevice, readerPublicKey: establishment.eReaderKey,
                sessionTranscriptBytes: try ProximitySessionTranscript.encode(transcript))
            let deviceRequest = try await catchingProximity { try DeviceRequest.decode(try enc.decrypt(establishment.encryptedDeviceRequest)) }

            let request = try await buildRequest(deviceRequest, transcript, enc)
            switch await s.awaitDecision(request) {
            case .none:
                try await recordDeclined(request)
                await transport.close()
                s.emit(.declined)
            case let .some(selection):
                s.emit(.submitting)
                do {
                    let deviceResponse = try await buildDeviceResponse(
                        deviceRequest, transcript, selection,
                        eReaderKey: establishment.eReaderKey,
                        transcriptBytes: try ProximitySessionTranscript.encode(transcript))
                    try await transport.send(try SessionMessages.encodeData(try enc.encrypt(deviceResponse)))
                } catch {
                    // Only the final submission failed — record the attempt with .error status (opt-in).
                    if recordFailures { try? await recordError(request, selection) }
                    await transport.close()
                    throw error
                }
                try await recordSuccess(request, selection)
                await transport.close()
                s.emit(.completed)
            }
        }
        session.launch()
        return session
    }

    private func buildRequest(_ deviceRequest: DeviceRequest, _ transcript: Cbor, _ session: SessionEncryption) async throws -> ProximityRequest {
        var documents: [RequestedDocumentView] = []
        for dr in deviceRequest.docRequests {
            var requestedElements: [String: [String]] = [:]
            for (ns, elems) in dr.requested { requestedElements[ns] = elems.map { $0.identifier } }
            documents.append(RequestedDocumentView(docType: dr.docType, requestedElements: requestedElements, candidate: try await findMdoc(dr.docType)))
        }
        let reader = await verifyReader(deviceRequest, transcript)
        return ProximityRequest(documents: documents, satisfiable: documents.allSatisfy { $0.candidate != nil },
                                reader: reader, deviceRequest: deviceRequest, transcript: transcript, session: session)
    }

    /// Verifies reader authentication (ISO 18013-5 §9.1.4) against the configured reader anchors.
    /// ISO/IEC 18013-7:2025 Annex C `org-iso-mdoc` Digital Credentials API: builds the mdoc DeviceResponse for
    /// `deviceRequestBase64`, HPKE-encrypts it to the verifier's `recipientPublicKey` (from `encryptionInfoBase64`),
    /// and returns the base64url of `["dcapi", {enc, cipherText}]`. No transport — the platform mediates.
    public func respondDcApiMdoc(deviceRequestBase64: String, encryptionInfoBase64: String, origin: String) async throws -> String {
        let deviceRequest = try DeviceRequest.decode(try Base64Url.decode(deviceRequestBase64))
        guard case let .array(encInfo) = try CborDecoder.decode(try Base64Url.decode(encryptionInfoBase64)),
              encInfo.count >= 2, case .text("dcapi") = encInfo[0] else {
            throw ProximityError.sessionFailed("malformed EncryptionInfo")
        }
        guard case let .map(infoMap) = encInfo[1],
              let recipientKeyCbor = infoMap.first(where: { if case .text("recipientPublicKey") = $0.0 { return true }; return false })?.1 else {
            throw ProximityError.sessionFailed("EncryptionInfo missing recipientPublicKey")
        }
        let recipientKey = try CoseKey.decode(recipientKeyCbor)

        let transcript = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: encryptionInfoBase64, origin: origin)
        var chosen: [String: CredentialId] = [:]
        for dr in deviceRequest.docRequests where chosen[dr.docType] == nil {
            if let id = try await findMdoc(dr.docType) { chosen[dr.docType] = id }
        }
        guard !chosen.isEmpty else { throw ProximityError.noMatchingCredential("no stored mdoc for the DC API request") }

        let deviceResponse = try await buildDeviceResponse(deviceRequest, transcript, ProximitySelection(chosen: chosen))
        let sealed = try Hpke.sealBaseP256(recipient: recipientKey, info: try CborEncoder.encode(transcript), aad: [], plaintext: deviceResponse)
        let envelope = Cbor.array([
            .text("dcapi"),
            .map([(.text("enc"), .bytes(sealed.enc)), (.text("cipherText"), .bytes(sealed.ciphertext))]),
        ])
        try await recordDcApiMdocSuccess(deviceRequest, transcript, Set(chosen.keys), origin)
        return Base64Url.encode(try CborEncoder.encode(envelope))
    }

    private func recordDcApiMdocSuccess(_ deviceRequest: DeviceRequest, _ transcript: Cbor, _ docTypes: Set<String>, _ origin: String) async throws {
        let reader = await verifyReader(deviceRequest, transcript)
        let documents = deviceRequest.docRequests.filter { docTypes.contains($0.docType) }.map { dr in
            LoggedDocument(format: "mso_mdoc", type: dr.docType, queryId: nil,
                           claims: dr.requested.flatMap { ns, els in els.map { LoggedClaim(path: [ns, $0.identifier]) } })
        }
        let rp = RelyingParty(id: reader.commonName ?? origin, name: reader.commonName ?? origin,
                              trusted: reader.trusted, certificateChainDer: reader.certificateChainDer)
        await txlog.recordPresentation(relyingParty: rp, documents: documents, status: .success)
    }

    private func verifyReader(_ deviceRequest: DeviceRequest, _ transcript: Cbor) async -> ProximityReaderInfo {
        let untrusted = ProximityReaderInfo(trusted: false, commonName: nil, certificateChainDer: [])
        guard let trust = readerTrust,
              let docRequest = deviceRequest.docRequests.first(where: { $0.readerAuth != nil }) else { return untrusted }
        do {
            let info = try await ReaderAuth.verify(docRequest, sessionTranscript: transcript, trust: trust)
            let cn = info.certificateChain?.first.flatMap { X509Support.commonName(fromDer: $0) }
            return ProximityReaderInfo(trusted: info.trusted, commonName: cn, certificateChainDer: info.certificateChain ?? [])
        } catch {
            return untrusted
        }
    }

    private func findMdoc(_ docType: String) async throws -> CredentialId? {
        try await store.list().first(where: { envelope in
            if case .issued = envelope.lifecycle, case let .msoMdoc(dt) = envelope.format, dt == docType { return true }
            return false
        })?.id
    }

    /// Builds the DeviceResponse for the first requested document (single-document retrieval; multi-doc is a
    /// follow-up). `eReaderKey` / `transcriptBytes` are only needed for `deviceMac`; the Digital Credentials
    /// API path has no EReaderKey and always signs.
    private func buildDeviceResponse(
        _ deviceRequest: DeviceRequest, _ transcript: Cbor, _ selection: ProximitySelection,
        eReaderKey: EcPublicKey? = nil, transcriptBytes: [UInt8]? = nil
    ) async throws -> [UInt8] {
        guard let docRequest = deviceRequest.docRequests.first(where: { selection.chosen[$0.docType] != nil }) else {
            throw ProximityError.noMatchingCredential("no chosen document")
        }
        let credentialId = selection.chosen[docRequest.docType]!
        guard let consumed = try await store.consumeInstance(credentialId) else {
            throw ProximityError.noMatchingCredential(docRequest.docType)
        }
        let area = secureAreas.first(where: { $0.id == consumed.instance.key.secureArea }) ?? secureAreas[0]
        let issuerSigned = try IssuerSigned.decode(consumed.instance.payload)

        let deviceAuth: DeviceAuth
        if case .mac = deviceAuthMode, let eReaderKey, let transcriptBytes {
            guard area.capabilities.keyAgreement else {
                throw ProximityError.sessionFailed("deviceMac needs a key-agreement DeviceKey; '\(area.id)' cannot do ECDH")
            }
            // Zab = ECDH(DeviceKey, EReaderKey) computed inside the secure area — the private half never leaves.
            let zab = try await area.keyAgreement(key: consumed.instance.key, peerPublicKey: eReaderKey, hint: nil)
            deviceAuth = .mac(emacKey: try SessionEncryption.emacKey(sharedSecret: zab, sessionTranscriptBytes: transcriptBytes))
        } else {
            deviceAuth = .signature(signer: SecureAreaCoseSigner(area: area, key: consumed.instance.key, algorithm: .es256))
        }

        return try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docRequest.docType, disclosed: docRequest.disclosable(issuerSigned),
            sessionTranscript: transcript, deviceAuth: deviceAuth)
    }

    private func recordSuccess(_ request: ProximityRequest, _ selection: ProximitySelection) async throws {
        await txlog.recordPresentation(relyingParty: proximityReader(request), documents: loggedDocuments(request, selection), status: .success)
    }

    private func recordError(_ request: ProximityRequest, _ selection: ProximitySelection) async throws {
        await txlog.recordPresentation(relyingParty: proximityReader(request), documents: loggedDocuments(request, selection), status: .error)
    }

    private func recordDeclined(_ request: ProximityRequest) async throws {
        await txlog.recordPresentation(relyingParty: proximityReader(request), documents: [], status: .incomplete)
    }

    private func loggedDocuments(_ request: ProximityRequest, _ selection: ProximitySelection) -> [LoggedDocument] {
        request.documents.filter { selection.chosen[$0.docType] != nil }.map { doc in
            LoggedDocument(format: "mso_mdoc", type: doc.docType, queryId: nil,
                           claims: doc.requestedElements.flatMap { ns, els in els.map { LoggedClaim(path: [ns, $0]) } })
        }
    }

    /// The in-person reader, from verified reader authentication (unauthenticated readers stay untrusted).
    private func proximityReader(_ request: ProximityRequest) -> RelyingParty {
        RelyingParty(id: request.reader.commonName ?? "proximity-reader", name: request.reader.commonName,
                     trusted: request.reader.trusted, certificateChainDer: request.reader.certificateChainDer)
    }

    private func catchingProximity<T>(_ block: () async throws -> T) async throws -> T {
        do {
            return try await block()
        } catch let e as Proximity.ProximityError {
            throw ProximityError.sessionFailed(e.description)
        }
    }
}
