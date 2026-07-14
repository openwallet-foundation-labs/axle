import CborCose
import CredentialStore
import Foundation
import MDoc
import OpenID4VP
import SdJwt
import StatusList
import TransactionLog
import Trust
import WalletAPI

/// OpenID4VP remote presentation. Bridges the store to the VP engine + records audit.
public struct PresentationService {
    let vp: Openid4VpClient
    let store: DefaultCredentialStore
    let txlog: TransactionLog
    let secureAreas: [any SecureArea]
    /// Registrar-scoped Token Status List client for RP registration certs (WRPRC); nil when no registrar
    /// anchors are configured. Used to refuse a revoked WRPRC before the consent screen.
    var registrarStatusClient: StatusListClient?
    /// Registrar TS5 API client for the dataset-only path (no WRPRC); nil when no registrar anchors are
    /// configured. Consulted only when `verifyRegistrationViaApi` is on (RPRC_16).
    var registrarApi: RegistrarApiClient?
    /// RPRC_16 opt-in: consult `registrarApi` to confirm a dataset-only RP's registration before consent.
    var verifyRegistrationViaApi: Bool = false
    /// When true, a failed final submission is recorded with `.error` status (opt-in via config).
    var recordFailures: Bool = false
    /// ISO 18013-5 §9.1.3.5 device-auth preference for mdoc presentations (deviceMac when the verifier requests it).
    var deviceAuthMode: MdocDeviceAuthMode = .signature
    var transactionDataBinder: OpenID4VP.MdocTransactionDataBinder?

    /// Remote (URL/QR) presentation: resolve → match stored credentials → consent → direct_post submit.
    public func start(_ requestUri: String) -> PresentationSession {
        runSession(
            resolve: { try await catchingVp { try await vp.resolveRequest(requestUri) } },
            submit: { resolved, matches, selection, held in
                let result = try await catchingVp {
                    try await vp.respond(request: resolved, matches: matches, selection: toVpSelection(selection), held: held)
                }
                return .completed(redirectUri: result.redirectUri, dcApiResponse: nil)
            })
    }

    /// Digital Credentials API presentation (browser-mediated). The platform hands over the `requestObject`
    /// and the caller `origin`; no HTTP is performed — the response object is returned in
    /// `PresentationState.completed(dcApiResponse:)` for the app to pass back to the platform.
    public func startDcApi(_ requestObject: String, origin: String) -> PresentationSession {
        runSession(
            resolve: { try await catchingVp { try await vp.resolveDcApiRequest(requestObject, origin: origin) } },
            submit: { resolved, matches, selection, held in
                let response = try await catchingVp {
                    try await vp.respondDcApi(request: resolved, matches: matches, selection: toVpSelection(selection), held: held)
                }
                return .completed(redirectUri: nil, dcApiResponse: response.serialize())
            })
    }

    private func runSession(
        resolve: @escaping () async throws -> ResolvedRequest,
        submit: @escaping (ResolvedRequest, DcqlMatchResult, PresentationSelection, [any PresentableCredential]) async throws -> PresentationState
    ) -> PresentationSession {
        let session = PresentationSession { s in
            s.emit(.resolvingRequest)
            let resolved = try await resolve()
            // Refuse a revoked RP registration cert (WRPRC) before doing any matching / consent. Only runs
            // when the request actually carried a WRPRC (registration != nil); absent → nothing to check.
            let statusValid = await checkRegistrationStatus(resolved)
            // Dataset-only path (no WRPRC): if the User opted in, confirm the RP's registration against the
            // registrar's TS5 API (RPRC_18). Best-effort — a failure leaves the self-declared dataset unverified.
            let registrarVerifiedCreds = await resolveRegistrarApi(resolved)

            let envelopes = try await store.list().filter { if case .issued = $0.lifecycle { return true }; return false }
            var held: [any PresentableCredential] = []
            for envelope in envelopes {
                if let p = presentableFor(envelope, firstInstance(envelope)) { held.append(p) }
            }
            let matches = vp.match(resolved, held: held)
            let request = buildRequest(resolved, matches, registrarVerifiedCreds: registrarVerifiedCreds, statusValid: statusValid)

            switch await s.awaitDecision(request) {
            case .none:
                try await recordDeclined(resolved)
                // §8.5: tell the verifier the user refused so it stops waiting. Best-effort — an
                // unreachable verifier must not turn a decline into a failure. DC API has no
                // response_uri; there the platform surfaces the refusal (§15.9.2).
                var redirectUri: String?
                if resolved.responseUri != nil {
                    redirectUri = try? await vp.reportError(
                        resolved, code: .accessDenied,
                        description: "the user declined to share the requested credentials"
                    ).redirectUri
                }
                s.emit(.declined(redirectUri: redirectUri))
            case let .some(selection):
                if selection.chosen.isEmpty { throw PresentationError.selectionIncomplete("no credential selected") }
                s.emit(.submitting)
                let chosenHeld = try await buildChosenHeld(envelopes, selection)
                let terminal: PresentationState
                do {
                    terminal = try await submit(resolved, matches, selection, chosenHeld)
                } catch {
                    // Only the final submission failed — record the attempted disclosure with .error status (opt-in).
                    if recordFailures { try? await recordError(resolved, selection, matches, statusValid) }
                    throw error
                }
                try await recordSuccess(resolved, selection, matches, statusValid)
                s.emit(terminal)
            }
        }
        session.launch()
        return session
    }

    /// Dataset-only registration confirmation (wrprc.md §5, RPRC_16/18). Returns the RP's registrar-signed
    /// registered credentials when the request carried only a self-declared `registrar_dataset` AND the User
    /// opted in AND the TS5 lookup succeeds; nil otherwise (WRPRC-attested, opted out, or the call failed — in
    /// which case we proceed with the self-declared dataset, unverified, per §5.3).
    private func resolveRegistrarApi(_ resolved: ResolvedRequest) async -> [RegisteredCredential]? {
        guard let reg = resolved.verifier.registration else { return nil }
        if reg.attested { return nil }                 // a WRPRC already gives authoritative, offline-verified registration
        guard verifyRegistrationViaApi, let api = registrarApi else { return nil } // RPRC_16 opt-in
        guard let registryURI = reg.dataset?.registryURI, let identifier = reg.dataset?.identifier else { return nil }
        // §5.3: could not obtain the registered info → proceed, the dataset stays unverified.
        return try? await api.fetchRegisteredCredentials(registryURI: registryURI, identifier: identifier,
                                                         intendedUseIdentifier: reg.dataset?.intendedUseIdentifier)
    }

    private func buildRequest(_ resolved: ResolvedRequest, _ matches: DcqlMatchResult,
                              registrarVerifiedCreds: [RegisteredCredential]? = nil,
                              statusValid: Bool? = nil) -> PresentationRequest {
        let required = matches.requiredQueryIds
        let queries = matches.candidatesByQuery.map { queryId, candidates in
            QueryPresentation(
                queryId: queryId, required: required.contains(queryId),
                candidates: candidates.map { PresentationCandidate(credentialId: CredentialId($0.credential.credentialId), disclosedPaths: $0.disclosedPaths) },
                multiple: candidates.first?.query.multiple ?? false)
        }
        let v = resolved.verifier
        let registration = v.registration.map { r -> VerifierRegistration in
            // Prefer the registrar-signed credentials from the TS5 lookup (dataset-only + opt-in) over the
            // self-declared ones; a WRPRC-attested request already carries authoritative registeredCredentials.
            let registered = registrarVerifiedCreds ?? r.registeredCredentials
            // RPRC_21 attribute-scope check: which requested attributes fall outside what the RP registered.
            let unregistered = RegistrationScope.unregistered(resolved.dcqlQuery, registered: registered)
            return VerifierRegistration(
                subject: r.subject, entitlements: r.entitlements,
                purpose: r.purpose.map { PurposeText(lang: $0.lang, value: $0.value) },
                intermediarySub: r.intermediarySub, intermediaryName: r.intermediaryName,
                // Reaching here means any revoked WRPRC was already refused; validated iff a status client ran.
                statusValid: statusValid,
                attested: r.attested,
                registrarVerified: r.attested || registrarVerifiedCreds != nil,
                registryURI: r.dataset?.registryURI,
                policyURI: r.dataset?.policyURI,
                unregisteredClaims: unregistered.map { $0.path })
        }
        return PresentationRequest(
            verifier: VerifierInfo(clientId: v.clientId, clientIdScheme: v.clientIdScheme, commonName: v.commonName,
                                   trusted: v.trusted, registration: registration),
            queries: queries, transactionData: resolved.transactionData, satisfiable: matches.isSatisfiable(),
            resolved: resolved, matches: matches)
    }

    /// Refuses a revoked/suspended RP registration cert (WRPRC) via the Token Status List, when the request
    /// carried a WRPRC (`resolved.verifier.registration`) and a registrar status client is configured. A
    /// missing WRPRC or missing status client is a no-op — interop with verifiers that don't send one yet.
    /// The RP registration cert (WRPRC) Token Status List result, surfaced (not enforced): true = valid,
    /// false = revoked/suspended (or the check failed), nil = nothing to check. The wallet shows it and the
    /// User decides — a revoked verifier does not hard-fail the presentation.
    private func checkRegistrationStatus(_ resolved: ResolvedRequest) async -> Bool? {
        guard let status = resolved.verifier.registration?.status, let client = registrarStatusClient else { return nil }
        do {
            return try await client.check(claims: .obj([("status", status)])) == .valid
        } catch {
            return false // could not confirm the status → treat as not-valid, surfaced to the User (not a hard fail)
        }
    }

    /// Consumes one instance per chosen credential (usage counting) and builds a signer-backed presentable.
    private func buildChosenHeld(_ envelopes: [CredentialEnvelope], _ selection: PresentationSelection) async throws -> [any PresentableCredential] {
        var byId: [String: CredentialEnvelope] = [:]
        for envelope in envelopes { byId[envelope.id.value] = envelope }
        var result: [any PresentableCredential] = []
        for idValue in Set(selection.chosen.values.flatMap { $0 }.map { $0.value }) {
            guard let envelope = byId[idValue] else { continue }
            guard let consumed = try await store.consumeInstance(CredentialId(idValue)) else { continue }
            if let p = presentableFor(envelope, consumed.instance) { result.append(p) }
        }
        return result
    }

    private func presentableFor(_ envelope: CredentialEnvelope, _ instance: CredentialInstance?) -> (any PresentableCredential)? {
        guard let instance else { return nil }
        guard let area = secureAreas.first(where: { $0.id == instance.key.secureArea }) else { return nil }
        do {
            switch envelope.format {
            case .sdJwtVc:
                return try HeldSdJwtVc(
                    credentialId: envelope.id.value,
                    sdJwt: try SdJwt.parse(String(decoding: instance.payload, as: UTF8.self)),
                    holderSigner: SecureAreaJwsSigner(area: area, key: instance.key, algorithm: .es256))
            case .msoMdoc:
                let key = instance.key
                var keyAgreement: MdocKeyAgreement?
                if area.capabilities.keyAgreement {
                    keyAgreement = { peer in try await area.keyAgreement(key: key, peerPublicKey: peer, hint: nil) }
                }
                return try HeldMdoc(
                    credentialId: envelope.id.value,
                    issuerSigned: try IssuerSigned.decode(instance.payload),
                    deviceSigner: SecureAreaCoseSigner(area: area, key: key, algorithm: .es256),
                    deviceKeyAgreement: keyAgreement,
                    deviceAuth: deviceAuthMode,
                    transactionDataBinder: transactionDataBinder)
            }
        } catch {
            return nil
        }
    }

    private func toVpSelection(_ selection: PresentationSelection) -> OpenID4VP.PresentationSelection {
        var chosen: [String: [String]] = [:]
        for (queryId, credentialIds) in selection.chosen { chosen[queryId] = credentialIds.map { $0.value } }
        return OpenID4VP.PresentationSelection(chosen: chosen)
    }

    private func firstInstance(_ envelope: CredentialEnvelope) -> CredentialInstance? {
        if case let .issued(_, instances) = envelope.lifecycle { return instances.first }
        return nil
    }

    private func recordSuccess(_ resolved: ResolvedRequest, _ selection: PresentationSelection, _ matches: DcqlMatchResult, _ statusValid: Bool?) async throws {
        await txlog.recordPresentation(relyingParty: relyingPartyOf(resolved, statusValid), documents: loggedDocuments(selection, matches), status: .success, transport: .remote)
    }

    private func recordDeclined(_ resolved: ResolvedRequest, _ statusValid: Bool? = nil) async throws {
        await txlog.recordPresentation(relyingParty: relyingPartyOf(resolved, statusValid), documents: [], status: .incomplete, transport: .remote)
    }

    private func recordError(_ resolved: ResolvedRequest, _ selection: PresentationSelection, _ matches: DcqlMatchResult, _ statusValid: Bool?) async throws {
        await txlog.recordPresentation(relyingParty: relyingPartyOf(resolved, statusValid), documents: loggedDocuments(selection, matches), status: .error, transport: .remote)
    }

    private func relyingPartyOf(_ resolved: ResolvedRequest, _ statusValid: Bool?) -> RelyingParty {
        let v = resolved.verifier
        let reg = v.registration
        return RelyingParty(
            id: v.clientId,
            name: v.commonName,
            trusted: v.trusted,
            certificateChainDer: v.certificateChainDer ?? [],
            clientIdScheme: v.clientIdScheme,
            subject: reg?.subject,
            entitlements: reg?.entitlements ?? [],
            purpose: reg?.purpose.map { LocalizedText(lang: $0.lang, value: $0.value) } ?? [],
            intermediaryName: reg?.intermediaryName,
            intermediarySub: reg?.intermediarySub,
            attested: reg?.attested,
            statusValid: statusValid)
    }

    private func loggedDocuments(_ selection: PresentationSelection, _ matches: DcqlMatchResult) -> [LoggedDocument] {
        selection.chosen.flatMap { queryId, credentialIds in
            credentialIds.compactMap { credentialId -> LoggedDocument? in
                guard let candidate = matches.candidatesByQuery[queryId]?.first(where: { $0.credential.credentialId == credentialId.value }) else { return nil }
                return LoggedDocument(
                    format: candidate.credential.format,
                    type: candidate.credential.vct ?? candidate.credential.docType,
                    queryId: queryId,
                    claims: candidate.disclosedPaths.map { LoggedClaim(path: $0) })
            }
        }
    }

    private func catchingVp<T>(_ block: () async throws -> T) async throws -> T {
        do {
            return try await block()
        } catch let e as TrustError {
            throw PresentationError.verifierNotTrusted(e.description)
        } catch VpError.invalidRequest(let m) {
            throw PresentationError.invalidRequest(m)
        } catch VpError.verifierNotTrusted(let m) {
            throw PresentationError.verifierNotTrusted(m)
        } catch VpError.queryNotSatisfiable(let missing) {
            throw PresentationError.queryNotSatisfiable("\(missing)")
        } catch VpError.selectionIncomplete(let m) {
            throw PresentationError.selectionIncomplete(m)
        } catch VpError.responseFailed(let m) {
            throw PresentationError.responseRejected(m)
        } catch VpError.unsupported(let m) {
            throw PresentationError.invalidRequest(m)
        }
    }
}
