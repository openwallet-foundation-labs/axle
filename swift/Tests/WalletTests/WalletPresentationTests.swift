import CborCose
import CredentialStore
import Foundation
import SdJwt
import TransactionLog
import Wallet
import WalletAPI
import WalletTestKit
import XCTest

/// Phase C: OpenID4VP remote presentation through the facade session (resolve → consent → submit → audit).
final class WalletPresentationTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    /// DC API must not perform any HTTP — the request/response are handed over by the platform.
    private struct NoHttp: HttpTransport {
        func execute(_ request: HttpRequest) async throws -> HttpResponse { HttpResponse(status: 404, headers: [], body: []) }
    }

    /// Seeds a holder-bound PID SD-JWT VC and returns the issuer public key (for the verifier).
    private func seedPid(_ area: SoftwareSecureArea, _ storage: InMemoryStorageDriver) async throws -> EcPublicKey {
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let holderKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        var n = 0
        let salts: () -> String = { n += 1; return "salt-\(n)" }
        let pid = try await SdJwtIssuer(saltProvider: salts).issue(
            signer: SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256),
            holderKey: holderKey.publicKey
        ) { b in
            b.claim("iss", "https://issuer.example")
            b.claim("vct", "urn:eudi:pid:1")
            b.sd("family_name", "Han")
            b.sd("given_name", "Jongho")
            b.sd("birthdate", "1990-05-15")
        }
        try await DefaultCredentialStore(driver: storage).save(CredentialEnvelope(
            id: CredentialId("pid-1"), format: .sdJwtVc(vct: "urn:eudi:pid:1"), createdAt: now,
            lifecycle: .issued(policy: CredentialPolicy(), instances: [CredentialInstance(key: holderKey.handle, payload: [UInt8](pid.serialize().utf8))])))
        return issuerKey.publicKey
    }

    func testRemotePresentationDisclosesOnlyRequestedClaims() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerPublic = try await seedPid(area, storage)
        let verifier = MockVerifier(issuerPublic: issuerPublic)
        let logStore = InMemoryTransactionLogStore()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier, transactionLogStore: logStore))

        let session = wallet.presentation.start(await verifier.requestUri("direct_post"))
        var captured: PresentationRequest?
        var terminal: PresentationState?
        for await state in session.states {
            if case let .requestResolved(request) = state {
                captured = request
                session.respond(PresentationSelection.auto(request))
            }
            if state.isTerminal { terminal = state; break }
        }
        XCTAssertEqual(true, captured?.satisfiable)
        XCTAssertEqual("verifier.example", captured?.verifier.clientId)
        guard case .completed = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }

        // verifier received only the requested claims, holder+nonce bound
        let claims = await verifier.verifiedClaims!
        if case let .str(fn)? = claims["family_name"] { XCTAssertEqual("Han", fn) } else { XCTFail("family_name") }
        if case let .str(gn)? = claims["given_name"] { XCTAssertEqual("Jongho", gn) } else { XCTFail("given_name") }
        XCTAssertNil(claims["birthdate"], "unrequested claim must not be disclosed")

        let entries = await logStore.all()
        XCTAssertEqual(1, entries.count)
        XCTAssertEqual(.success, entries[0].status)
        XCTAssertEqual("verifier.example", entries[0].relyingParty?.id)
        XCTAssertEqual(false, entries[0].relyingParty?.trusted) // unsigned request → not cryptographically trusted
        XCTAssertTrue(entries[0].documents.contains { $0.type == "urn:eudi:pid:1" })
        let loggedPaths = entries[0].documents.flatMap { $0.claims.map { $0.path } }
        XCTAssertTrue(loggedPaths.contains(["family_name"]) && loggedPaths.contains(["given_name"]))
        wallet.close()
    }

    func testDeclineTerminatesAndRecordsAudit() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerPublic = try await seedPid(area, storage)
        let verifier = MockVerifier(issuerPublic: issuerPublic)
        let logStore = InMemoryTransactionLogStore()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier, transactionLogStore: logStore))

        let session = wallet.presentation.start(await verifier.requestUri("direct_post"))
        var terminal: PresentationState?
        for await state in session.states {
            if case .requestResolved = state { session.decline() }
            if state.isTerminal { terminal = state; break }
        }
        guard case let .declined(redirectUri) = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }

        let claims = await verifier.verifiedClaims
        XCTAssertNil(claims, "nothing presented on decline")
        // §8.5: the verifier is told the user refused, and the wallet surfaces its redirect_uri.
        let error = await verifier.errorResponse
        XCTAssertEqual("access_denied", error?.error)
        XCTAssertEqual("xyz", error?.state)
        XCTAssertEqual("https://verifier.example/done", redirectUri)
        let entries = await logStore.all()
        XCTAssertEqual(.incomplete, entries[0].status)
        wallet.close()
    }

    /// OpenID4VP §8.3: the wallet encrypts to a `client_metadata.jwks` key whose `alg` it matches, and
    /// repeats that key's `kid` in the JWE header so the verifier knows which private key to use.
    /// ISO 18013-7 B.5.3 additionally binds the request `nonce` into `apv`; `apu` would carry the
    /// `mdocGeneratedNonce` of the superseded B.4.4 handover, so it is absent.
    func testEncryptedResponseEchoesKidAndBindsNonceInApv() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerPublic = try await seedPid(area, storage)
        let verifier = MockVerifier(issuerPublic: issuerPublic)
        let wallet = Wallet.create(config: WalletConfig(),
                                   ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier))

        let session = wallet.presentation.start(await verifier.requestUri("direct_post.jwt"))
        var terminal: PresentationState?
        for await state in session.states {
            if case let .requestResolved(request) = state { session.respond(.auto(request)) }
            if state.isTerminal { terminal = state; break }
        }
        guard case .completed = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }

        let claims = await verifier.verifiedClaims
        XCTAssertNotNil(claims, "the verifier decrypted and verified the response")
        let kid = await verifier.seenJweKid
        let apv = await verifier.seenJweApv
        let nonce = await verifier.nonce
        XCTAssertEqual(MockVerifier.encKid, kid)
        XCTAssertEqual(nonce, apv)
        wallet.close()
    }

    /// DC API has no response_uri: the refusal goes back to the platform, never to a verifier endpoint (§15.9.2).
    func testDeclineOverDcApiReportsNothing() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerPublic = try await seedPid(area, storage)
        let verifier = MockVerifier(issuerPublic: issuerPublic)
        let wallet = Wallet.create(config: WalletConfig(),
                                   ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier))

        let session = wallet.presentation.startDcApi(await verifier.dcApiRequestObject(), origin: "https://verifier.example")
        var terminal: PresentationState?
        for await state in session.states {
            if case .requestResolved = state { session.decline() }
            if state.isTerminal { terminal = state; break }
        }
        guard case let .declined(redirectUri) = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }

        XCTAssertNil(redirectUri)
        let error = await verifier.errorResponse
        XCTAssertNil(error, "no error may be POSTed over the DC API")
        wallet.close()
    }

    func testMdocRemotePresentationSignsDeviceResponse() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let bytes = try await MdocTestIssuer.issue(
            area: area, issuerKey: issuerKey, deviceKey: deviceKey.publicKey,
            docType: "org.iso.18013.5.1.mDL", namespace: "org.iso.18013.5.1",
            elements: [("family_name", .text("Kim")), ("given_name", .text("Minsu")), ("age_over_18", .bool(true))],
            x5chain: [[0x30, 0x01]],
            signed: now, validFrom: now, validUntil: now.addingTimeInterval(31_536_000))
        try await DefaultCredentialStore(driver: storage).save(CredentialEnvelope(
            id: CredentialId("mdl-1"), format: .msoMdoc(docType: "org.iso.18013.5.1.mDL"), createdAt: now,
            lifecycle: .issued(policy: CredentialPolicy(), instances: [CredentialInstance(key: deviceKey.handle, payload: bytes)])))

        let verifier = MockMdocVerifier()
        let logStore = InMemoryTransactionLogStore()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier, transactionLogStore: logStore))

        let session = wallet.presentation.start(await verifier.requestUri())
        var terminal: PresentationState?
        for await state in session.states {
            if case let .requestResolved(request) = state { session.respond(PresentationSelection.auto(request)) }
            if state.isTerminal { terminal = state; break }
        }
        guard case .completed = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }

        // verifier verified the device signature and got only the requested elements (age_over_18 withheld)
        let disclosed = await verifier.disclosedElements
        XCTAssertEqual(Set(["family_name", "given_name"]), disclosed)
        let entries = await logStore.all()
        XCTAssertEqual(.success, entries[0].status)
        XCTAssertTrue(entries[0].documents.contains { $0.type == "org.iso.18013.5.1.mDL" })
        wallet.close()
    }

    func testDigitalCredentialsApiPresentationBindsOrigin() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let bytes = try await MdocTestIssuer.issue(
            area: area, issuerKey: issuerKey, deviceKey: deviceKey.publicKey,
            docType: "org.iso.18013.5.1.mDL", namespace: "org.iso.18013.5.1",
            elements: [("family_name", .text("Kim")), ("given_name", .text("Minsu")), ("age_over_18", .bool(true))],
            x5chain: [[0x30, 0x01]],
            signed: now, validFrom: now, validUntil: now.addingTimeInterval(31_536_000))
        try await DefaultCredentialStore(driver: storage).save(CredentialEnvelope(
            id: CredentialId("mdl-1"), format: .msoMdoc(docType: "org.iso.18013.5.1.mDL"), createdAt: now,
            lifecycle: .issued(policy: CredentialPolicy(), instances: [CredentialInstance(key: deviceKey.handle, payload: bytes)])))

        let verifier = MockDcApiVerifier()
        let logStore = InMemoryTransactionLogStore()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: NoHttp(), transactionLogStore: logStore))

        let session = wallet.presentation.startDcApi(verifier.requestObject(), origin: verifier.origin)
        var terminal: PresentationState?
        for await state in session.states {
            if case let .requestResolved(request) = state { session.respond(PresentationSelection.auto(request)) }
            if state.isTerminal { terminal = state; break }
        }
        guard case let .completed(redirectUri, dcApiResponse) = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }
        XCTAssertNil(redirectUri, "DC API has no redirect")
        let response = try XCTUnwrap(dcApiResponse)

        // response is origin-bound and selectively disclosed
        XCTAssertEqual(Set(["family_name", "given_name"]), try verifier.verify(response))
        let entries = await logStore.all()
        XCTAssertEqual(.success, entries[0].status)
        wallet.close()
    }

    func testFailedSubmissionRecordsErrorWhenEnabled() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerPublic = try await seedPid(area, storage)
        let verifier = MockVerifier(issuerPublic: issuerPublic)
        await verifier.setRejectResponse(true)
        let logStore = InMemoryTransactionLogStore()
        let wallet = Wallet.create(
            config: WalletConfig(transactionLog: TransactionLogConfig(recordFailures: true)),
            ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier, transactionLogStore: logStore))

        let session = wallet.presentation.start(await verifier.requestUri("direct_post"))
        var terminal: PresentationState?
        for await state in session.states {
            if case let .requestResolved(request) = state { session.respond(PresentationSelection.auto(request)) }
            if state.isTerminal { terminal = state; break }
        }
        guard case .failed = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }

        // the failed final submission is recorded with .error + the attempted disclosure
        let entries = await logStore.all()
        XCTAssertEqual(1, entries.count)
        XCTAssertEqual(.error, entries[0].status)
        XCTAssertEqual("verifier.example", entries[0].relyingParty?.id)
        XCTAssertTrue(entries[0].documents.contains { $0.type == "urn:eudi:pid:1" })
        wallet.close()
    }

    func testFailedSubmissionNotRecordedByDefault() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerPublic = try await seedPid(area, storage)
        let verifier = MockVerifier(issuerPublic: issuerPublic)
        await verifier.setRejectResponse(true)
        let logStore = InMemoryTransactionLogStore()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier, transactionLogStore: logStore))

        let session = wallet.presentation.start(await verifier.requestUri("direct_post"))
        var terminal: PresentationState?
        for await state in session.states {
            if case let .requestResolved(request) = state { session.respond(PresentationSelection.auto(request)) }
            if state.isTerminal { terminal = state; break }
        }
        guard case .failed = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }

        // default config → failures are NOT recorded
        let entries = await logStore.all()
        XCTAssertTrue(entries.isEmpty, "no transaction recorded by default")
        wallet.close()
    }
}
