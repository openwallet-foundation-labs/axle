import CborCose
import CredentialStore
import Foundation
import SdJwt
import Wallet
import WalletAPI
import WalletTestKit
import XCTest

/// Phase C: OpenID4VP remote presentation through the facade session (resolve → consent → submit → audit).
final class WalletPresentationTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private actor RecordingLog: TransactionLog {
        private(set) var entries: [TransactionLogEntry] = []
        func record(_ entry: TransactionLogEntry) async throws { entries.append(entry) }
        func list() async throws -> [TransactionLogEntry] { entries }
    }

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
        let log = RecordingLog()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier, transactionLog: log))

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

        let entries = await log.entries
        XCTAssertEqual(1, entries.count)
        XCTAssertEqual(.success, entries[0].status)
        XCTAssertTrue(entries[0].credentialIds.contains("pid-1"))
        XCTAssertTrue(Set(entries[0].claimsDisclosed).isSuperset(of: ["family_name", "given_name"]))
        wallet.close()
    }

    func testDeclineTerminatesAndRecordsAudit() async throws {
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerPublic = try await seedPid(area, storage)
        let verifier = MockVerifier(issuerPublic: issuerPublic)
        let log = RecordingLog()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier, transactionLog: log))

        let session = wallet.presentation.start(await verifier.requestUri("direct_post"))
        var terminal: PresentationState?
        for await state in session.states {
            if case .requestResolved = state { session.decline() }
            if state.isTerminal { terminal = state; break }
        }
        guard case .declined = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }

        let claims = await verifier.verifiedClaims
        XCTAssertNil(claims, "nothing presented on decline")
        let entries = await log.entries
        XCTAssertEqual(.declined, entries[0].status)
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
        let log = RecordingLog()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: verifier, transactionLog: log))

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
        let entries = await log.entries
        XCTAssertEqual(.success, entries[0].status)
        XCTAssertTrue(entries[0].credentialIds.contains("mdl-1"))
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
        let log = RecordingLog()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: NoHttp(), transactionLog: log))

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
        let entries = await log.entries
        XCTAssertEqual(.success, entries[0].status)
        wallet.close()
    }
}
