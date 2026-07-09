import Foundation
import Wallet
import WalletAPI
import WalletTestKit
import XCTest

/// Phase B: OpenID4VCI issuance through the facade session — all grants + follow-ups.
final class WalletIssuanceTests: XCTestCase {

    private func makeWallet() async throws -> (Wallet, MockIssuer, SoftwareSecureArea) {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: 1_700_000_000)
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: InMemoryStorageDriver(), http: mock))
        return (wallet, mock, area)
    }

    /// Drives the session to a terminal state, handling browser/tx-code interruptions.
    private func drive(_ session: IssuanceSession, mock: MockIssuer? = nil, txCode: String? = nil) async -> IssuanceState {
        for await state in session.states {
            switch state {
            case let .authorizationRequired(url):
                if let mock,
                   let redirect = try? await mock.execute(HttpRequest(method: .get, url: url)),
                   let location = redirect.headers.first(where: { $0.0 == "Location" })?.1 {
                    session.completeAuthorization(location)
                }
            case .txCodeRequired:
                if let txCode { session.submitTxCode(txCode) }
            default:
                break
            }
            if state.isTerminal { return state }
        }
        return session.currentState
    }

    /// §4.1.1: the input hints reach the host through `.txCodeRequired` so it can render + warn
    /// (advisory, never blocking).
    func testTxCodeHintsReachTheHost() async throws {
        let (wallet, mock, _) = try await makeWallet()
        let offer = try await wallet.issuance.resolveOffer(mock.credentialOfferJson)

        // No txCode in the request → the session pauses and surfaces the hints.
        let session = wallet.issuance.start(.fromOffer(offer, configurationId: "eu.europa.ec.eudi.pid.1"))
        var spec: TxCodeSpec??
        for await state in session.states {
            if case let .txCodeRequired(s) = state {
                spec = .some(s)
                session.submitTxCode("1234")
            }
            if state.isTerminal { break }
        }

        let hints = try XCTUnwrap(spec ?? nil, "TxCodeRequired must carry the spec")
        XCTAssertEqual(4, hints.length)
        XCTAssertEqual("numeric", hints.inputMode)
        XCTAssertTrue(hints.validate("12").contains { $0.contains("4 characters") }, "short code warns")
        XCTAssertTrue(hints.validate("abcd").contains { $0.contains("digits") }, "non-numeric warns")
        XCTAssertTrue(hints.validate("1234").isEmpty, "a conformant code is clean")
    }

    func testPreAuthorizedIssuanceStoresCredential() async throws {
        let (wallet, mock, _) = try await makeWallet()
        let offer = try await wallet.issuance.resolveOffer(mock.credentialOfferJson)
        XCTAssertTrue(offer.requiresTxCode)

        let session = wallet.issuance.start(.fromOffer(offer, configurationId: "eu.europa.ec.eudi.pid.1", txCode: "1234", policy: CredentialPolicy(batchSize: 2, use: .oneTime)))
        guard case let .completed(result) = await drive(session) else { return XCTFail("not completed") }
        XCTAssertEqual(1, result.issued.count)

        let creds = try await wallet.credentials.list()
        XCTAssertEqual(1, creds.count)
        let credential = creds[0]
        guard case let .issued(claims, _, instances) = credential.lifecycle else { return XCTFail("not issued") }
        XCTAssertEqual(2, instances.remaining)
        XCTAssertTrue(claims.contains { $0.path == ["given_name"] && $0.value.display() == "John" })
        // metadata captured
        XCTAssertEqual("Hopae Test Issuer", credential.issuer?.displayName)
        XCTAssertEqual("Personal ID", credential.display?.name)
        XCTAssertEqual("eu.europa.ec.eudi.pid.1", credential.configurationId)
        wallet.close()
    }

    func testAuthorizationCodeWithBrowserStep() async throws {
        let (wallet, mock, _) = try await makeWallet()
        let session = wallet.issuance.start(.fromIssuer("https://issuer.example", configurationId: "eu.europa.ec.eudi.pid.1"))
        guard case .completed = await drive(session, mock: mock) else { return XCTFail("auth-code not completed") }
        let count = try await wallet.credentials.list().count
        XCTAssertEqual(1, count)
        wallet.close()
    }

    func testTxCodeSuppliedInteractively() async throws {
        let (wallet, mock, _) = try await makeWallet()
        let offer = try await wallet.issuance.resolveOffer(mock.credentialOfferJson)
        let session = wallet.issuance.start(.fromOffer(offer, configurationId: "eu.europa.ec.eudi.pid.1"))
        guard case .completed = await drive(session, txCode: "1234") else { return XCTFail("txCode not completed") }
        wallet.close()
    }

    private struct FixedClock: WalletClock {
        let instant: Date
        func now() -> Date { instant }
    }

    /// OpenID4VCI §9.2 deferred issuance: an unready issuer defers (HTTP 202 + interval + transaction_id).
    /// The wallet reports .deferred with the retry instant — not a failure — and resuming after a still-
    /// deferred response reports .deferred again, until the credential is finally issued.
    func testDeferredIssuanceReportsDeferredUntilReady() async throws {
        let epoch: TimeInterval = 1_700_000_000
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: Int64(epoch))
        await mock.setDeferMode(true)
        let wallet = Wallet.create(config: WalletConfig(),
                                   ports: WalletPorts(secureAreas: [area], storage: InMemoryStorageDriver(), http: mock,
                                                      clock: FixedClock(instant: Date(timeIntervalSince1970: epoch))))
        let offer = try await wallet.issuance.resolveOffer(mock.credentialOfferJson)

        // start: the issuer defers immediately (interval 300 → retryAfter = now + 300s), not .completed.
        guard case let .deferred(id, retryAfter) = await drive(wallet.issuance.start(.fromOffer(offer, configurationId: "eu.europa.ec.eudi.pid.1", txCode: "1234"))) else {
            return XCTFail("expected deferred")
        }
        XCTAssertEqual(Date(timeIntervalSince1970: epoch + 300), retryAfter)
        if case .deferred = try await wallet.credentials.get(id)!.lifecycle {} else { XCTFail("credential is deferred") }

        // first poll: still deferred (interval 42 → fresh retryAfter), still .deferred not .failed.
        guard case let .deferred(_, retry1) = await drive(wallet.issuance.resumeDeferred(id)) else { return XCTFail("expected deferred") }
        XCTAssertEqual(Date(timeIntervalSince1970: epoch + 42), retry1)

        // second poll: ready
        guard case .completed = await drive(wallet.issuance.resumeDeferred(id)) else { return XCTFail("expected completed") }
        if case .issued = try await wallet.credentials.get(id)!.lifecycle {} else { XCTFail("credential now issued") }
        wallet.close()
    }

    func testReissueRenewsCredential() async throws {
        let (wallet, mock, _) = try await makeWallet()
        let offer = try await wallet.issuance.resolveOffer(mock.credentialOfferJson)
        guard case let .completed(r) = await drive(wallet.issuance.start(.fromOffer(offer, configurationId: "eu.europa.ec.eudi.pid.1", txCode: "1234"))) else { return XCTFail() }
        let id = r.issued[0]

        guard case let .completed(r2) = await drive(wallet.issuance.reissue(id)) else { return XCTFail("reissue not completed") }
        XCTAssertEqual(id, r2.issued[0])
        let count = try await wallet.credentials.list().count
        XCTAssertEqual(1, count)
        wallet.close()
    }

    func testIssuanceNotifiesIssuer() async throws {
        let (wallet, mock, _) = try await makeWallet()
        let offer = try await wallet.issuance.resolveOffer(mock.credentialOfferJson)
        _ = await drive(wallet.issuance.start(.fromOffer(offer, configurationId: "eu.europa.ec.eudi.pid.1", txCode: "1234")))
        let seen = await mock.seenNotification
        XCTAssertEqual("n-1", seen?.0)
        XCTAssertEqual("credential_accepted", seen?.1)
        wallet.close()
    }
}
