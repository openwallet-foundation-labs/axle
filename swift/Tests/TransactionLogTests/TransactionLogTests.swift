import XCTest
@testable import TransactionLog

final class TransactionLogTests: XCTestCase {

    private func makeLog(store: any TransactionLogStore, start: Int64 = 1_000) -> TransactionLog {
        let id = Counter()
        let now = Counter(start)
        return TransactionLog(store: store, idGenerator: { "tx-\(id.next())" }, clock: { now.next() })
    }

    private final class Counter: @unchecked Sendable {
        private var v: Int64
        init(_ start: Int64 = 0) { v = start }
        func next() -> Int64 { defer { v += 1 }; return v }
    }

    private let pidDoc = LoggedDocument(
        format: "dc+sd-jwt", type: "urn:eudi:pid:1", queryId: "query_0",
        claims: [LoggedClaim(path: ["family_name"], value: "Han"), LoggedClaim(path: ["given_name"], value: "Jongho")]
    )

    func testRecordsAndReturnsHistoryNewestFirst() async {
        let log = makeLog(store: InMemoryTransactionLogStore())
        await log.recordIssuance(issuer: "https://issuer.eudiw.dev", documents: [pidDoc])
        await log.recordPresentation(relyingParty: RelyingParty(id: "verifier.eudiw.dev", name: "EUDI Remote Verifier", trusted: true), documents: [pidDoc])

        let history = await log.history()
        XCTAssertEqual(2, history.count)
        XCTAssertEqual(.presentation, history[0].type) // newest first
        XCTAssertEqual(.issuance, history[1].type)
        XCTAssertEqual("EUDI Remote Verifier", history[0].relyingParty?.name)
        XCTAssertEqual(true, history[0].relyingParty?.trusted)
    }

    func testQueriesByTypeAndRelyingPartyAndWindow() async {
        let log = makeLog(store: InMemoryTransactionLogStore(), start: 100)
        await log.recordPresentation(relyingParty: RelyingParty(id: "rp-a"), documents: [pidDoc]) // ts 100
        await log.recordPresentation(relyingParty: RelyingParty(id: "rp-b"), documents: [pidDoc]) // ts 101
        await log.recordIssuance(issuer: "iss", documents: [pidDoc])                              // ts 102

        let byType = await log.query(type: .presentation)
        let byRp = await log.query(relyingPartyId: "rp-b")
        let since = await log.query(since: 101)
        let untilPres = await log.query(type: .presentation, until: 100)
        XCTAssertEqual(2, byType.count)
        XCTAssertEqual("rp-b", byRp.first?.relyingParty?.id)
        XCTAssertEqual(2, since.count)
        XCTAssertEqual(1, untilPres.count)
    }

    func testJsonRoundTripPreservesFields() throws {
        let entry = TransactionLogEntry(
            id: "tx-1", timestamp: 1_700_000_000, type: .presentation, status: .success,
            relyingParty: RelyingParty(id: "verifier.eudiw.dev", name: "EUDI Remote Verifier", trusted: true, certificateChainDer: [[0x30, 0x01, 0x02]]),
            documents: [pidDoc], rawRequest: [1, 2, 3], rawResponse: [4, 5]
        )
        let decoded = try TransactionLogCodec.decode(TransactionLogCodec.encode(entry))

        XCTAssertEqual("tx-1", decoded.id)
        XCTAssertEqual(1_700_000_000, decoded.timestamp)
        XCTAssertEqual(.presentation, decoded.type)
        XCTAssertEqual(.success, decoded.status)
        XCTAssertEqual("EUDI Remote Verifier", decoded.relyingParty?.name)
        XCTAssertEqual(true, decoded.relyingParty?.trusted)
        XCTAssertEqual([0x30, 0x01, 0x02], decoded.relyingParty?.certificateChainDer.first)
        XCTAssertEqual("urn:eudi:pid:1", decoded.documents.first?.type)
        XCTAssertEqual(["family_name"], decoded.documents.first?.claims.first?.path)
        XCTAssertEqual("Han", decoded.documents.first?.claims.first?.value)
        XCTAssertEqual([1, 2, 3], decoded.rawRequest)
        XCTAssertEqual([4, 5], decoded.rawResponse)
    }

    func testIssuanceEntryOmitsRelyingParty() async throws {
        let log = makeLog(store: InMemoryTransactionLogStore())
        let entry = await log.recordIssuance(issuer: "iss", documents: [pidDoc])
        let decoded = try TransactionLogCodec.decode(TransactionLogCodec.encode(entry))
        XCTAssertEqual(.issuance, decoded.type)
        XCTAssertEqual("iss", decoded.issuer)
        XCTAssertNil(decoded.relyingParty)
    }
}
