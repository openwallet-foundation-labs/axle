import XCTest
@testable import OpenID4VCI

/// OpenID4VCI §4.1.1 transaction-code input hints. `TxCodeSpec.violations` is advisory only — it reports
/// how a code departs from the offer's hints so a wallet can warn, but never blocks issuance (a hint can
/// be wrong; the Authorization Server is the authority on the code).
final class TxCodeSpecTests: XCTestCase {

    private func spec(length: Int? = nil, inputMode: String? = nil) -> CredentialOffer.TxCodeSpec {
        CredentialOffer.TxCodeSpec(length: length, inputMode: inputMode, description: nil)
    }

    func testAMatchingNumericCodeHasNoViolations() {
        XCTAssertTrue(spec(length: 5, inputMode: "numeric").violations("12345").isEmpty)
    }

    func testNumericIsTheDefaultInputMode() {
        // §4.1.1: "The default is numeric." — non-digits are flagged even when input_mode is absent.
        XCTAssertTrue(spec().violations("abc").contains { $0.contains("digits") })
        XCTAssertTrue(spec().violations("123").isEmpty)
    }

    func testNonDigitsViolateNumeric() {
        let v = spec(inputMode: "numeric").violations("12a45")
        XCTAssertEqual(1, v.count)
        XCTAssertTrue(v[0].contains("digits"))
    }

    func testTextInputModeAcceptsAnyCharacters() {
        XCTAssertTrue(spec(inputMode: "text").violations("a-b C!").isEmpty)
    }

    func testWrongLengthIsFlagged() {
        let v = spec(length: 6).violations("123")
        XCTAssertTrue(v.contains { $0.contains("6 characters") && $0.contains("got 3") }, "\(v)")
    }

    func testReportsBothMismatchesAtOnce() {
        // wrong charset AND wrong length — a wallet can show every problem in one pass.
        let v = spec(length: 4, inputMode: "numeric").violations("ab")
        XCTAssertEqual(2, v.count, "\(v)")
    }
}
