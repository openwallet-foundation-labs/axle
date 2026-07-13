import Foundation
import SdJwt
import XCTest
@testable import OpenID4VP

/// ETSI TS 119 475 RPRC_21 attribute-scope check + registrar_dataset parsing.
final class RegistrationScopeTests: XCTestCase {

    private func mdocDcql(_ elements: [String]) throws -> DcqlQuery {
        let claims = elements.map { #"{"path":["org.iso.18013.5.1","\#($0)"]}"# }.joined(separator: ",")
        let json = #"{"credentials":[{"id":"q","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[\#(claims)]}]}"#
        return try DcqlQuery.parse(try JsonValue.parse(json))
    }

    private let mdlRegistered = [
        RegisteredCredential(format: "mso_mdoc", docType: "org.iso.18013.5.1.mDL", vctValues: nil,
                             claims: [["org.iso.18013.5.1", "given_name"], ["org.iso.18013.5.1", "family_name"]]),
    ]

    func testAllRequestedWithinRegistrationIsEmpty() throws {
        let dcql = try mdocDcql(["given_name", "family_name"])
        XCTAssertTrue(RegistrationScope.unregistered(dcql, registered: mdlRegistered).isEmpty)
    }

    func testOverAskingSurfacesUnregisteredClaims() throws {
        let dcql = try mdocDcql(["given_name", "birth_date", "portrait"])
        let out = RegistrationScope.unregistered(dcql, registered: mdlRegistered)
        XCTAssertEqual([["org.iso.18013.5.1", "birth_date"], ["org.iso.18013.5.1", "portrait"]], out.map { $0.path })
    }

    func testFormatMismatchIsUnregistered() throws {
        // The RP registered mdoc claims; an SD-JWT query for the same element name is not covered.
        let json = #"{"credentials":[{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}"#
        let dcql = try DcqlQuery.parse(try JsonValue.parse(json))
        let out = RegistrationScope.unregistered(dcql, registered: mdlRegistered)
        XCTAssertEqual([["given_name"]], out.map { $0.path })
    }

    func testNoRegisteredCredentialsSkipsCheck() throws {
        let dcql = try mdocDcql(["given_name"])
        XCTAssertTrue(RegistrationScope.unregistered(dcql, registered: []).isEmpty)
    }

    func testWildcardPathIsSkipped() throws {
        // mso_mdoc requires the first two path segments to be strings; a wildcard may appear deeper (indexing
        // into a structured element value). Such a path can't be pinned to a registered path, so it is skipped.
        let json = #"{"credentials":[{"id":"q","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","driving_privileges",null]}]}]}"#
        let dcql = try DcqlQuery.parse(try JsonValue.parse(json))
        XCTAssertTrue(RegistrationScope.unregistered(dcql, registered: mdlRegistered).isEmpty)
    }

    func testDatasetParsesIdentifierAndCredentials() throws {
        let json = #"{"identifier":[{"type":"LEI","identifier":"RP-1"}],"registryURI":"https://r.example/registrar","policyURI":"https://rp.example/p","intendedUseIdentifier":"iu-1","srvDescription":[{"lang":"en","content":"Svc"}],"purpose":[{"lang":"en","content":"Age"}],"credential":[{"format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claim":[{"path":["org.iso.18013.5.1","given_name"]}]}]}"#
        let ds = RegistrarDataset.fromData(try JsonValue.parse(json))
        XCTAssertEqual("RP-1", ds.identifier)
        XCTAssertEqual("https://r.example/registrar", ds.registryURI)
        XCTAssertEqual("https://rp.example/p", ds.policyURI)
        XCTAssertEqual("iu-1", ds.intendedUseIdentifier)
        XCTAssertEqual("Age", ds.purpose.first?.value)
        XCTAssertEqual(1, ds.credentials.count)
        XCTAssertEqual("org.iso.18013.5.1.mDL", ds.credentials.first?.docType)
        XCTAssertEqual([["org.iso.18013.5.1", "given_name"]], ds.credentials.first?.claims)
    }
}
