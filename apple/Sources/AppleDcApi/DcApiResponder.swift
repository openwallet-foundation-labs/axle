import Foundation
import MDoc
import Wallet

/// Turns Apple's `IdentityDocumentWebPresentmentRawRequest` (its `requestData` JSON + the calling web origin) into
/// the raw CBOR `DeviceResponse` bytes for `ISO18013MobileDocumentResponse(responseData:)`.
///
/// The cryptography — mdoc `DeviceResponse` build, HPKE seal to the verifier's key, ISO/IEC 18013-7:2025 Annex C
/// SessionTranscript — is the SDK's `proximity.respondDcApiMdoc`; the flow matches android's `GetCredentialActivity`
/// mdoc branch (resolve → respond). Around it this marshals Apple's wire shapes (base64url-JSON in, raw `Data` out),
/// normalizes the origin, and runs one iOS-only check Apple recommends: **consistency** — the raw request we are
/// about to sign may not ask for anything the OS did not show the user. (Android needs no equivalent: its DC API
/// hands the app a single request object, so the displayed and signed requests can't diverge.)
public enum DcApiResponder {
    public enum Failure: Error, CustomStringConvertible {
        case missingOrigin
        case malformedRequest
        case inconsistentRequest(String)
        case responseEncoding
        public var description: String {
            switch self {
            case .missingOrigin: return "the web presentment request had no requesting origin"
            case .malformedRequest: return "request data was not the expected {deviceRequest, encryptionInfo} JSON"
            case let .inconsistentRequest(what): return "the request asked for something the consent screen did not show (\(what))"
            case .responseEncoding: return "the DeviceResponse was not valid base64url"
            }
        }
    }

    private struct RawRequest: Decodable { let deviceRequest: String; let encryptionInfo: String }

    /// Builds the encrypted `org-iso-mdoc` DeviceResponse for a raw web-presentment request. `wallet` must be built
    /// from the shared Secure Enclave + keychain group so it can read the app's credentials and sign with their
    /// device keys. `shown` is what the consent screen displayed (docType → namespace → element identifiers); the
    /// raw request may ask for a subset, never a superset — otherwise we refuse rather than sign undisclosed data.
    public static func responseData(
        rawRequestData: Data,
        origin: URL?,
        wallet: Wallet,
        shown: [String: [String: Set<String>]]
    ) async throws -> Data {
        guard let origin else { throw Failure.missingOrigin }
        guard let req = try? JSONDecoder().decode(RawRequest.self, from: rawRequestData) else { throw Failure.malformedRequest }

        // Consistency: decode the exact bytes we are about to sign and confirm every requested element was shown.
        if let bytes = dataFromBase64Url(req.deviceRequest).map([UInt8].init), let deviceRequest = try? DeviceRequest.decode(bytes) {
            try validateConsistency(deviceRequest, shown: shown)
        }

        let base64url = try await wallet.proximity.respondDcApiMdoc(
            deviceRequestBase64: req.deviceRequest,
            encryptionInfoBase64: req.encryptionInfo,
            origin: normalizedOrigin(origin))
        guard let data = dataFromBase64Url(base64url) else { throw Failure.responseEncoding }
        return data
    }

    /// Every requested (docType, namespace, element) must have been shown to the user. Apple's reference leaves this
    /// as an empty stub (`// proposed function in the wwdc video, to be implemented`); we actually check it.
    private static func validateConsistency(_ deviceRequest: DeviceRequest, shown: [String: [String: Set<String>]]) throws {
        for dr in deviceRequest.docRequests {
            guard let shownNamespaces = shown[dr.docType] else {
                throw Failure.inconsistentRequest("document \(dr.docType) was not shown")
            }
            for (namespace, elements) in dr.requested {
                let shownElements = shownNamespaces[namespace] ?? []
                for element in elements where !shownElements.contains(element.identifier) {
                    throw Failure.inconsistentRequest("\(dr.docType)/\(namespace)/\(element.identifier)")
                }
            }
        }
    }

    /// The verifier hashes the *exact* origin string into the SessionTranscript; Apple's `URL.absoluteString` can
    /// carry a trailing `/` the web origin does not, which would silently change the hash and fail verification.
    static func normalizedOrigin(_ url: URL) -> String {
        var s = url.absoluteString
        while s.hasSuffix("/") { s.removeLast() }
        return s
    }

    static func dataFromBase64Url(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t.append("=") }
        return Data(base64Encoded: t)
    }
}
