import Foundation
import OpenID4VP
import SdJwt
import WalletAPI

public struct RegistrarApiError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// Client for the Registrar's TS5 *RP registration* API (EUDI Wallet TS5), used on the **dataset-only**
/// presentation path (wrprc.md §5): when the request carries a self-declared `registrar_dataset` but no
/// registrar-sealed WRPRC, and the User has opted in (RPRC_16), the wallet fetches the same information
/// *registrar-signed* to confirm what the RP is registered to request (RPRC_18).
///
/// Responses are `application/jwt` — a JWS with `typ` `wrp-registry+jwt` whose `x5c` chains to the registrar
/// CA; the signature is verified through the same `IssuerKeyResolver` the status-list client uses.
public struct RegistrarApiClient {
    private let http: any HttpTransport
    private let keyResolver: any IssuerKeyResolver

    public init(http: any HttpTransport, keyResolver: any IssuerKeyResolver) {
        self.http = http
        self.keyResolver = keyResolver
    }

    /// Fetches `GET {registryURI}/wrp/{identifier}` (the RP record), verifies the JWS against the registrar
    /// CA, and returns the credentials/claims the RP is registered to request for the given intended use —
    /// the authoritative input to the attribute-scope check (RPRC_21). Throws on fetch/verify failure.
    public func fetchRegisteredCredentials(registryURI: String, identifier: String,
                                           intendedUseIdentifier: String?) async throws -> [RegisteredCredential] {
        let base = registryURI.hasSuffix("/") ? String(registryURI.dropLast()) : registryURI
        let encoded = identifier.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? identifier
        let url = "\(base)/wrp/\(encoded)"
        let resp = try await http.execute(HttpRequest(method: .get, url: url, headers: [("Accept", "application/jwt")], body: nil))
        guard (200...299).contains(resp.status) else { throw RegistrarApiError("registry fetch failed: HTTP \(resp.status)") }

        let jws = try Jws.parse(String(decoding: resp.body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        if case let .str(typ)? = jws.header["typ"], typ != "wrp-registry+jwt" {
            throw RegistrarApiError("unexpected registry token typ '\(typ)'")
        }
        guard let payload = try? JsonValue.parse(String(decoding: jws.payloadBytes, as: UTF8.self)) else {
            throw RegistrarApiError("registry token payload must be JSON")
        }
        let iss: String = { if case let .str(s)? = payload["iss"] { return s }; return registryURI }()
        let key = try await keyResolver.resolve(iss: iss, header: jws.header) // verifies x5c to the registrar CA
        guard jws.verify(key: key.publicKey, expected: key.algorithm) else {
            throw RegistrarApiError("registry token signature invalid")
        }

        // Pick the intended-use matching the dataset's identifier (else the first) and read its credentials.
        var intendedUses: [JsonValue] = []
        if case let .arr(items)? = payload["intendedUse"] { intendedUses = items }
        let iu: JsonValue? = {
            if let id = intendedUseIdentifier,
               let match = intendedUses.first(where: {
                   if case let .str(v)? = $0["intendedUseIdentifier"] { return v == id } else { return false }
               }) {
                return match
            }
            return intendedUses.first
        }()
        return RegisteredCredential.listFromJson(iu?["credential"])
    }
}
