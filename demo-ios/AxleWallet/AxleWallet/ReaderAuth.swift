import CborCose
import CryptoKit
import Foundation
import MDoc

/// The demo's ISO 18013-5 reader-auth identity for the Read-mDL role — the iOS counterpart of android
/// `DemoWallet.loadReaderAuth`. Loaded from a gitignored `reader_wrpac.json` bundle asset
/// (`{privateKeyPem, certPem, caCertPem}` — the verifier's WRPAC, which chains to the registrar CA that holders
/// trust as a reader anchor). When present, the Read-mDL role signs its requests with reader authentication so the
/// other wallet can show us as a verified reader; absent asset → `nil` (reads are unauthenticated), exactly as on
/// android. Drop your `reader_wrpac.json` next to `Info.plist` (it is gitignored) to enable it.
enum ReaderAuthLoader {
    static func load() -> ReaderAuthSigner? {
        guard let url = Bundle.main.url(forResource: "reader_wrpac", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: String],
              let privateKeyPem = obj["privateKeyPem"], let certPem = obj["certPem"], let caCertPem = obj["caCertPem"]
        else {
            LogStore.shared.log("Reader-auth identity not configured (reader_wrpac.json absent) — reads are unauthenticated")
            return nil
        }
        do {
            let x5c = [try pemToDer(certPem), try pemToDer(caCertPem)]
            let signer = try ReaderAuthSigner(signer: PemEcCoseSigner(privateKeyPem: privateKeyPem), x5chain: x5c)
            LogStore.shared.log("Reader-auth identity loaded — Read mDL signs its requests")
            return signer
        } catch {
            LogStore.shared.log("❌ Reader-auth load failed: \(error)")
            return nil
        }
    }

    private static func pemToDer(_ pem: String) throws -> [UInt8] {
        let base64 = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .components(separatedBy: .whitespacesAndNewlines).joined()
        guard let data = Data(base64Encoded: base64) else { throw ReaderAuthError.badCertPem }
        return [UInt8](data)
    }

    enum ReaderAuthError: Error { case badCertPem }
}

/// COSE ES256 signer over an embedded EC private key (PKCS#8 or SEC1 PEM) — the demo reader's WRPAC key, the iOS
/// counterpart of android `PemEcCoseSigner`. Stores only the 32-byte private scalar (so the signer stays
/// `Sendable`) and reconstructs the CryptoKit key per signature. `signature(for:)` hashes with SHA-256 internally
/// and `rawRepresentation` is the COSE `r || s` form.
struct PemEcCoseSigner: CoseSigner {
    let algorithm: CoseAlgorithm = .es256
    private let scalar: Data

    init(privateKeyPem: String) throws {
        scalar = try P256.Signing.PrivateKey(pemRepresentation: privateKeyPem).rawRepresentation
    }

    func sign(_ toBeSigned: [UInt8]) async throws -> [UInt8] {
        let key = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        return [UInt8](try key.signature(for: Data(toBeSigned)).rawRepresentation)
    }
}
