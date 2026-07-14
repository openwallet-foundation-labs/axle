import Foundation
import SdJwt

public struct TransactionLogCodecError: Error, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// JSON serialization for `TransactionLogEntry` so a persistent `TransactionLogStore` can store
/// entries as text. Byte fields are base64url; the shape mirrors the Kotlin codec for a stable,
/// cross-platform on-disk format.
public enum TransactionLogCodec {

    public static func encode(_ entry: TransactionLogEntry) -> String { toJson(entry).serialize() }

    public static func decode(_ text: String) throws -> TransactionLogEntry {
        try fromJson(try JsonValue.parse(text))
    }

    static func toJson(_ e: TransactionLogEntry) -> JsonValue {
        var o: [(String, JsonValue)] = [
            ("id", .str(e.id)),
            ("timestamp", .numInt(e.timestamp)),
            ("type", .str(e.type.rawValue)),
            ("status", .str(e.status.rawValue)),
        ]
        if let rp = e.relyingParty { o.append(("relyingParty", rpJson(rp))) }
        if let issuer = e.issuer { o.append(("issuer", .str(issuer))) }
        o.append(("documents", .arr(e.documents.map(docJson))))
        if let error = e.error { o.append(("error", .str(error))) }
        if let raw = e.rawRequest { o.append(("rawRequest", .str(Base64Url.encode(raw)))) }
        if let raw = e.rawResponse { o.append(("rawResponse", .str(Base64Url.encode(raw)))) }
        if let transport = e.transport { o.append(("transport", .str(transport.rawValue))) }
        if let issuerName = e.issuerName { o.append(("issuerName", .str(issuerName))) }
        if let issuerRegistered = e.issuerRegistered { o.append(("issuerRegistered", .bool(issuerRegistered))) }
        return .obj(o)
    }

    static func fromJson(_ json: JsonValue) throws -> TransactionLogEntry {
        guard case .obj = json else { throw TransactionLogCodecError("entry must be an object") }
        guard case let .str(id)? = json["id"], case let .numInt(ts)? = json["timestamp"],
              case let .str(typeRaw)? = json["type"], let type = TransactionType(rawValue: typeRaw),
              case let .str(statusRaw)? = json["status"], let status = TransactionStatus(rawValue: statusRaw)
        else { throw TransactionLogCodecError("entry missing required fields") }

        var rp: RelyingParty?
        if let rpJson = json["relyingParty"], case .obj = rpJson { rp = rpFromJson(rpJson) }
        var issuer: String?
        if case let .str(s)? = json["issuer"] { issuer = s }
        var documents: [LoggedDocument] = []
        if case let .arr(items)? = json["documents"] { documents = items.compactMap { if case .obj = $0 { return docFromJson($0) }; return nil } }
        var error: String?
        if case let .str(s)? = json["error"] { error = s }
        var rawRequest: [UInt8]?
        if case let .str(s)? = json["rawRequest"] { rawRequest = try Base64Url.decode(s) }
        var rawResponse: [UInt8]?
        if case let .str(s)? = json["rawResponse"] { rawResponse = try Base64Url.decode(s) }
        var transport: TransactionTransport?
        if case let .str(s)? = json["transport"] { transport = TransactionTransport(rawValue: s) }
        var issuerName: String?
        if case let .str(s)? = json["issuerName"] { issuerName = s }
        var issuerRegistered: Bool?
        if case let .bool(b)? = json["issuerRegistered"] { issuerRegistered = b }

        return TransactionLogEntry(id: id, timestamp: ts, type: type, status: status, relyingParty: rp,
                                   issuer: issuer, documents: documents, error: error,
                                   rawRequest: rawRequest, rawResponse: rawResponse,
                                   transport: transport, issuerName: issuerName, issuerRegistered: issuerRegistered)
    }

    private static func rpJson(_ rp: RelyingParty) -> JsonValue {
        var o: [(String, JsonValue)] = [("id", .str(rp.id))]
        if let name = rp.name { o.append(("name", .str(name))) }
        o.append(("trusted", .bool(rp.trusted)))
        if !rp.certificateChainDer.isEmpty {
            o.append(("certificateChain", .arr(rp.certificateChainDer.map { .str(Base64Url.encode($0)) })))
        }
        if let clientIdScheme = rp.clientIdScheme { o.append(("clientIdScheme", .str(clientIdScheme))) }
        if let subject = rp.subject { o.append(("subject", .str(subject))) }
        if !rp.entitlements.isEmpty { o.append(("entitlements", .arr(rp.entitlements.map { .str($0) }))) }
        if !rp.purpose.isEmpty { o.append(("purpose", .arr(rp.purpose.map(textJson)))) }
        if let intermediaryName = rp.intermediaryName { o.append(("intermediaryName", .str(intermediaryName))) }
        if let intermediarySub = rp.intermediarySub { o.append(("intermediarySub", .str(intermediarySub))) }
        if let attested = rp.attested { o.append(("attested", .bool(attested))) }
        if let statusValid = rp.statusValid { o.append(("statusValid", .bool(statusValid))) }
        return .obj(o)
    }

    private static func rpFromJson(_ json: JsonValue) -> RelyingParty {
        var id = ""; if case let .str(s)? = json["id"] { id = s }
        var name: String?; if case let .str(s)? = json["name"] { name = s }
        var trusted = false; if case let .bool(b)? = json["trusted"] { trusted = b }
        var chain: [[UInt8]] = []
        if case let .arr(items)? = json["certificateChain"] { chain = items.compactMap { if case let .str(s) = $0 { return try? Base64Url.decode(s) }; return nil } }
        var clientIdScheme: String?; if case let .str(s)? = json["clientIdScheme"] { clientIdScheme = s }
        var subject: String?; if case let .str(s)? = json["subject"] { subject = s }
        var entitlements: [String] = []
        if case let .arr(items)? = json["entitlements"] { entitlements = items.compactMap { if case let .str(s) = $0 { return s }; return nil } }
        var purpose: [LocalizedText] = []
        if case let .arr(items)? = json["purpose"] { purpose = items.compactMap { if case .obj = $0 { return textFromJson($0) }; return nil } }
        var intermediaryName: String?; if case let .str(s)? = json["intermediaryName"] { intermediaryName = s }
        var intermediarySub: String?; if case let .str(s)? = json["intermediarySub"] { intermediarySub = s }
        var attested: Bool?; if case let .bool(b)? = json["attested"] { attested = b }
        var statusValid: Bool?; if case let .bool(b)? = json["statusValid"] { statusValid = b }
        return RelyingParty(id: id, name: name, trusted: trusted, certificateChainDer: chain,
                            clientIdScheme: clientIdScheme, subject: subject, entitlements: entitlements,
                            purpose: purpose, intermediaryName: intermediaryName, intermediarySub: intermediarySub,
                            attested: attested, statusValid: statusValid)
    }

    private static func textJson(_ t: LocalizedText) -> JsonValue {
        .obj([("lang", .str(t.lang)), ("value", .str(t.value))])
    }

    private static func textFromJson(_ json: JsonValue) -> LocalizedText {
        var lang = ""; if case let .str(s)? = json["lang"] { lang = s }
        var value = ""; if case let .str(s)? = json["value"] { value = s }
        return LocalizedText(lang: lang, value: value)
    }

    private static func docJson(_ d: LoggedDocument) -> JsonValue {
        var o: [(String, JsonValue)] = [("format", .str(d.format))]
        if let type = d.type { o.append(("type", .str(type))) }
        if let queryId = d.queryId { o.append(("queryId", .str(queryId))) }
        o.append(("claims", .arr(d.claims.map(claimJson))))
        return .obj(o)
    }

    private static func docFromJson(_ json: JsonValue) -> LoggedDocument {
        var format = ""; if case let .str(s)? = json["format"] { format = s }
        var type: String?; if case let .str(s)? = json["type"] { type = s }
        var queryId: String?; if case let .str(s)? = json["queryId"] { queryId = s }
        var claims: [LoggedClaim] = []
        if case let .arr(items)? = json["claims"] { claims = items.compactMap { if case .obj = $0 { return claimFromJson($0) }; return nil } }
        return LoggedDocument(format: format, type: type, queryId: queryId, claims: claims)
    }

    private static func claimJson(_ c: LoggedClaim) -> JsonValue {
        var o: [(String, JsonValue)] = [("path", .arr(c.path.map { .str($0) }))]
        if let value = c.value { o.append(("value", .str(value))) }
        return .obj(o)
    }

    private static func claimFromJson(_ json: JsonValue) -> LoggedClaim {
        var path: [String] = []
        if case let .arr(items)? = json["path"] { path = items.compactMap { if case let .str(s) = $0 { return s }; return nil } }
        var value: String?; if case let .str(s)? = json["value"] { value = s }
        return LoggedClaim(path: path, value: value)
    }
}
