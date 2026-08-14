import CborCose
import Foundation // Data (image-claim base64 encoding)
import MDoc

/// Reader-side helpers that keep the `MDoc` / `CborCose` types out of the app: the app builds a request and
/// renders results through these, naming only `AppleProximity` types. Mirrors the android demo's
/// `readerRequest()` + `ReaderResultCard` rendering.

/// One document a proximity reader received, flattened for display.
public struct ReaderResultDoc: Sendable {
    public let docType: String
    public let deviceAuthenticated: Bool
    /// Why the document is unverified (issuer signature, digest, validity or holder binding), when known.
    public let verificationError: String?
    public let claims: [Claim]

    public struct Claim: Sendable {
        public let namespace: String
        public let element: String
        public let value: String
        /// Standard-base64 raw bytes for an image element (portrait etc.), so the app can render a thumbnail.
        public let imageBase64: String?
    }
}

/// The document types the demo reader can request — pick one or several on the reader screen.
/// Mirrors the android demo's `ReaderDocKind`.
public enum ReaderDocKind: String, CaseIterable, Sendable {
    case pid = "Personal ID"
    case mdl = "Driving Licence"
    case age = "Proof of Age"
    case photoID = "Photo ID"

    /// The exact mdoc DocType this kind requests — shown under the friendly name in the picker.
    public var doctype: String {
        switch self {
        case .pid: return "eu.europa.ec.eudi.pid.1"
        case .mdl: return "org.iso.18013.5.1.mDL"
        case .age: return "eu.europa.ec.av.1"
        case .photoID: return "org.iso.23220.photoid.1"
        }
    }
}

public enum MdocReaderRequests {
    /// The request for one document kind (android demo `readerRequest(kind)`).
    public static func request(_ kind: ReaderDocKind) -> [RequestedDocument] {
        request([kind])
    }

    /// One DocRequest per selected kind — a single DeviceRequest may carry several (ISO 18013-5 §8.3.2.1.2.1).
    public static func request(_ kinds: Set<ReaderDocKind>) -> [RequestedDocument] {
        ReaderDocKind.allCases.filter { kinds.contains($0) }.map { kind in
            let elements: [(String, [String])]
            switch kind {
            case .pid:
                elements = [("eu.europa.ec.eudi.pid.1", ["family_name", "given_name", "birth_date", "nationality"])]
            // portrait is an ISO 18013-5 mandatory element — the reader verifies the holder's photo.
            case .mdl:
                elements = [("org.iso.18013.5.1", ["family_name", "given_name", "portrait", "driving_privileges"])]
            // AV Profile §A.4: age_over_18 is the only attribute a Proof of Age attestation carries.
            case .age:
                elements = [("eu.europa.ec.av.1", ["age_over_18"])]
            // ISO 23220-4 Annex C: identity claims live in the generic 23220-2 namespace.
            case .photoID:
                elements = [("org.iso.23220.1", ["family_name", "given_name", "birth_date", "portrait", "age_over_18"])]
            }
            return RequestedDocument(docType: kind.doctype, elements: elements)
        }
    }

    /// Flattens verified documents into display rows, rendering each CBOR element value to a readable string.
    public static func flatten(_ documents: [VerifiedDocument]) -> [ReaderResultDoc] {
        documents.map { doc in
            var claims: [ReaderResultDoc.Claim] = []
            for (namespace, elements) in doc.elements {
                for (element, value) in elements {
                    var imageBase64: String?
                    if case let .bytes(b) = value, imageElements.contains(element.lowercased()) {
                        imageBase64 = Data(b).base64EncodedString()
                    }
                    claims.append(.init(namespace: namespace, element: element, value: cborString(element: element, value), imageBase64: imageBase64))
                }
            }
            return ReaderResultDoc(
                docType: doc.docType,
                deviceAuthenticated: doc.deviceAuthenticated,
                verificationError: doc.verificationError,
                claims: claims.sorted { $0.element < $1.element }
            )
        }
    }
}

/// mdoc image-carrying elements (ISO 23220-2 / 18013-5) — surfaced with raw bytes for thumbnail rendering.
private let imageElements: Set<String> = ["portrait", "enrolment_portrait_image", "signature_usual_mark"]

/// Renders a received mdoc element value for display.
///
/// Most ISO 18013-5 elements are scalars — `family_name` is a tstr, `birth_date` a tagged full-date,
/// `age_over_18` a bool, `portrait` a bstr — so a flat renderer got by. `driving_privileges` is not: §7.2.4
/// defines it as an array of maps, and 23220-based doctypes nest further still. Anything this function does
/// not name recurses through `cborValue` rather than falling through to a `String(describing:)` dump.
func cborString(element: String, _ value: Cbor) -> String {
    if element == "driving_privileges", let rendered = drivingPrivilegesText(value) { return rendered }
    return cborValue(value)
}

/// Generic recursive rendering. Maps become `key: value` pairs and arrays their elements; the top level of an
/// array goes one entry per line, nested levels stay inline so a row does not explode vertically.
func cborValue(_ value: Cbor, depth: Int = 0) -> String {
    switch value {
    case let .text(s): return s
    case let .uint(u): return String(u)
    case let .nint(n): return "-\(n + 1)"
    case let .bool(b): return b ? "Yes" : "No"
    case let .bytes(b): return "\(b.count) bytes"
    case .null: return "—"
    case let .tagged(_, inner): return cborValue(inner, depth: depth) // full-date / tdate carry the date inside
    case let .array(a):
        // One line per entry only when the entries carry structure (an array of maps, e.g. driving_privileges);
        // a list of scalars like `nationality` stays inline so it does not eat four rows of screen.
        let structured = depth == 0 && a.contains { if case .map = $0 { return true }; if case .array = $0 { return true }; return false }
        return a.map { cborValue($0, depth: depth + 1) }.joined(separator: structured ? "\n" : ", ")
    case let .map(entries):
        return entries.map { "\(elementLabel(cborValue($0.0, depth: depth + 1))): \(cborValue($0.1, depth: depth + 1))" }
            .joined(separator: ", ")
    default: return String(describing: value)
    }
}

/// `snake_case` element identifier → "Snake case", for map keys surfaced inside a value.
private func elementLabel(_ id: String) -> String {
    let spaced = id.replacingOccurrences(of: "_", with: " ")
    return spaced.prefix(1).uppercased() + spaced.dropFirst()
}

/// ISO 18013-5 §7.2.4 `DrivingPrivileges`: an array of `{vehicle_category_code, ?issue_date, ?expiry_date,
/// ?codes}`, where each `Code` is `{code, ?sign, ?value}`. Rendered one category per line — the category is
/// what a verifier reads, so it leads; dates and codes qualify it.
///
/// Returns nil when the value is not that shape, so an issuer that sends something unexpected still gets the
/// generic rendering instead of a blank row.
private func drivingPrivilegesText(_ value: Cbor) -> String? {
    guard case let .array(privileges) = value else { return nil }
    if privileges.isEmpty { return "—" } // §7.2.4 NOTE 2: the structure can legitimately be an empty array

    func fields(_ c: Cbor) -> [String: Cbor]? {
        guard case let .map(entries) = c else { return nil }
        return Dictionary(entries.map { (cborValue($0.0), $0.1) }, uniquingKeysWith: { first, _ in first })
    }

    var lines: [String] = []
    for privilege in privileges {
        guard let f = fields(privilege), let categoryValue = f["vehicle_category_code"] else { return nil }
        let category = cborValue(categoryValue)
        let issued = f["issue_date"].map { cborValue($0) }
        let expires = f["expiry_date"].map { cborValue($0) }
        let validity: String
        switch (issued, expires) {
        case let (issued?, expires?): validity = " · \(issued) → \(expires)"
        case let (issued?, nil): validity = " · from \(issued)"
        case let (nil, expires?): validity = " · until \(expires)"
        default: validity = ""
        }
        var codes: [String] = []
        if case let .array(rawCodes)? = f["codes"] {
            for code in rawCodes {
                guard let cf = fields(code), let id = cf["code"] else { continue }
                codes.append(cborValue(id) + (cf["sign"].map { cborValue($0) } ?? "") + (cf["value"].map { cborValue($0) } ?? ""))
            }
        }
        lines.append(category + validity + (codes.isEmpty ? "" : " · " + codes.joined(separator: ", ")))
    }
    return lines.joined(separator: "\n")
}
