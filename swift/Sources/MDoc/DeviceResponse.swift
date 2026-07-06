import CborCose

/// One document inside a `DeviceResponse` (ISO 18013-5 §8.3.2.1.2.2), reader-side view.
public struct ResponseDocument {
    public let docType: String
    public let issuerSigned: IssuerSigned
    /// `DeviceNameSpacesBytes` (#6.24) as received — for `DeviceAuthentication` reconstruction.
    public let deviceNameSpacesBytes: Cbor
    /// COSE_Sign1 device authentication, or nil when the document uses `deviceMac` instead.
    public let deviceSignature: CoseSign1?
    /// COSE_Mac0 device authentication (ISO 18013-5 §9.1.3.5), for key-agreement device keys.
    public let deviceMac: CoseMac0?
}

/// A wallet's `DeviceResponse` as parsed by the reader/verifier.
public struct DeviceResponse {
    public let version: String
    public let status: Int64
    public let documents: [ResponseDocument]

    public static func decode(_ bytes: [UInt8]) throws -> DeviceResponse {
        guard case let .map(entries) = try CborDecoder.decode(bytes) else { throw MdocError("DeviceResponse must be a map") }
        guard case let .text(version)? = mdocField(entries, "version") else { throw MdocError("missing version") }
        var status: Int64 = 0
        if case let .uint(s)? = mdocField(entries, "status") { status = Int64(s) }

        var documents: [ResponseDocument] = []
        if case let .array(docs)? = mdocField(entries, "documents") {
            documents = try docs.map { doc in
                guard case let .map(docMap) = doc else { throw MdocError("document must be a map") }
                guard case let .text(docType)? = mdocField(docMap, "docType") else { throw MdocError("missing docType") }
                guard let issuerSignedCbor = mdocField(docMap, "issuerSigned") else { throw MdocError("missing issuerSigned") }
                let issuerSigned = try IssuerSigned.fromCbor(issuerSignedCbor)
                guard case let .map(deviceSigned)? = mdocField(docMap, "deviceSigned") else { throw MdocError("missing deviceSigned") }
                guard let deviceNameSpacesBytes = mdocField(deviceSigned, "nameSpaces") else { throw MdocError("missing deviceSigned nameSpaces") }
                guard case let .map(deviceAuth)? = mdocField(deviceSigned, "deviceAuth") else { throw MdocError("missing deviceAuth") }
                let deviceSignature = try mdocField(deviceAuth, "deviceSignature").map { try CoseSign1.fromCbor($0) }
                let deviceMac = try mdocField(deviceAuth, "deviceMac").map { try CoseMac0.fromCbor($0) }
                if deviceSignature == nil, deviceMac == nil { throw MdocError("deviceAuth has neither deviceSignature nor deviceMac") }
                return ResponseDocument(docType: docType, issuerSigned: issuerSigned, deviceNameSpacesBytes: deviceNameSpacesBytes,
                                        deviceSignature: deviceSignature, deviceMac: deviceMac)
            }
        }
        return DeviceResponse(version: version, status: status, documents: documents)
    }
}
