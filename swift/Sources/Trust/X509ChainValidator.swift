import Foundation
import SwiftASN1
import X509

/// Trust anchors (IACA / issuer-CA roots) the wallet is configured with — populated from the
/// EU LOTL / trust list by the host.
public struct TrustAnchors {
    let roots: [Certificate]

    public init(roots: [Certificate]) {
        precondition(!roots.isEmpty, "at least one trust anchor is required")
        self.roots = roots
    }

    public static func ofDer(_ ders: [[UInt8]]) throws -> TrustAnchors {
        TrustAnchors(roots: try ders.map { try X509Support.parse($0) })
    }
}

/// Supplies the current trust anchors at validation time (Level 1 dynamic trust). A static set
/// is `FixedAnchorSource`; a Level 2 LOTL provider (M6) would cache a signed trust list and
/// refresh it on a TTL, so anchors update without rebuilding the validator.
public protocol TrustAnchorSource: Sendable {
    func anchors() async throws -> TrustAnchors
}

/// A fixed anchor set — the common case (host injects a known list).
public struct FixedAnchorSource: TrustAnchorSource {
    private let value: TrustAnchors
    public init(_ value: TrustAnchors) { self.value = value }
    public func anchors() async -> TrustAnchors { value }
}

/// Validates an X.509 chain (leaf-first, excluding the anchor) to the anchors from a
/// `TrustAnchorSource` via swift-certificates' `Verifier` with the RFC 5280 policy. The source
/// is consulted per validation, so a dynamic (cached, TTL-refreshed) trust list plugs in.
public struct X509ChainValidator {
    private let anchorSource: any TrustAnchorSource
    private let validationTime: Date

    public init(anchorSource: any TrustAnchorSource, validationTime: Date = Date()) {
        self.anchorSource = anchorSource
        self.validationTime = validationTime
    }

    /// Convenience for the static case — validate against a fixed anchor set.
    public init(anchors: TrustAnchors, validationTime: Date = Date()) {
        self.init(anchorSource: FixedAnchorSource(anchors), validationTime: validationTime)
    }

    /// Returns the parsed chain (leaf first) if it validates to a current anchor, else throws.
    public func validate(_ chainDer: [[UInt8]]) async throws -> [Certificate] {
        guard let leafDer = chainDer.first else { throw TrustError("empty certificate chain") }
        let anchors = try await anchorSource.anchors()
        let leaf = try X509Support.parse(leafDer)
        let intermediates = try chainDer.dropFirst().map { try X509Support.parse($0) }

        let time = validationTime
        var verifier = Verifier(rootCertificates: CertificateStore(anchors.roots)) {
            RFC5280Policy(validationTime: time)
            AcceptExtendedKeyUsagePolicy()
        }
        let result = await verifier.validate(
            leafCertificate: leaf,
            intermediates: CertificateStore(intermediates)
        )
        switch result {
        case .validCertificate:
            return [leaf] + intermediates
        case let .couldNotValidate(failures):
            throw TrustError("chain does not validate to a trust anchor: \(failures)")
        }
    }
}

/// Marks `extendedKeyUsage` as a handled extension so a certificate that carries it CRITICAL is not
/// rejected as bearing an unhandled critical extension. ISO/IEC 18013-5 Annex B REQUIRES a critical EKU
/// (id-mdl-kp-mdlDS, 1.0.18013.5.1.2) on the mDL Document Signer — `RFC5280Policy` does not process EKU,
/// so without this policy every spec-conformant mDL/mdoc DS chain fails validation (the Java/Node stacks
/// treat EKU as a known extension natively). Purpose-specific EKU *enforcement* (e.g. requiring mdlDS for
/// mdoc issuer auth, TS 119 475 EKUs for a WRPAC) remains with the calling context.
private struct AcceptExtendedKeyUsagePolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [.X509ExtensionID.extendedKeyUsage]
    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        .meetsPolicy
    }
}
