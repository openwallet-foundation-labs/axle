import SwiftUI
import Wallet
import WalletAPI // CredentialFormat cases

/// Shared credential-content pieces — a 1:1 port of android `ui/CredentialContent.kt`. Used by the document
/// detail and the issuance review step so both render identically (gradient card, trust panel, claim sections).

/// The gradient credential card (kicker + format pill + title + issuer).
struct CredentialGradientCard: View {
    let cred: Credential
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(credKicker(cred).uppercased()).font(WalletFont.labelSmall).tracking(0.6).foregroundStyle(.white.opacity(0.85))
                Spacer()
                Pill(text: credFormatLabel(cred), bg: .white.opacity(0.12), fg: .white)
            }
            Spacer().frame(height: 22)
            Text(credTitle(cred)).font(WalletFont.titleMedium).foregroundStyle(.white)
            if let issuer = cred.issuer?.displayName {
                Text(issuer).font(WalletFont.bodySmall).foregroundStyle(.white.opacity(0.75)).padding(.top, 3)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            LinearGradient(colors: credGradient(cred), startPoint: .topLeading, endPoint: .bottomTrailing),
            in: RoundedRectangle(cornerRadius: 20)
        )
    }
}

/// Trust panel: credential signature + issuer registration.
struct CredentialTrustCard: View {
    let cred: Credential
    var body: some View {
        WalletCard(padding: .flush) {
            TrustRow(label: "Credential signature", value: credTrustText(cred.issuer?.trusted), ok: cred.issuer?.trusted == true)
            Rectangle().fill(WalletTheme.divider).frame(height: 1)
            TrustRow(label: "Issuer registration", value: credTrustText(cred.issuer?.registered), ok: cred.issuer?.registered == true)
        }
    }
}

/// "Claims" and "Metadata" sections (SDK-classified), sensitive values masked unless `reveal`.
struct CredentialClaimSections: View {
    let cred: Credential
    var reveal: Bool

    private var claims: [Claim] {
        if case let .issued(claims, _, _) = cred.lifecycle { return claims }
        return []
    }

    var body: some View {
        let personal = claims.filter { $0.category != .metadata }
        let metadata = claims.filter { $0.category == .metadata }
        if !personal.isEmpty {
            SectionLabel("Claims")
            claimsCard(personal)
        }
        if !metadata.isEmpty {
            SectionLabel("Metadata")
            claimsCard(metadata)
        }
    }

    private func claimsCard(_ items: [Claim]) -> some View {
        WalletCard(padding: .flush) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, claim in
                if isImageClaim(claim.path), let image = claimImage(claim) {
                    ClaimImageRow(label: credClaimLabel(cred, claim.path), image: image)
                } else {
                    WalletInfoRow(label: credClaimLabel(cred, claim.path), value: displayValue(claim))
                }
            }
        }
    }

    private func displayValue(_ claim: Claim) -> String {
        let raw = claim.value.display()
        return (isSensitiveClaim(claim.path) && !reveal) ? maskSensitive(raw) : raw
    }
}

/// mdoc image-carrying elements (ISO 23220-2 / 18013-5: portrait, signature) arrive as base64url text —
/// the SDK projects CBOR bstr that way for DCQL matching — so every claim-listing surface (detail, consents,
/// proximity, reader) decodes them by element name and renders an image row instead of text.
private let imageElements: Set<String> = ["portrait", "enrolment_portrait_image", "signature_usual_mark"]

func isImageElement(_ key: String?) -> Bool {
    guard let k = key?.lowercased() else { return false }
    return imageElements.contains(k)
}

func isImageClaim(_ path: [String]) -> Bool { isImageElement(path.last) }

/// Decodes an image from base64 in either alphabet (base64url claim text or standard base64), padded or not.
func claimImage(base64 raw: String) -> UIImage? {
    var b64 = raw
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while b64.count % 4 != 0 { b64 += "=" }
    guard let data = Data(base64Encoded: b64) else { return nil }
    return UIImage(data: data)
}

func claimImage(_ claim: Claim) -> UIImage? { claimImage(base64: claim.value.display()) }

/// A WalletInfoRow variant whose value is an image (mirrors android `ClaimImageRow`).
struct ClaimImageRow: View {
    let label: String
    let image: UIImage

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 12) {
                Text(label).font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
                Spacer(minLength: 12)
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(width: 64, height: 84)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            .padding(.horizontal, 16).padding(.vertical, 13)
            Rectangle().fill(WalletTheme.divider).frame(height: 1)
        }
    }
}

/// Whether the credential has any sensitive claim (so a caller can offer a reveal toggle).
func hasSensitiveClaims(_ cred: Credential) -> Bool {
    guard case let .issued(claims, _, _) = cred.lifecycle else { return false }
    return claims.contains { isSensitiveClaim($0.path) }
}

func credTrustText(_ flag: Bool?) -> String {
    switch flag {
    case .some(true): return "Trusted"
    case .some(false): return "Not verified"
    case .none: return "Not checked"
    }
}

/// mdoc claim paths start with the namespace (same for every element) — drop it for readability.
func credClaimLabel(_ cred: Credential, _ path: [String]) -> String {
    var p = path
    if case .msoMdoc = cred.format, p.count > 1 { p = Array(p.dropFirst()) }
    return p.map { seg in
        let spaced = seg.replacingOccurrences(of: "_", with: " ")
        return spaced.prefix(1).uppercased() + spaced.dropFirst()
    }.joined(separator: " › ")
}

private let sensitiveKeys = ["number", "identifier", "birth", "national", "iban", "administrative", "document", "passport", "ssn", "tax"]

func isSensitiveClaim(_ path: [String]) -> Bool {
    guard let key = path.last?.lowercased() else { return false }
    return sensitiveKeys.contains { key.contains($0) }
}

func maskSensitive(_ v: String) -> String {
    String(v.map { $0.isLetter || $0.isNumber ? "•" : $0 })
}
