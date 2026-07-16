import AppleCore // re-exports TransactionLog (TransactionLogEntry)
import SwiftUI
import Wallet
import WalletAPI // CredentialFormat cases

/// Presentation helpers for a `Credential` — a 1:1 port of android `ui/CredentialVisuals.kt`. The stable
/// "kind" (derived from the type string) picks a friendly title, kicker, glyph, and card gradient.

/// Stable kind of a credential, derived from its type identifier.
private enum DocKind { case pid, mdl, age, photoID, health, education, residence, finance, other }

/// The credential's type identifier (SD-JWT `vct` or mdoc `docType`) — used to match transaction-log entries.
func credType(_ c: Credential) -> String {
    switch c.format {
    case let .sdJwtVc(vct): return vct
    case let .msoMdoc(docType): return docType
    }
}

private func kindOf(_ c: Credential) -> DocKind {
    let t = credType(c).lowercased()
    if t.contains(".av.") || t.contains("proof_of_age") || t.contains("age_verification") { return .age }
    if t.contains("photoid") || t.contains("photo_id") { return .photoID }
    if t.contains("pid") || t.contains("eudi.pid") || t.contains("identity") { return .pid }
    if t.contains("mdl") || (t.contains("mdoc") && t.contains("18013")) || t.contains("18013.5.1.mdl") || t.contains("driving") { return .mdl }
    if t.contains("ehic") || t.contains("health") || t.contains("insurance") { return .health }
    if t.contains("diploma") || t.contains("education") || t.contains("degree") { return .education }
    if t.contains("residence") || t.contains("address") { return .residence }
    if t.contains("iban") || t.contains("bank") || t.contains("account") || t.contains("payment") { return .finance }
    return .other
}

/// A short human title for the credential card (e.g. "Personal ID", "Mobile Driving Licence").
func credTitle(_ c: Credential) -> String {
    switch kindOf(c) {
    case .pid: return "Personal ID"
    case .mdl: return "Mobile Driving Licence"
    case .age: return "Proof of Age"
    case .photoID: return "Photo ID"
    case .health: return "Health Insurance Card"
    case .education: return "Education Credential"
    case .residence: return "Residence Certificate"
    case .finance: return "Bank Account"
    case .other: return prettifyType(credType(c))
    }
}

/// The all-caps kicker shown on the card (e.g. "PERSONAL ID · PID").
func credKicker(_ c: Credential) -> String {
    switch kindOf(c) {
    case .pid: return "Personal ID · PID"
    case .mdl: return "Driving Licence · mDL"
    case .age: return "Age Verification · 18+"
    case .photoID: return "Photo ID · ISO 23220"
    case .health: return "Health · EHIC"
    case .education: return "Education"
    case .residence: return "Residence"
    case .finance: return "Finance"
    case .other: return "Credential"
    }
}

/// The 2-letter glyph on the document tile.
func credGlyph(_ c: Credential) -> String {
    switch kindOf(c) {
    case .pid: return "ID"
    case .mdl: return "DL"
    case .age: return "18"
    case .photoID: return "PH"
    case .health: return "HC"
    case .education: return "ED"
    case .residence: return "RC"
    case .finance: return "BA"
    case .other: return initials(credTitle(c))
    }
}

/// The card gradient for the credential's kind (deterministic for unknown kinds).
func credGradient(_ c: Credential) -> [Color] {
    switch kindOf(c) {
    case .pid: return DocGradients.pid
    case .mdl: return DocGradients.mdl
    case .age: return DocGradients.age
    case .photoID: return DocGradients.photoId
    case .health: return DocGradients.health
    case .education: return DocGradients.education
    case .residence: return DocGradients.residence
    case .finance: return DocGradients.finance
    case .other: return DocGradients.palette[abs(credType(c).hashValue % DocGradients.palette.count)]
    }
}

/// The credential format label ("mdoc" / "SD-JWT VC").
func credFormatLabel(_ c: Credential) -> String {
    switch c.format {
    case .sdJwtVc: return "SD-JWT VC"
    case .msoMdoc: return "mdoc"
    }
}

/// True for a Mobile Driving Licence — the one credential kind that also presents over proximity (Phase 4).
func credIsMdl(_ c: Credential) -> Bool { kindOf(c) == .mdl }

/// True for a Personal ID (PID) — the wallet's primary identity credential, featured as the home hero.
func credIsPid(_ c: Credential) -> Bool { kindOf(c) == .pid }

private func prettifyType(_ raw: String) -> String {
    let tail = raw.split(whereSeparator: { $0 == "/" || $0 == ":" || $0 == "." }).last.map(String.init) ?? raw
    let spaced = tail.replacingOccurrences(of: "_", with: " ").trimmingCharacters(in: .whitespaces)
    guard let first = spaced.first else { return "Credential" }
    return first.uppercased() + spaced.dropFirst()
}

private func initials(_ name: String) -> String {
    let parts = name.split(whereSeparator: { $0 == " " || $0 == "-" }).prefix(2)
    let s = parts.compactMap { $0.first?.uppercased() }.joined()
    return s.isEmpty ? "DC" : s
}

extension Array where Element == Credential {
    /// Orders credentials most-recently-used first: the later of the credential's issuance time and the
    /// newest transaction-log entry that presented a document of the same type. Mirrors android `byRecentUse`.
    func byRecentUse(_ txs: [TransactionLogEntry]) -> [Credential] {
        func lastUsed(_ cred: Credential) -> TimeInterval {
            let type = credType(cred)
            let txSeconds = txs
                .filter { e in e.documents.contains { $0.type == type } }
                .map { Double($0.timestamp) }
                .max() ?? 0
            return Swift.max(cred.createdAt.timeIntervalSince1970, txSeconds)
        }
        return sorted { lastUsed($0) > lastUsed($1) }
    }
}
