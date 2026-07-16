import SwiftUI
import UIKit
import Wallet
import WalletAPI

/// OpenID4VP remote presentation — a 1:1 mirror of android `PresentScreen`, in behavior and layout. Drives
/// the session from `.resolvingRequest` through consent (`.requestResolved`) to submit and the terminal
/// `.completed`/`.failed`. Brand palette + Manrope + the shared cards. On completion with a `redirectUri`
/// the verifier's result URL is opened; otherwise an in-wallet "Shared" success is shown.
struct PresentView: View {
    let session: PresentationSession
    let onDone: () -> Void
    let onCancel: () -> Void

    @State private var step: PresentStep = .resolving
    @State private var request: PresentationRequest?
    @State private var chosen: [String: [CredentialId]] = [:]
    @State private var included: [String: Bool] = [:]
    @State private var credsById: [CredentialId: Credential] = [:]
    @State private var errorMessage: String?
    @State private var confirmDecline = false

    enum PresentStep { case resolving, review, sharing, shared, failed }

    var body: some View {
        VStack(spacing: 0) {
            if step == .review {
                Text("Sharing request").font(WalletFont.titleMedium).foregroundStyle(WalletTheme.ink)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Spacer().frame(height: 16)
            }
            content.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(WalletTheme.screen.ignoresSafeArea())
        .task { await loadCreds() }
        .task { await drive() }
        .alert("Decline this request?", isPresented: $confirmDecline) {
            Button("Decline", role: .destructive) { decline() }
            Button("Keep", role: .cancel) {}
        } message: {
            Text("Nothing will be shared with the verifier.")
        }
        .interactiveDismissDisabled(true)
    }

    @ViewBuilder private var content: some View {
        switch step {
        case .resolving:
            FlowLoading(title: "Resolving request…", subtitle: "Verifying who is asking.")
        case .review:
            if let request { reviewStep(request) }
        case .sharing:
            FlowLoading(title: "Sharing…", subtitle: "Sending the selected data to the verifier.")
        case .shared:
            FlowResult(kind: .success, title: "Shared", subtitle: "The verifier received the selected data.", buttonTitle: "Done", onButton: onDone)
        case .failed:
            FlowResult(kind: .failure, title: "Couldn't share", subtitle: errorMessage ?? "The presentation failed.", buttonTitle: "Close", onButton: onCancel)
        }
    }

    // MARK: - Consent

    private func reviewStep(_ request: PresentationRequest) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    verifierCard(request.verifier)
                    SectionLabel("Trust")
                    trustCard(request.verifier)
                    if let reg = request.verifier.registration { purposeSection(reg) }
                    SectionLabel("You'll share")
                    ForEach(sortedQueries(request), id: \.queryId) { queryCard($0) }
                    FlowNote("Required attributes are always shared; optional ones are off unless you turn them on. Everything else stays on this device.")
                }
            }
            FlowFooter(primaryTitle: "Share", primaryEnabled: request.satisfiable,
                       onPrimary: { share() }, secondaryTitle: "Decline", onSecondary: { confirmDecline = true })
        }
    }

    private func verifierCard(_ verifier: VerifierInfo) -> some View {
        WalletCard {
            HStack(spacing: 12) {
                Text(String(rpName(verifier).prefix(1)).uppercased())
                    .font(WalletFont.titleMedium).foregroundStyle(.white)
                    .frame(width: 42, height: 42)
                    .background(WalletTheme.ink, in: RoundedRectangle(cornerRadius: 12))
                VStack(alignment: .leading, spacing: 2) {
                    Text(rpName(verifier)).font(WalletFont.titleSmall).foregroundStyle(WalletTheme.ink)
                    Text(rpSubtitle(verifier)).font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted).lineLimit(1)
                }
                Spacer()
                TrustPill(trusted: verifier.trusted, trustedText: "Verified", untrustedText: "Unverified")
            }
        }
    }

    private func trustCard(_ verifier: VerifierInfo) -> some View {
        WalletCard(padding: .flush) {
            TrustRow(label: "Signed request", value: verifier.trusted ? "Verified" : "Not verified", ok: verifier.trusted)
            Rectangle().fill(WalletTheme.divider).frame(height: 1)
            let reg = verifier.registration
            let (text, ok) = registrationVerdict(reg)
            TrustRow(label: "Registration (WRPRC)", value: text, ok: ok)
        }
    }

    private func purposeSection(_ reg: VerifierRegistration) -> some View {
        let overAsking = !reg.unregisteredClaims.isEmpty
        return VStack(alignment: .leading, spacing: 8) {
            SectionLabel("Purpose")
            WalletCard {
                HStack(spacing: 10) {
                    Text(purposeText(reg.purpose) ?? "Attribute request")
                        .font(WalletFont.bodyMedium).foregroundStyle(WalletTheme.ink)
                    Spacer()
                    TrustPill(trusted: !overAsking, trustedText: "In scope", untrustedText: "Out of scope")
                }
            }
        }
    }

    private func queryCard(_ query: QueryPresentation) -> some View {
        let willShare = query.required || (included[query.queryId] ?? false)
        let selectedIds = chosen[query.queryId] ?? []
        let primaryId = selectedIds.first ?? query.candidates.first?.credentialId
        let primaryCand = query.candidates.first { $0.credentialId == primaryId } ?? query.candidates.first
        let primaryCred = primaryId.flatMap { credsById[$0] }
        let leaves = sharedLeaves(primaryCred, primaryCand?.disclosedPaths ?? [])

        return WalletCard(padding: .flush) {
            // header: document + optional toggle
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(primaryCred.map { credTitle($0) } ?? query.queryId)
                        .font(WalletFont.titleSmall).foregroundStyle(willShare ? WalletTheme.ink : WalletTheme.inkFaint)
                    Text(query.required ? "Required" : "Optional").font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
                }
                Spacer()
                if !query.required {
                    Toggle("", isOn: Binding(get: { included[query.queryId] ?? false }, set: { included[query.queryId] = $0 }))
                        .labelsHidden().tint(WalletTheme.brand)
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 12)

            if query.candidates.isEmpty {
                cardDivider
                Text("No matching document in your wallet.")
                    .font(WalletFont.bodySmall).foregroundStyle(WalletTheme.danger)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.vertical, 12)
            } else {
                if query.candidates.count > 1 {
                    cardDivider
                    groupHeader("Choose a document")
                    ForEach(query.candidates, id: \.credentialId) { cand in
                        candidateCard(query, cand, selectedIds: selectedIds)
                    }
                    Spacer().frame(height: 6)
                }
                cardDivider
                groupHeader(query.required ? "Shared" : "Optional")
                if leaves.isEmpty {
                    Text("No personal attributes.")
                        .font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 16).padding(.bottom, 12)
                } else {
                    ForEach(Array(leaves.enumerated()), id: \.offset) { _, claim in
                        if willShare, isImageClaim(claim.path), let image = claimImage(claim) {
                            ClaimImageRow(label: claimLabel(claim.path), image: image)
                        } else {
                            WalletInfoRow(label: claimLabel(claim.path),
                                          value: willShare ? claim.value.display() : "Off",
                                          valueColor: willShare ? WalletTheme.ink : WalletTheme.inkFaint)
                        }
                    }
                }
            }
        }
    }

    private func candidateCard(_ query: QueryPresentation, _ candidate: PresentationCandidate, selectedIds: [CredentialId]) -> some View {
        let checked = selectedIds.contains(candidate.credentialId)
        let cred = credsById[candidate.credentialId]
        let shape = RoundedRectangle(cornerRadius: 12)
        return Button {
            toggleCandidate(query, candidate.credentialId)
        } label: {
            HStack(spacing: 12) {
                if let cred { DocTile(glyph: credGlyph(cred), colors: credGradient(cred), size: 40) }
                VStack(alignment: .leading, spacing: 2) {
                    Text(cred.map { credTitle($0) } ?? "Credential").font(WalletFont.titleSmall).foregroundStyle(WalletTheme.ink)
                    let subtitle = candidateSubtitle(cred, candidate.disclosedPaths)
                    if !subtitle.isEmpty {
                        Text(subtitle).font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted).lineLimit(1)
                    }
                }
                Spacer()
                selectionIndicator(checked: checked, multiple: query.multiple)
            }
            .padding(10)
            .background(checked ? WalletTheme.brand.opacity(0.06) : WalletTheme.card, in: shape)
            .overlay(shape.strokeBorder(checked ? WalletTheme.brand : WalletTheme.cardBorder, lineWidth: checked ? 1.5 : 1))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 12).padding(.vertical, 5)
    }

    private func selectionIndicator(checked: Bool, multiple: Bool) -> some View {
        let shape = RoundedRectangle(cornerRadius: multiple ? 6 : 99)
        return ZStack {
            shape.fill(checked ? WalletTheme.brand : Color.clear)
            shape.strokeBorder(checked ? WalletTheme.brand : WalletTheme.cardBorderStrong, lineWidth: 2)
            if checked { Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(.white) }
        }
        .frame(width: 20, height: 20)
    }

    private func groupHeader(_ text: String) -> some View {
        Text(text.uppercased())
            .font(WalletFont.labelSmall).tracking(0.6).foregroundStyle(WalletTheme.inkFaint)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16).padding(.top, 10).padding(.bottom, 4)
    }

    private var cardDivider: some View { Rectangle().fill(WalletTheme.divider).frame(height: 1) }

    // MARK: - Behavior

    private func drive() async {
        for await state in session.states {
            switch state {
            case .resolvingRequest:
                step = .resolving
            case let .requestResolved(req):
                request = req
                initSelection(req)
                step = .review
            case .submitting:
                step = .sharing
            case let .completed(redirectUri, _):
                await followRedirect(redirectUri)
                return
            case .declined:
                onCancel()
                return
            case let .failed(error):
                errorMessage = error.displayMessage
                step = .failed
                return
            }
        }
    }

    private func loadCreds() async {
        let list = (try? await DemoWallet.shared.credentials.list()) ?? []
        credsById = Dictionary(list.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
    }

    private func initSelection(_ request: PresentationRequest) {
        var chosen: [String: [CredentialId]] = [:]
        var included: [String: Bool] = [:]
        for query in request.queries {
            chosen[query.queryId] = query.candidates.first.map { [$0.credentialId] } ?? []
            included[query.queryId] = query.required
        }
        self.chosen = chosen
        self.included = included
    }

    /// Per-query selection, mirroring android `buildSelection` (not `PresentationSelection.auto`).
    private func buildSelection() -> PresentationSelection {
        guard let request else { return PresentationSelection(chosen: [:]) }
        var map: [String: [CredentialId]] = [:]
        for query in request.queries where !query.candidates.isEmpty && (query.required || included[query.queryId] == true) {
            let ids = chosen[query.queryId] ?? []
            map[query.queryId] = ids.isEmpty ? [query.candidates[0].credentialId] : ids
        }
        return PresentationSelection(chosen: map)
    }

    private func toggleCandidate(_ query: QueryPresentation, _ id: CredentialId) {
        if query.multiple {
            var ids = chosen[query.queryId] ?? []
            if let idx = ids.firstIndex(of: id) {
                ids.remove(at: idx)
                if ids.isEmpty { ids = [id] }
            } else {
                ids.append(id)
            }
            chosen[query.queryId] = ids
        } else {
            chosen[query.queryId] = [id]
        }
    }

    /// Biometric confirm-to-share (android `PresentScreen.share`), gated on the enabled biometric.
    private func share() {
        let selection = buildSelection()
        if WalletSecurity.biometricEnabled && BiometricAuth.canUse() {
            BiometricAuth.prompt(reason: "Confirm to share the selected data", onSuccess: {
                step = .sharing
                session.respond(selection)
            })
        } else {
            step = .sharing
            session.respond(selection)
        }
    }

    private func decline() {
        session.decline()
        onCancel()
    }

    private func followRedirect(_ redirectUri: String?) async {
        if let redirectUri, let url = URL(string: redirectUri) {
            await UIApplication.shared.open(url)
            onDone()
        } else {
            step = .shared
        }
    }

    // MARK: - Display helpers

    private func registrationVerdict(_ reg: VerifierRegistration?) -> (String, Bool) {
        guard let reg else { return ("None", false) }
        let sigOk = reg.attested || reg.registrarVerified
        if !sigOk { return ("Self-declared", false) }
        if reg.statusValid == false { return ("Revoked", false) }
        return ("Verified by registrar", true)
    }

    private func sharedLeaves(_ cred: Credential?, _ disclosed: [[String]]) -> [Claim] {
        guard let cred, case let .issued(claims, _, _) = cred.lifecycle else { return [] }
        func isDisclosed(_ path: [String]) -> Bool {
            disclosed.contains { d in d.count <= path.count && Array(path.prefix(d.count)) == d }
        }
        return claims.filter { $0.category == .subject && isDisclosed($0.path) }
    }

    private func candidateSubtitle(_ cred: Credential?, _ disclosed: [[String]]) -> String {
        sharedLeaves(cred, disclosed)
            .filter { !isImageClaim($0.path) } // an image value is a base64 blob — useless as a text preview
            .map { $0.value.display() }.filter { !$0.isEmpty }.prefix(2).joined(separator: " · ")
    }

    private func rpName(_ verifier: VerifierInfo) -> String {
        if let name = verifier.registration?.subjectName, !name.isEmpty { return name }
        if let subject = verifier.registration?.subject, !subject.isEmpty { return subject }
        return verifier.commonName ?? verifier.clientId
    }

    private func rpSubtitle(_ verifier: VerifierInfo) -> String {
        if let intermediary = verifier.registration?.intermediaryName { return "via \(intermediary)" }
        return verifier.clientId
    }

    private func purposeText(_ purpose: [PurposeText]?) -> String? {
        guard let purpose, !purpose.isEmpty else { return nil }
        let lang = Locale.current.language.languageCode?.identifier ?? "en"
        return (purpose.first { $0.lang.hasPrefix(lang) } ?? purpose[0]).value
    }

    private func sortedQueries(_ request: PresentationRequest) -> [QueryPresentation] {
        request.queries.sorted { $0.required && !$1.required }
    }

    private func claimLabel(_ path: [String]) -> String {
        let last = path.last ?? path.joined(separator: " › ")
        let spaced = last.replacingOccurrences(of: "_", with: " ")
        guard let first = spaced.first else { return last }
        return first.uppercased() + spaced.dropFirst()
    }
}

extension PresentationError {
    var displayMessage: String {
        switch self {
        case let .invalidRequest(m): return m
        case let .verifierNotTrusted(m): return m
        case let .queryNotSatisfiable(m): return m
        case let .selectionIncomplete(m): return m
        case let .responseRejected(m): return m
        case let .unexpected(m): return m
        }
    }
}
