import SwiftUI
import UIKit
import Wallet
import WalletAPI

/// OpenID4VP remote presentation — a behavioral mirror of android `PresentScreen`. Drives the session
/// from `.resolvingRequest` through consent (`.requestResolved`) to submit (`.submitting`) and the
/// terminal `.completed`/`.failed`. On completion with a `redirectUri` the verifier's result URL is
/// opened in the browser; otherwise an in-wallet "Shared" success is shown.
struct PresentView: View {
    let session: PresentationSession
    /// Shared / opened-redirect path — dismiss and reload the wallet lists.
    let onDone: () -> Void
    /// Declined or failed — dismiss without reload.
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
            if step == .review { header }
            content
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.systemBackground).ignoresSafeArea())
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

    private var header: some View {
        HStack {
            Button { confirmDecline = true } label: {
                Image(systemName: "chevron.left").font(.headline)
                    .frame(width: 36, height: 36)
                    .background(Color(.secondarySystemBackground), in: Circle())
            }
            Spacer()
            Text("Sharing request").font(.headline)
            Spacer()
            Color.clear.frame(width: 36, height: 36)
        }
        .padding()
    }

    @ViewBuilder private var content: some View {
        switch step {
        case .resolving:
            CenteredStatus(system: nil, title: "Resolving request…", subtitle: "Verifying who is asking.", showsSpinner: true)
        case .review:
            if let request { reviewStep(request) } else { EmptyView() }
        case .sharing:
            CenteredStatus(system: nil, title: "Sharing…", subtitle: "Sending the selected data to the verifier.", showsSpinner: true)
        case .shared:
            CenteredStatus(system: "checkmark.circle.fill", title: "Shared",
                           subtitle: "The verifier received the selected data.", tint: .green,
                           button: ("Done", onDone))
        case .failed:
            CenteredStatus(system: "exclamationmark.triangle.fill", title: "Couldn't share",
                           subtitle: errorMessage ?? "The presentation failed.", tint: .red,
                           button: ("Close", onCancel))
        }
    }

    // MARK: - Consent

    private func reviewStep(_ request: PresentationRequest) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    verifierCard(request.verifier)
                    trustSection(request.verifier)
                    if let purpose = purposeText(request.verifier.registration?.purpose) {
                        Section2(title: "Purpose") { NoteText(purpose) }
                    }
                    if let reg = request.verifier.registration, !reg.unregisteredClaims.isEmpty {
                        NoteText("⚠ This verifier is requesting attributes it isn't registered for.")
                    }
                    Section2(title: "You'll share") {
                        VStack(spacing: 12) {
                            ForEach(sortedQueries(request), id: \.queryId) { query in
                                queryCard(query)
                            }
                        }
                    }
                    Text("Required attributes are always shared; optional ones are off unless you turn them on. Everything else stays on this device.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                .padding()
            }
            Footer(primary: "Share", secondary: "Decline",
                   primaryEnabled: request.satisfiable,
                   onPrimary: { share() },
                   onSecondary: { confirmDecline = true })
        }
    }

    private func verifierCard(_ verifier: VerifierInfo) -> some View {
        HStack(spacing: 12) {
            Text(String(rpName(verifier).prefix(1)).uppercased())
                .font(.title3.weight(.bold)).foregroundStyle(.white)
                .frame(width: 42, height: 42)
                .background(Color.blue, in: RoundedRectangle(cornerRadius: 10))
            VStack(alignment: .leading, spacing: 2) {
                Text(rpName(verifier)).font(.body.weight(.semibold))
                Text(rpSubtitle(verifier)).font(.footnote).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            TrustBadge(ok: verifier.trusted, okText: "Verified", badText: "Unverified")
        }
        .padding()
        .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))
    }

    private func trustSection(_ verifier: VerifierInfo) -> some View {
        Section2(title: "Trust") {
            VStack(spacing: 0) {
                InfoRow(title: "Signed request", value: verifier.trusted ? "Verified" : "Not verified")
                if let reg = verifier.registration {
                    InfoRow(title: "Registration",
                            value: reg.attested ? "Verified by registrar" : reg.registrarVerified ? "Confirmed online" : "Self-declared")
                    if let statusValid = reg.statusValid {
                        InfoRow(title: "Registration status", value: statusValid ? "Valid" : "Revoked")
                    }
                } else {
                    InfoRow(title: "Registration", value: "None")
                }
            }
        }
    }

    private func queryCard(_ query: QueryPresentation) -> some View {
        let willShare = query.required || (included[query.queryId] ?? false)
        let selectedId = chosen[query.queryId]?.first ?? query.candidates.first?.credentialId
        let candidate = query.candidates.first { $0.credentialId == selectedId } ?? query.candidates.first
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(credTitle(selectedId)).font(.body.weight(.semibold))
                    Text(query.required ? "Required" : "Optional").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if !query.required {
                    Toggle("", isOn: Binding(
                        get: { included[query.queryId] ?? false },
                        set: { included[query.queryId] = $0 }
                    )).labelsHidden()
                }
            }
            if query.candidates.isEmpty {
                Text("No matching document in your wallet.").font(.footnote).foregroundStyle(.red)
            } else {
                if query.candidates.count > 1 {
                    ForEach(query.candidates, id: \.credentialId) { cand in
                        candidateRow(query, cand)
                    }
                }
                if let candidate {
                    Divider()
                    ForEach(Array(candidate.disclosedPaths.enumerated()), id: \.offset) { _, path in
                        InfoRow(title: claimLabel(path), value: willShare ? "Shared" : "Off")
                    }
                }
            }
        }
        .padding()
        .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))
    }

    private func candidateRow(_ query: QueryPresentation, _ candidate: PresentationCandidate) -> some View {
        let isSelected = (chosen[query.queryId] ?? []).contains(candidate.credentialId)
        let icon = query.multiple
            ? (isSelected ? "checkmark.square.fill" : "square")
            : (isSelected ? "largecircle.fill.circle" : "circle")
        return Button {
            toggleCandidate(query, candidate.credentialId)
        } label: {
            HStack {
                Image(systemName: icon).foregroundStyle(isSelected ? Color.accentColor : .secondary)
                Text(credTitle(candidate.credentialId))
                Spacer()
            }
        }
        .buttonStyle(.plain)
    }

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
                if ids.isEmpty { ids = [id] } // never below one (§6.1)
            } else {
                ids.append(id)
            }
            chosen[query.queryId] = ids
        } else {
            chosen[query.queryId] = [id]
        }
    }

    private func share() {
        // Biometric confirm-to-share is gated on onboarding (Phase 6); with biometrics not yet enabled the
        // android flow also skips the prompt, so we submit directly.
        step = .sharing
        session.respond(buildSelection())
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

    private func credTitle(_ id: CredentialId?) -> String {
        guard let id, let cred = credsById[id] else { return "Credential" }
        return cred.display?.name ?? cred.configurationId ?? prettyConfig(docTypeOrVct(cred.format))
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
