import SwiftUI
import Wallet
import WalletAPI

/// OpenID4VCI issuance flow — a 1:1 behavioral mirror of android `IssueScreen`. Steps:
/// Review → (TxCode) → Issuing → ReviewCredential → Success, or Failed. The auth-code grant opens a
/// browser (ASWebAuthenticationSession) and resumes via `completeAuthorization`.
struct IssueView: View {
    let offer: CredentialOffer
    /// "View in wallet" / success path — dismiss and reload the wallet lists.
    let onDone: () -> Void
    /// Cancelled or failed — dismiss without reload (an already-issued credential is deleted first).
    let onCancel: () -> Void

    @State private var step: IssueStep = .review
    @State private var preview: OfferPreview?
    @State private var previewLoading = true
    @State private var txCode = ""
    @State private var issued: Credential?
    @State private var errorMessage: String?
    @State private var confirmCancel = false

    private let wallet = DemoWallet.shared

    enum IssueStep { case review, txCode, issuing, reviewCredential, success, failed }

    private var configId: String { offer.credentialConfigurationIds.first ?? "" }

    var body: some View {
        VStack(spacing: 0) {
            if step == .review || step == .txCode || step == .reviewCredential {
                header
            }
            content
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.systemBackground).ignoresSafeArea())
        .task { await loadPreview() }
        .alert(cancelTitle, isPresented: $confirmCancel) {
            Button(step == .reviewCredential ? "Discard" : "Cancel adding", role: .destructive) {
                Task { await finishCancel() }
            }
            Button("Keep", role: .cancel) {}
        } message: {
            Text(cancelBody)
        }
        .interactiveDismissDisabled(true)
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            Button {
                back()
            } label: {
                Image(systemName: "chevron.left")
                    .font(.headline)
                    .frame(width: 36, height: 36)
                    .background(Color(.secondarySystemBackground), in: Circle())
            }
            Spacer()
            Text(step == .reviewCredential ? "Review credential" : "Add document")
                .font(.headline)
            Spacer()
            Color.clear.frame(width: 36, height: 36)
        }
        .padding()
    }

    // MARK: - Content per step

    @ViewBuilder private var content: some View {
        switch step {
        case .review: reviewStep
        case .txCode: txCodeStep
        case .issuing: CenteredStatus(system: nil, title: "Issuing…", subtitle: "Contacting the issuer and verifying the credential.", showsSpinner: true)
        case .reviewCredential: reviewCredentialStep
        case .success: successStep
        case .failed: failedStep
        }
    }

    private var reviewStep: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    DocumentHeaderCard(
                        badge: "NEW DOCUMENT",
                        format: primaryFormatLabel,
                        title: primaryTitle,
                        subtitle: hostOf(offer.credentialIssuer)
                    )

                    Section2(title: "Issuer") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(preview?.issuerDisplayName ?? hostOf(offer.credentialIssuer))
                                .font(.body.weight(.semibold))
                            Text(hostOf(offer.credentialIssuer))
                                .font(.footnote).foregroundStyle(.secondary)
                            if previewLoading {
                                ProgressView().controlSize(.small)
                            } else {
                                TrustBadge(ok: preview?.issuerRegistered == true, okText: "Registered", badText: "Unverified")
                            }
                        }
                    }

                    if let preview, !preview.issuerRegistered, !previewLoading {
                        NoteText("This issuer isn't on the EU trusted list. You can still add the document.")
                    }
                    if let preview, preview.credentials.count > 1 {
                        Section2(title: "You'll receive") {
                            ForEach(preview.credentials, id: \.configurationId) { c in
                                InfoRow(title: c.displayName ?? prettyConfig(c.configurationId), value: formatLabel(c.format))
                            }
                        }
                    }
                    if offer.requiresTxCode {
                        NoteText("This issuer will ask for a transaction code.")
                    }
                }
                .padding()
            }
            Footer(
                primary: "Continue",
                secondary: "Cancel",
                onPrimary: {
                    if offer.requiresTxCode { step = .txCode } else { Task { await runIssuance(code: nil) } }
                },
                onSecondary: { confirmCancel = true }
            )
        }
    }

    private var txCodeStep: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Enter the transaction code").font(.title3.weight(.semibold))
                    Text("The issuer sent you a code to authorise this credential.")
                        .foregroundStyle(.secondary)
                    if let desc = offer.txCode?.description {
                        NoteText(desc)
                    }
                    TextField("Transaction code", text: $txCode)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(offer.txCode?.inputMode == "text" ? .default : .numberPad)
                }
                .padding()
            }
            Footer(primary: "Issue", secondary: nil,
                   primaryEnabled: !txCode.trimmingCharacters(in: .whitespaces).isEmpty,
                   onPrimary: { Task { await runIssuance(code: txCode) } },
                   onSecondary: {})
        }
    }

    private var reviewCredentialStep: some View {
        VStack(spacing: 0) {
            if let issued {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        Text("Review the credential you received before saving it to your wallet.")
                            .foregroundStyle(.secondary)
                        CredentialCard(credential: issued)
                        Section2(title: "Trust") {
                            TrustBadge(ok: issued.issuer?.trusted == true, okText: "Issuer verified", badText: "Issuer unverified")
                        }
                        ClaimsList(credential: issued)
                    }
                    .padding()
                }
                Footer(primary: "Save to wallet", secondary: "Discard",
                       onPrimary: { step = .success },
                       onSecondary: { confirmCancel = true })
            } else {
                CenteredStatus(system: nil, title: "Finishing…", subtitle: "", showsSpinner: true)
            }
        }
    }

    private var successStep: some View {
        CenteredStatus(system: "checkmark.circle.fill", title: "Document added",
                       subtitle: "Saved securely on this device.", tint: .green,
                       button: ("View in wallet", onDone))
    }

    private var failedStep: some View {
        CenteredStatus(system: "exclamationmark.triangle.fill", title: "Couldn't add document",
                       subtitle: errorMessage ?? "The issuance failed.", tint: .red,
                       button: ("Close", onCancel))
    }

    // MARK: - Behavior

    private func loadPreview() async {
        previewLoading = true
        preview = try? await wallet.issuance.previewOffer(offer)
        previewLoading = false
    }

    /// Drives the SDK issuance session to a terminal state, mirroring android `runIssuance`'s collector.
    private func runIssuance(code: String?) async {
        step = .issuing
        let request = IssuanceRequest.fromOffer(offer, configurationId: configId, txCode: code)
        let session = wallet.issuance.start(request)
        for await state in session.states {
            switch state {
            case .txCodeRequired:
                if let code { session.submitTxCode(code) } // latent fallback; code is passed at start()
            case let .authorizationRequired(url):
                await authorize(url: url, session: session)
            case .completed:
                issued = try? await wallet.credentials.list().max { $0.createdAt < $1.createdAt }
                step = .reviewCredential
                return
            case .deferred:
                issued = nil
                step = .success
                return
            case let .failed(error):
                errorMessage = error.displayMessage
                step = .failed
                return
            case .preparing, .processing:
                break
            }
        }
    }

    private func authorize(url: String, session: IssuanceSession) async {
        guard let authURL = URL(string: url) else {
            session.cancel(); errorMessage = "Invalid authorization URL."; step = .failed; return
        }
        let coordinator = WebAuthCoordinator()
        do {
            let redirect = try await coordinator.authorize(url: authURL, callbackScheme: "eu.europa.ec.euidi")
            session.completeAuthorization(redirect)
        } catch {
            session.cancel()
            errorMessage = "Authorization was cancelled."
            step = .failed
        }
    }

    private func back() {
        switch step {
        case .txCode: step = .review
        case .review, .reviewCredential: confirmCancel = true
        case .success: onDone()
        case .failed: onCancel()
        case .issuing: break // blocked during the round-trip
        }
    }

    /// Confirmed discard/cancel: delete an already-issued credential (ReviewCredential) then dismiss.
    private func finishCancel() async {
        if step == .reviewCredential, let issued {
            try? await wallet.credentials.delete(issued.id)
        }
        onCancel()
    }

    private var cancelTitle: String {
        step == .reviewCredential ? "Discard this credential?" : "Cancel adding this document?"
    }
    private var cancelBody: String {
        step == .reviewCredential ? "It won't be saved to your wallet." : "You'll need to start over to add it."
    }

    private var primaryFormatLabel: String { formatLabel(preview?.credentials.first?.format ?? "") }
    private var primaryTitle: String {
        preview?.credentials.first?.displayName ?? prettyConfig(configId)
    }
}

// MARK: - Reusable pieces

struct DocumentHeaderCard: View {
    let badge: String
    let format: String
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(badge).font(.caption2.weight(.bold)).foregroundStyle(.white.opacity(0.85))
                Spacer()
                Text(format).font(.caption2.weight(.semibold))
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(.white.opacity(0.2), in: Capsule())
                    .foregroundStyle(.white)
            }
            Spacer(minLength: 24)
            Text(title).font(.title3.weight(.bold)).foregroundStyle(.white)
            Text(subtitle).font(.footnote).foregroundStyle(.white.opacity(0.85))
        }
        .padding()
        .frame(maxWidth: .infinity, minHeight: 150, alignment: .leading)
        .background(LinearGradient(colors: [.blue, .indigo], startPoint: .topLeading, endPoint: .bottomTrailing))
        .clipShape(RoundedRectangle(cornerRadius: 18))
    }
}

private struct CredentialCard: View {
    let credential: Credential
    var body: some View {
        DocumentHeaderCard(
            badge: "CREDENTIAL",
            format: formatLabel(formatString(credential.format)),
            title: credential.display?.name ?? credential.configurationId ?? prettyConfig(docTypeOrVct(credential.format)),
            subtitle: credential.issuer?.displayName ?? credential.issuer?.url ?? ""
        )
    }
}

func formatString(_ format: CredentialFormat) -> String {
    switch format {
    case .msoMdoc: return "mso_mdoc"
    case .sdJwtVc: return "sd-jwt-vc"
    }
}

func docTypeOrVct(_ format: CredentialFormat) -> String {
    switch format {
    case let .msoMdoc(docType): return docType
    case let .sdJwtVc(vct): return vct
    }
}

struct Section2<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title.uppercased()).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct InfoRow: View {
    let title: String
    let value: String
    var body: some View {
        HStack {
            Text(title)
            Spacer()
            Text(value).foregroundStyle(.secondary)
        }
        .font(.subheadline)
        .padding(.vertical, 4)
    }
}

struct NoteText: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(.footnote).foregroundStyle(.secondary)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct TrustBadge: View {
    let ok: Bool
    let okText: String
    let badText: String
    var body: some View {
        Label(ok ? okText : badText, systemImage: ok ? "checkmark.seal.fill" : "exclamationmark.shield.fill")
            .font(.caption.weight(.semibold))
            .foregroundStyle(ok ? .green : .orange)
    }
}

private struct ClaimsList: View {
    let credential: Credential
    var body: some View {
        if case let .issued(claims, _, _) = credential.lifecycle, !claims.isEmpty {
            Section2(title: "Details") {
                VStack(spacing: 0) {
                    ForEach(Array(claims.enumerated()), id: \.offset) { _, claim in
                        InfoRow(title: claim.path.last ?? claim.path.joined(separator: "."),
                                value: claim.value.display())
                    }
                }
            }
        }
    }
}

struct Footer: View {
    let primary: String
    let secondary: String?
    var primaryEnabled: Bool = true
    let onPrimary: () -> Void
    let onSecondary: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            Button(action: onPrimary) {
                Text(primary).frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!primaryEnabled)

            if let secondary {
                Button(role: .cancel, action: onSecondary) {
                    Text(secondary).frame(maxWidth: .infinity)
                }
                .controlSize(.large)
            }
        }
        .padding()
        .background(.bar)
    }
}

struct CenteredStatus: View {
    var system: String?
    let title: String
    let subtitle: String
    var showsSpinner = false
    var tint: Color = .accentColor
    var button: (String, () -> Void)?

    var body: some View {
        VStack(spacing: 16) {
            Spacer()
            if showsSpinner {
                ProgressView().controlSize(.large)
            } else if let system {
                Image(systemName: system).font(.system(size: 64)).foregroundStyle(tint)
            }
            Text(title).font(.title2.weight(.bold))
            if !subtitle.isEmpty {
                Text(subtitle).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            Spacer()
            if let button {
                Button(action: button.1) { Text(button.0).frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).controlSize(.large).padding()
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Helpers (mirror android formatLabel / prettyConfig / hostOf)

func formatLabel(_ format: String) -> String {
    let f = format.lowercased()
    if f.contains("sd-jwt") || f.contains("sd_jwt") || f.contains("dc+sd") { return "SD-JWT VC" }
    if f.contains("mdoc") || f.contains("mso") { return "mdoc" }
    return format.isEmpty ? "Credential" : format
}

func prettyConfig(_ id: String) -> String {
    let last = id.split(whereSeparator: { $0 == "/" || $0 == ":" }).last.map(String.init) ?? id
    let spaced = last.replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: ".", with: " ")
    let trimmed = spaced.trimmingCharacters(in: .whitespaces)
    guard let first = trimmed.first else { return "Credential" }
    return first.uppercased() + trimmed.dropFirst()
}

func hostOf(_ url: String) -> String {
    URL(string: url)?.host ?? url
}

extension IssuanceError {
    var displayMessage: String {
        switch self {
        case let .invalidOffer(m): return m
        case let .authorizationFailed(_, m): return m
        case let .credentialRequestFailed(m): return m
        case let .unexpected(m): return m
        }
    }
}
