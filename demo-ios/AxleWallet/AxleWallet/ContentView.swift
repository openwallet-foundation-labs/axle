import AppleCore
import SwiftUI
import UIKit
import Wallet
import WalletTestKit

/// Phase-3 wallet home: the Documents list plus the entry points that drive issuance/presentation —
/// QR scan, pasted/opened deep links — routed through `WalletModel` exactly like android `WalletRoot`.
/// A debug action still qualifies the Secure Enclave / Keychain adapters against the SDK contract suites.
struct ContentView: View {
    @State private var model = WalletModel()
    @State private var credentials: [Credential] = []
    @State private var loadError: String?
    @State private var isLoading = true
    @State private var contractResult: String?
    @State private var isTesting = false
    @State private var showScanner = false

    var body: some View {
        NavigationStack {
            documentsList
                .navigationTitle("Documents")
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Button {
                            Task { await runContractTests() }
                        } label: {
                            Image(systemName: "checkmark.seal")
                        }
                        .disabled(isTesting)
                        .accessibilityLabel("Test adapters")
                    }
                    ToolbarItem(placement: .topBarTrailing) {
                        Menu {
                            Button {
                                showScanner = true
                            } label: {
                                Label("Scan QR", systemImage: "qrcode.viewfinder")
                            }
                            Button {
                                if let text = UIPasteboard.general.string {
                                    model.handleURI(text, source: "Pasted")
                                }
                            } label: {
                                Label("Paste offer or request", systemImage: "doc.on.clipboard")
                            }
                        } label: {
                            Image(systemName: "plus")
                        }
                    }
                }
                .alert("Adapter check", isPresented: showingResult) {
                    Button("OK", role: .cancel) { contractResult = nil }
                } message: {
                    Text(contractResult ?? "")
                }
                .sheet(isPresented: $showScanner) {
                    ScannerSheet { model.handleURI($0, source: "Scanned") }
                }
        }
        .task(id: model.reloadToken) { await load() }
        .overlay {
            if let busy = model.busy { BusyOverlay(message: busy) }
        }
        .fullScreenCover(isPresented: issuingBinding) {
            if let offer = model.issuingOffer {
                IssueView(
                    offer: offer,
                    onDone: { model.finishIssuance(reload: true) },
                    onCancel: { model.finishIssuance(reload: false) }
                )
            }
        }
        .fullScreenCover(isPresented: presentingBinding) {
            if let session = model.presentingSession {
                PresentView(
                    session: session,
                    onDone: { model.finishPresentation(reload: true) },
                    onCancel: { model.finishPresentation(reload: false) }
                )
            }
        }
        .onOpenURL { model.handleURI($0.absoluteString, source: "Opened link") }
    }

    @ViewBuilder private var documentsList: some View {
        if isLoading {
            ProgressView("Loading…")
        } else if let loadError {
            ContentUnavailableView(
                "Couldn't load",
                systemImage: "exclamationmark.triangle",
                description: Text(loadError)
            )
        } else if credentials.isEmpty {
            ContentUnavailableView {
                Label("No documents yet", systemImage: "doc.text")
            } description: {
                Text("Scan or paste an issuer offer to add your first document.")
            } actions: {
                Button("Scan QR") { showScanner = true }
            }
        } else {
            List(credentials, id: \.id) { credential in
                DocumentRow(credential: credential)
            }
        }
    }

    private var issuingBinding: Binding<Bool> {
        Binding(get: { model.issuingOffer != nil }, set: { if !$0 { model.issuingOffer = nil } })
    }

    private var presentingBinding: Binding<Bool> {
        Binding(get: { model.presentingSession != nil }, set: { if !$0 { model.presentingSession = nil } })
    }

    private var showingResult: Binding<Bool> {
        Binding(get: { contractResult != nil }, set: { if !$0 { contractResult = nil } })
    }

    private func load() async {
        isLoading = true
        do {
            credentials = try await DemoWallet.shared.credentials.list()
            loadError = nil
        } catch {
            loadError = String(describing: error)
        }
        isLoading = false
    }

    /// On-device adapter qualification: "adapter qualification = passing the shared contract suite."
    private func runContractTests() async {
        isTesting = true
        defer { isTesting = false }
        do {
            try await SecureAreaContract.verify(SecureEnclaveSecureArea())
            try await StorageDriverContract.verify(KeychainStorageDriver())
            contractResult = "✅ Secure Enclave + Keychain adapters pass the SDK contract suites."
        } catch {
            contractResult = "❌ \(error)"
        }
    }
}

private struct DocumentRow: View {
    let credential: Credential

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline)
            if let subtitle {
                Text(subtitle).font(.subheadline).foregroundStyle(.secondary)
            }
            Text("\(claimCount) claims").font(.caption).foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
    }

    private var title: String {
        credential.display?.name ?? credential.configurationId ?? "Credential"
    }

    private var subtitle: String? {
        credential.issuer?.displayName ?? credential.issuer?.url
    }

    private var claimCount: Int {
        if case let .issued(claims, _, _) = credential.lifecycle { return claims.count }
        return 0
    }
}

private struct BusyOverlay: View {
    let message: String
    var body: some View {
        ZStack {
            Color.black.opacity(0.35).ignoresSafeArea()
            VStack(spacing: 12) {
                ProgressView()
                Text(message).font(.callout)
            }
            .padding(24)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
        }
        .transition(.opacity)
    }
}

#Preview {
    ContentView()
}
