import SwiftUI
import Wallet

/// Phase-1 milestone screen: lists stored credentials via `wallet.credentials.list()`. Proves the SDK
/// compiles and runs on iOS. The full Documents/Home/Activity/Settings UI (mirroring android `demo`)
/// arrives in Phase 3.
struct ContentView: View {
    @State private var credentials: [Credential] = []
    @State private var loadError: String?
    @State private var isLoading = true

    var body: some View {
        NavigationStack {
            Group {
                if isLoading {
                    ProgressView("Loading…")
                } else if let loadError {
                    ContentUnavailableView(
                        "Couldn't load",
                        systemImage: "exclamationmark.triangle",
                        description: Text(loadError)
                    )
                } else if credentials.isEmpty {
                    ContentUnavailableView(
                        "No documents yet",
                        systemImage: "doc.text",
                        description: Text("Issued credentials will appear here.")
                    )
                } else {
                    List(credentials, id: \.id) { credential in
                        DocumentRow(credential: credential)
                    }
                }
            }
            .navigationTitle("Documents")
        }
        .task { await load() }
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

#Preview {
    ContentView()
}
