import SwiftUI
import Wallet

/// The document detail — gradient card, trust panel, and the credential's claims (sensitive values masked
/// behind a reveal toggle) plus admin metadata, built from the shared `CredentialContent` pieces so it
/// matches the issuance review. Mirrors android `DocumentDetailScreen`. Proximity present (mDL) uses BLE.
struct DocumentDetailView: View {
    let cred: Credential

    @Environment(WalletModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var reveal = false
    @State private var confirmDelete = false
    @State private var showProximity = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                topBar
                CredentialGradientCard(cred: cred)
                SectionLabel("Trust")
                CredentialTrustCard(cred: cred)
                CredentialClaimSections(cred: cred, reveal: reveal)

                // Proximity is the one genuinely holder-initiated present action — show *this* mDL in person
                // over BLE. Cross-device / QR presentation is request-driven (scan a verifier from Home).
                if credIsMdoc(cred) {
                    Button { showProximity = true } label: {
                        Label("Present via proximity", systemImage: "dot.radiowaves.left.and.right")
                            .font(WalletFont.labelLarge)
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity).padding(.vertical, 15)
                            .background(WalletTheme.brand, in: RoundedRectangle(cornerRadius: 14))
                    }
                    .buttonStyle(.plain).padding(.top, 4)
                }
            }
            .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 28)
        }
        .walletScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .alert("Delete \(credTitle(cred))?", isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { Task { await model.delete(cred.id); dismiss() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes the credential from this device. You can be issued a new one later.")
        }
        .fullScreenCover(isPresented: $showProximity) {
            ProximityHolderView { showProximity = false }
        }
    }

    private var topBar: some View {
        HStack(spacing: 8) {
            CircleIconButton(system: "chevron.left") { dismiss() }
            Text(credTitle(cred)).font(WalletFont.titleMedium).foregroundStyle(WalletTheme.ink)
            Spacer()
            if hasSensitiveClaims(cred) {
                CircleIconButton(system: reveal ? "eye.slash" : "eye") { reveal.toggle() }
            }
            Menu {
                Button(role: .destructive) { confirmDelete = true } label: {
                    Label("Delete document", systemImage: "trash")
                }
            } label: {
                Image(systemName: "ellipsis")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(WalletTheme.ink)
                    .frame(width: 36, height: 36)
                    .background(WalletTheme.card, in: Circle())
                    .overlay(Circle().strokeBorder(WalletTheme.cardBorder, lineWidth: 1))
            }
        }
    }
}
