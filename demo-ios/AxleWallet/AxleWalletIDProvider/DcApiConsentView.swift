import AppleDcApi
import IdentityDocumentServices
import IdentityDocumentServicesUI
import SwiftUI

/// The consent screen the OS presents inside the provider extension for an `org-iso-mdoc` DC API request. It is
/// our own SwiftUI, so it mirrors the app's in-person share screen (android `ProximityHolderDialog` / our
/// `ProximityHolderView`): a reader card with the verified requester identity, a trust row, and the attributes
/// that will be shared, over a Share / Cancel footer.
///
/// Apple's flow is two-phase: pre-consent we only have the OS-parsed, typed `context.request` (what to show); the
/// raw `DeviceRequest` bytes we sign arrive later inside `sendResponse`. On "Share" the response is produced via
/// `DcApiResponder` (auto-disclosing `requested ∩ held`); the reader identity is validated against the reader
/// anchors the app cached into the shared App Group.
struct DcApiConsentView: View {
    let context: ISO18013MobileDocumentRequestContext
    private let documents: [RequestedDoc]
    private let reader: DcApiReaderTrust.Reader

    @State private var phase: Phase = .review
    private enum Phase: Equatable { case review, sharing, failed(String) }

    init(context: ISO18013MobileDocumentRequestContext) {
        self.context = context
        self.documents = Self.parse(context.request)
        let chain = context.request.requestAuthentications.first?.authenticationCertificateChain ?? []
        self.reader = DcApiReaderTrust.evaluate(chain: chain)
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Identity request").font(WalletFont.titleLarge).foregroundStyle(WalletTheme.ink)
                        .padding(.top, 4)

                    readerCard

                    SectionLabel("Trust")
                    WalletCard(padding: .flush) {
                        TrustRow(label: "Reader authentication",
                                 value: reader.verified ? "Verified" : "Not verified", ok: reader.verified)
                    }

                    SectionLabel("You'll share")
                    if documents.isEmpty {
                        WalletCard { Text("This request did not ask for any documents.").font(WalletFont.bodyMedium).foregroundStyle(WalletTheme.inkMuted) }
                    } else {
                        ForEach(documents) { docCard($0) }
                    }

                    FlowNote("Only the shown attributes are shared. Your full documents never leave this device.")

                    if case let .failed(message) = phase {
                        Text(message).font(WalletFont.bodySmall).foregroundStyle(WalletTheme.danger)
                    }
                }
                .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 8)
            }
            footer
        }
        .background(WalletTheme.screen.ignoresSafeArea())
    }

    private var readerCard: some View {
        WalletCard {
            HStack(spacing: 12) {
                Text(readerInitial)
                    .font(WalletFont.titleMedium).foregroundStyle(.white)
                    .frame(width: 42, height: 42)
                    .background(WalletTheme.ink, in: RoundedRectangle(cornerRadius: 12))
                VStack(alignment: .leading, spacing: 2) {
                    Text(readerTitle).font(WalletFont.titleSmall).foregroundStyle(WalletTheme.ink).lineLimit(1)
                    Text(readerSubtitle).font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted).lineLimit(1)
                }
                Spacer(minLength: 8)
                TrustPill(trusted: reader.verified)
            }
        }
    }

    private func docCard(_ doc: RequestedDoc) -> some View {
        WalletCard(padding: .flush) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(docTitle(doc.docType)).font(WalletFont.titleSmall).foregroundStyle(WalletTheme.ink)
                    Text("Requested").font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
                }
                Spacer()
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            Rectangle().fill(WalletTheme.divider).frame(height: 1)
            groupHeader("Shared")
            if doc.claims.isEmpty {
                Text("No attributes requested from this document.")
                    .font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.bottom, 12)
            } else {
                ForEach(Array(doc.claims.enumerated()), id: \.element.id) { index, claim in
                    SharedAttributeRow(label: humanize(claim.element), last: index == doc.claims.count - 1)
                }
            }
        }
    }

    private func groupHeader(_ text: String) -> some View {
        Text(text.uppercased())
            .font(WalletFont.labelSmall).tracking(0.6).foregroundStyle(WalletTheme.inkFaint)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16).padding(.top, 10).padding(.bottom, 4)
    }

    private var footer: some View {
        HStack(spacing: 10) {
            SecondaryButton(title: "Cancel") { context.cancel() }.frame(maxWidth: .infinity)
            Button(action: share) {
                Group {
                    if phase == .sharing { ProgressView().tint(.white) }
                    else { Text("Share").font(WalletFont.labelLarge).foregroundStyle(.white) }
                }
                .frame(maxWidth: .infinity).padding(.vertical, 15)
                .background(documents.isEmpty ? WalletTheme.cardBorderStrong : WalletTheme.brand, in: RoundedRectangle(cornerRadius: 14))
            }
            .buttonStyle(.plain)
            .disabled(phase == .sharing || documents.isEmpty)
            .frame(maxWidth: .infinity)
        }
        .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 16)
        .background(WalletTheme.screen)
    }

    private func share() {
        // Hoist to locals so the @Sendable response closure captures Sendable values, not the MainActor view.
        let context = self.context
        let wallet = ExtensionWallet.shared
        // What we displayed: docType → namespace → element identifiers. The response path refuses to sign a raw
        // request that asks for anything outside this (Apple's two-phase API — displayed vs signed are separate).
        let shown = documents.reduce(into: [String: [String: Set<String>]]()) { acc, doc in
            var namespaces = acc[doc.docType] ?? [:]
            for claim in doc.claims { namespaces[claim.namespace, default: []].insert(claim.element) }
            acc[doc.docType] = namespaces
        }
        let reason = "Confirm to share your ID with \(readerTitle)"
        Task {
            // Biometric confirm before sharing, matching the app's remote / in-person present flows.
            if ExtensionBiometrics.required, await !ExtensionBiometrics.authenticate(reason: reason) {
                phase = .failed("Authentication cancelled")
                return
            }
            phase = .sharing
            do {
                try await context.sendResponse { rawRequest in
                    let data = try await DcApiResponder.responseData(
                        rawRequestData: rawRequest.requestData,
                        origin: context.requestingWebsiteOrigin,
                        wallet: wallet,
                        shown: shown)
                    return ISO18013MobileDocumentResponse(responseData: data)
                }
                // The platform dismisses the extension on success.
            } catch {
                phase = .failed(String(describing: error))
            }
        }
    }

    // MARK: - Reader display

    private var readerTitle: String { reader.commonName ?? originHost ?? "Online reader" }
    private var readerSubtitle: String {
        if reader.commonName != nil, let originHost { return "ISO 18013-7 · \(originHost)" }
        return "ISO 18013-7 · online"
    }
    private var readerInitial: String { String((reader.commonName ?? originHost ?? "R").prefix(1)).uppercased() }
    private var originHost: String? { context.requestingWebsiteOrigin?.host ?? context.requestingWebsiteOrigin?.absoluteString }

    // MARK: - Request model (built once from the OS-parsed request)

    private struct RequestedDoc: Identifiable {
        let docType: String
        let claims: [Claim]
        var id: String { docType }
        struct Claim: Identifiable {
            let namespace: String; let element: String; let retaining: Bool
            var id: String { "\(namespace).\(element)" }
        }
    }

    private static func parse(_ request: ISO18013MobileDocumentRequest) -> [RequestedDoc] {
        request.presentmentRequests.flatMap { presentment in
            presentment.documentRequestSets.flatMap { $0.requests }.map { req in
                let claims = req.namespaces
                    .flatMap { ns, elements in elements.map { RequestedDoc.Claim(namespace: ns, element: $0.key, retaining: $0.value.isRetaining) } }
                    .sorted { $0.element < $1.element }
                return RequestedDoc(docType: req.documentType, claims: claims)
            }
        }
    }

    private func docTitle(_ docType: String) -> String {
        let d = docType.lowercased()
        if d.contains("photoid") { return "Photo ID" }
        if d.contains("pid") { return "Personal ID" }
        if d.contains("mdl") || d.contains("18013.5.1") { return "Mobile Driving Licence" }
        if d.contains(".av.") { return "Age verification" }
        let tail = docType.split(separator: ".").last.map(String.init) ?? docType
        let spaced = tail.replacingOccurrences(of: "_", with: " ")
        return spaced.prefix(1).uppercased() + spaced.dropFirst()
    }

    private func humanize(_ element: String) -> String {
        let spaced = element.replacingOccurrences(of: "_", with: " ")
        return spaced.prefix(1).uppercased() + spaced.dropFirst()
    }
}
