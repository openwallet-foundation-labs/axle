import AppleProximity
import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit
import Wallet
import WalletAPI // ProximityTransport, CredentialId

/// Holder-side ISO 18013-5 proximity presentation over BLE — a 1:1 mirror of android `ProximityHolderDialog`
/// (top bar "Present in person" → engagement QR → consent → result). Advertises/connects per the Settings
/// "Bluetooth role", drives `ProximityService.present`, and requires biometric confirmation before sharing.
struct ProximityHolderView: View {
    let onClose: () -> Void

    private let wallet = DemoWallet.shared
    @State private var phase: Phase = .starting
    @State private var qr: UIImage?
    @State private var request: ProximityRequest?
    @State private var chosen: [String: CredentialId] = [:]
    @State private var credsById: [CredentialId: Credential] = [:]
    @State private var errorMessage: String?
    @State private var transport: (any ProximityTransport)?
    @State private var session: ProximitySession?

    enum Phase { case starting, engaging, consent, sending, done, declined, failed }

    var body: some View {
        content
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 20)
            .background(WalletTheme.screen.ignoresSafeArea())
            .task { await run() }
            .onDisappear { teardown() }
    }

    @ViewBuilder private var content: some View {
        switch phase {
        case .starting:
            FlowLoading(title: "Starting Bluetooth…", subtitle: "Preparing in-person sharing.")
        case .engaging:
            interactive { engagingBody }
        case .consent:
            if let request { interactive { consentBody(request) } }
        case .sending:
            FlowLoading(title: "Sharing…", subtitle: "Sending your document to the reader.")
        case .done:
            FlowResult(kind: .success, title: "Shared", subtitle: "The reader received your document.", buttonTitle: "Done", onButton: onClose)
        case .declined:
            FlowResult(kind: .failure, title: "Declined", subtitle: "Nothing was shared.", buttonTitle: "Close", onButton: onClose)
        case .failed:
            FlowResult(kind: .failure, title: "Couldn't share", subtitle: errorMessage ?? "The proximity session failed.", buttonTitle: "Close", onButton: onClose)
        }
    }

    /// A top bar ("Present in person" + back) with the phase content below (android `ProximityHolderDialog`).
    private func interactive<C: View>(@ViewBuilder content: () -> C) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                CircleIconButton(system: "chevron.left") { cancel() }
                Text("Present in person").font(WalletFont.titleMedium).foregroundStyle(WalletTheme.ink)
                Spacer()
            }
            Spacer().frame(height: 16)
            content()
        }
    }

    private var engagingBody: some View {
        VStack(spacing: 16) {
            Spacer()
            if let qr {
                Image(uiImage: qr)
                    .interpolation(.none).resizable().scaledToFit()
                    .frame(width: 240, height: 240)
                    .frame(width: 280, height: 280)
                    .background(WalletTheme.card, in: RoundedRectangle(cornerRadius: 16))
                    .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(WalletTheme.cardBorder, lineWidth: 1))
            } else {
                ProgressView().tint(WalletTheme.brand)
            }
            Text("Show this to the reader to connect.").font(WalletFont.bodyMedium).foregroundStyle(WalletTheme.inkBody)
            HStack(spacing: 8) {
                ProgressView().controlSize(.small).tint(WalletTheme.brand)
                Text("Waiting for the reader…").font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func consentBody(_ request: ProximityRequest) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Reader
                    WalletCard {
                        HStack(spacing: 12) {
                            Text(String((request.reader.commonName ?? "R").prefix(1)).uppercased())
                                .font(WalletFont.titleMedium).foregroundStyle(.white)
                                .frame(width: 42, height: 42)
                                .background(WalletTheme.ink, in: RoundedRectangle(cornerRadius: 12))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(request.reader.commonName ?? "In-person reader").font(WalletFont.titleSmall).foregroundStyle(WalletTheme.ink)
                                Text("ISO 18013-5 · in person").font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
                            }
                            Spacer()
                            TrustPill(trusted: request.reader.trusted, trustedText: "Verified", untrustedText: "Unverified")
                        }
                    }
                    // Trust (reader authentication only — no OpenID4VP registration in proximity)
                    SectionLabel("Trust")
                    WalletCard(padding: .flush) {
                        TrustRow(label: "Reader authentication", value: request.reader.trusted ? "Verified" : "Not verified", ok: request.reader.trusted)
                    }
                    // Shared attributes per requested document
                    SectionLabel("You'll share")
                    ForEach(Array(request.documents.enumerated()), id: \.offset) { _, doc in
                        docCard(doc)
                    }
                    FlowNote("Only the shown attributes are shared. Your full documents never leave this device.")
                }
            }
            FlowFooter(primaryTitle: "Share", primaryEnabled: request.satisfiable,
                       onPrimary: { confirmAndShare() }, secondaryTitle: "Decline", onSecondary: { session?.decline() })
        }
    }

    private func docCard(_ doc: RequestedDocumentView) -> some View {
        let selectedId = chosen[doc.docType] ?? doc.candidates.first
        let cred = selectedId.flatMap { credsById[$0] }
        let requestedPaths = doc.requestedElements.flatMap { ns, els in els.map { [ns, $0] } }
        let shared = sharedValues(cred, requestedPaths)

        return WalletCard(padding: .flush) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(cred.map { credTitle($0) } ?? docTypeLabel(doc.docType))
                        .font(WalletFont.titleSmall).foregroundStyle(cred != nil ? WalletTheme.ink : WalletTheme.inkFaint)
                    Text(cred != nil ? "Required" : "No matching document")
                        .font(WalletFont.bodySmall).foregroundStyle(cred != nil ? WalletTheme.inkMuted : WalletTheme.danger)
                }
                Spacer()
            }
            .padding(.horizontal, 16).padding(.vertical, 12)

            if doc.candidates.count > 1 {
                cardDivider
                groupHeader("Choose a document")
                ForEach(doc.candidates, id: \.value) { candId in
                    candidateCard(doc, candId, checked: candId == selectedId)
                }
                Spacer().frame(height: 6)
            }

            cardDivider
            groupHeader("Shared")
            if shared.isEmpty {
                Text("No matching attributes in this document.")
                    .font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.bottom, 12)
            } else {
                ForEach(Array(shared.enumerated()), id: \.offset) { _, entry in
                    if isImageClaim(entry.path), let image = claimImage(base64: entry.value) {
                        ClaimImageRow(label: elementLabel(entry.path), image: image)
                    } else {
                        WalletInfoRow(label: elementLabel(entry.path), value: entry.value)
                    }
                }
            }
        }
    }

    private func candidateCard(_ doc: RequestedDocumentView, _ candId: CredentialId, checked: Bool) -> some View {
        let cred = credsById[candId]
        let requestedPaths = doc.requestedElements.flatMap { ns, els in els.map { [ns, $0] } }
        let subtitle = sharedValues(cred, requestedPaths.filter { !isImageClaim($0) }).prefix(2).map { $0.value }.joined(separator: " · ")
        let shape = RoundedRectangle(cornerRadius: 12)
        return Button {
            chosen[doc.docType] = candId
        } label: {
            HStack(spacing: 12) {
                if let cred { DocTile(glyph: credGlyph(cred), colors: credGradient(cred), size: 40) }
                VStack(alignment: .leading, spacing: 2) {
                    Text(cred.map { credTitle($0) } ?? "Credential").font(WalletFont.titleSmall).foregroundStyle(WalletTheme.ink)
                    if !subtitle.isEmpty {
                        Text(subtitle).font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted).lineLimit(1)
                    }
                }
                Spacer()
                ZStack {
                    Circle().fill(checked ? WalletTheme.brand : .clear)
                    Circle().strokeBorder(checked ? WalletTheme.brand : WalletTheme.cardBorderStrong, lineWidth: 2)
                    if checked { Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(.white) }
                }.frame(width: 20, height: 20)
            }
            .padding(10)
            .background(checked ? WalletTheme.brand.opacity(0.06) : WalletTheme.card, in: shape)
            .overlay(shape.strokeBorder(checked ? WalletTheme.brand : WalletTheme.cardBorder, lineWidth: checked ? 1.5 : 1))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 12).padding(.vertical, 5)
    }

    private func groupHeader(_ text: String) -> some View {
        Text(text.uppercased())
            .font(WalletFont.labelSmall).tracking(0.6).foregroundStyle(WalletTheme.inkFaint)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16).padding(.top, 10).padding(.bottom, 4)
    }

    private var cardDivider: some View { Rectangle().fill(WalletTheme.divider).frame(height: 1) }

    /// The requested element paths the chosen credential actually holds, with their rendered values
    /// (ISO 18013-5 partial disclosure — absent elements are simply omitted).
    private func sharedValues(_ cred: Credential?, _ requestedPaths: [[String]]) -> [(path: [String], value: String)] {
        guard let cred, case let .issued(claims, _, _) = cred.lifecycle else { return [] }
        var byPath: [[String]: String] = [:]
        for claim in claims { byPath[claim.path] = claim.value.display() }
        return requestedPaths.compactMap { path in byPath[path].map { (path, $0) } }
    }

    private func elementLabel(_ path: [String]) -> String {
        let segment = path.count > 1 ? path[path.count - 1] : (path.first ?? "")
        let spaced = segment.replacingOccurrences(of: "_", with: " ")
        return spaced.prefix(1).uppercased() + spaced.dropFirst()
    }

    private func docTypeLabel(_ docType: String) -> String {
        let d = docType.lowercased()
        if d.contains("pid") { return "Personal ID" }
        if d.contains("mdl") || d.contains("18013.5.1") { return "Mobile Driving Licence" }
        let tail = docType.split(separator: ".").last.map(String.init) ?? docType
        let spaced = tail.replacingOccurrences(of: "_", with: " ")
        return spaced.prefix(1).uppercased() + spaced.dropFirst()
    }

    // MARK: - Behavior

    private var bleLogger: @Sendable (String) -> Void {
        { m in Task { @MainActor in LogStore.shared.log("BLE ▸ \(m)") } }
    }

    /// Biometric confirm-to-share (android `PresentScreen.share`), gated on the enabled biometric.
    private func confirmAndShare() {
        let selection = ProximitySelection(chosen: chosen)
        if WalletSecurity.biometricEnabled && BiometricAuth.canUse() {
            BiometricAuth.prompt(reason: "Confirm to share in person", onSuccess: { session?.respond(selection) })
        } else {
            session?.respond(selection)
        }
    }

    private func run() async {
        guard transport == nil else { return }
        let list = (try? await wallet.credentials.list()) ?? []
        credsById = Dictionary(list.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })

        let central = UserDefaults.standard.bool(forKey: "bleCentral")
        let session: ProximitySession
        var centralHolder: BleCentralTransport?
        if central {
            let t = BleCentralTransport.holder(logger: bleLogger)
            transport = t
            centralHolder = t
            session = wallet.proximity.present(t)
        } else {
            let t = BlePeripheralTransport.holder(logger: bleLogger)
            transport = t
            do {
                try await t.start()
            } catch {
                errorMessage = String(describing: error)
                phase = .failed
                return
            }
            session = wallet.proximity.present(t)
        }
        self.session = session
        for await state in session.states {
            switch state {
            case .generatingEngagement:
                phase = .starting
            case let .engagementReady(engagement, _):
                centralHolder?.armIdent(engagement: engagement)
                qr = Self.qrImage(mdocQR(engagement))
                phase = .engaging
                LogStore.shared.log("present: QR ready — waiting for reader")
            case let .requestReceived(req):
                request = req
                chosen = Dictionary(uniqueKeysWithValues: req.documents.compactMap { doc in
                    doc.candidates.first.map { (doc.docType, $0) }
                })
                phase = .consent
                LogStore.shared.log("present: reader request received")
            case .submitting:
                phase = .sending
            case .completed:
                phase = .done
                LogStore.shared.log("present: ✅ shared")
                return
            case .declined:
                phase = .declined
                return
            case let .failed(error):
                errorMessage = String(describing: error)
                phase = .failed
                LogStore.shared.log("present: ❌ \(error)")
                return
            }
        }
    }

    private func cancel() {
        session?.cancel()
        teardown()
        onClose()
    }

    private func teardown() {
        session?.cancel()
        if let transport { Task { await transport.close() } }
    }

    /// ISO 18013-5 QR payload: `mdoc:` + base64url(DeviceEngagement).
    private func mdocQR(_ engagement: [UInt8]) -> String {
        let b64 = Data(engagement).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "mdoc:" + b64
    }

    private static func qrImage(_ string: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)) else { return nil }
        let context = CIContext()
        guard let cg = context.createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
