import SwiftUI

/// The wallet brand palette — a 1:1 port of android `ui/theme/Color.kt` (`WalletColors` + `DocGradients`
/// + the dark debug console). The design is a fixed light theme; `WalletHome` pins `.light` so these
/// tokens read the same as on android. Semantic tokens the design leans on (text tiers, trust greens,
/// per-document gradients) that don't map onto system colors live here.
enum WalletTheme {
    // Brand blue
    static let brand = Color(hex: 0x2555DB)
    static let brandPressed = Color(hex: 0x1D47BC)
    static let brandSoftBg = Color(hex: 0xEAF1FF)
    static let brandSoftBorder = Color(hex: 0xCBDBFA)

    // Neutrals
    static let canvas = Color(hex: 0xE9EBF1)
    static let screen = Color(hex: 0xF4F5F9)
    static let card = Color.white
    static let cardBorder = Color(hex: 0xE9EBF1)
    static let cardBorderStrong = Color(hex: 0xE4E7EC)
    static let divider = Color(hex: 0xF0F2F7)

    // Text tiers
    static let ink = Color(hex: 0x101828)
    static let inkBody = Color(hex: 0x344054)
    static let inkMuted = Color(hex: 0x667085)
    static let inkFaint = Color(hex: 0x98A2B3)

    // Trust / success
    static let trust = Color(hex: 0x12855F)
    static let trustDeep = Color(hex: 0x0E6B4C)
    static let trustBg = Color(hex: 0xE8F5EE)
    static let trustBorder = Color(hex: 0xC2E5D2)

    // Danger
    static let danger = Color(hex: 0xD92D20)
    static let dangerBg = Color(hex: 0xFEF3F2)

    // Accent
    static let gold = Color(hex: 0xFFD617)

    // Dark debug console
    enum Console {
        static let bg = Color(hex: 0x0D1220)
        static let panel = Color(hex: 0x151C30)
        static let chipActive = Color(hex: 0x26335C)
        static let border = Color(hex: 0x2A3350)
        static let text = Color(hex: 0xDCE4F8)
        static let textDim = Color(hex: 0x7684AC)
        static let info = Color(hex: 0x5BA4F5)
        static let warn = Color(hex: 0xE8B44C)
        static let error = Color(hex: 0xF06A5E)
    }
}

/// Per-document card gradients (top-left → bottom-right), keyed by a stable document kind — see
/// `credGradient`. Mirrors android `DocGradients`.
enum DocGradients {
    static let pid = [Color(hex: 0x101F52), Color(hex: 0x1D3FA8), Color(hex: 0x2E63E7)]
    static let mdl = [Color(hex: 0x0B3B35), Color(hex: 0x116A5C), Color(hex: 0x1B9A82)]
    static let age = [Color(hex: 0x4A1140), Color(hex: 0x7E1E5F), Color(hex: 0xB03A80)]
    static let photoId = [Color(hex: 0x0C3C4E), Color(hex: 0x156579), Color(hex: 0x2492A8)]
    static let health = [Color(hex: 0x0E4E8F), Color(hex: 0x1B74C9), Color(hex: 0x3D97E8)]
    static let education = [Color(hex: 0x3A1F63), Color(hex: 0x5B35A8), Color(hex: 0x8557E0)]
    static let residence = [Color(hex: 0x5F2D0C), Color(hex: 0x9A4E17), Color(hex: 0xD0742B)]
    static let finance = [Color(hex: 0x232A3A), Color(hex: 0x3D485F), Color(hex: 0x5B6880)]
    static let neutral = [Color(hex: 0x2A3550), Color(hex: 0x44557C)]

    /// Rotation for document kinds we have no dedicated palette for, keyed deterministically.
    static let palette = [education, residence, finance, health, neutral]
}

/// The wallet type scale — a 1:1 port of android `ui/theme/Type.kt` (Manrope, Material3 slots). Sizes and
/// weights match the Compose `WalletTypography` exactly so text lays out the same. Tracking (letter spacing)
/// is applied at the call site via `.tracking(...)` where android sets it (section labels, kickers).
enum WalletFont {
    private static func manrope(_ size: CGFloat, _ weight: Font.Weight) -> Font {
        .custom("Manrope", size: size).weight(weight)
    }

    static let titleLarge = manrope(21, .heavy)    // 800
    static let titleMedium = manrope(16, .heavy)   // 800
    static let titleSmall = manrope(14, .bold)     // 700
    static let bodyLarge = manrope(14, .semibold)  // 600
    static let bodyMedium = manrope(13, .semibold) // 600
    static let bodySmall = manrope(12, .medium)    // 500
    static let labelLarge = manrope(14, .bold)     // 700
    static let labelMedium = manrope(12, .bold)    // 700
    static let labelSmall = manrope(11, .bold)     // 700 (tracked 0.6 at call site)
    static let sectionLabel = manrope(11.5, .heavy) // 800 (tracked 0.8 at call site)
    /// android `bodyMedium` with a `fontWeight(700)` override — used for InfoRow/TrustRow values.
    static let bodyMediumStrong = manrope(13, .bold)

    /// JetBrains Mono for the debug console.
    static func mono(_ size: CGFloat = 11) -> Font { .custom("JetBrains Mono", size: size) }
}

extension Color {
    /// 24-bit RGB hex (e.g. `0x2555DB`) — matches the android `Color(0xFF……)` tokens.
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: 1
        )
    }
}

extension View {
    /// The screen-background fill used by every top-level screen.
    func walletScreenBackground() -> some View {
        background(WalletTheme.screen.ignoresSafeArea())
    }
}
