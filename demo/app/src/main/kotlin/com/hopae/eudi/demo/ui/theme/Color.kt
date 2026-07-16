package com.hopae.eudi.demo.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * Brand palette for the wallet, distilled from the EUDI Wallet design guide.
 * Material3's [androidx.compose.material3.ColorScheme] carries the common roles (primary/surface/…);
 * [WalletColors] adds the extended semantic tokens the design leans on — text tiers, trust greens,
 * the dark debug console, and the per-document card gradients — that don't map cleanly onto Material roles.
 */

// ── Brand blue ──────────────────────────────────────────────────────────────
val BrandBlue = Color(0xFF2555DB)
val BrandBluePressed = Color(0xFF1D47BC)
val BrandBlueDeep = Color(0xFF173C9E)
val BrandBlueSoftBg = Color(0xFFEAF1FF)
val BrandBlueSoftBorder = Color(0xFFCBDBFA)

// ── Neutrals ────────────────────────────────────────────────────────────────
val CanvasGrey = Color(0xFFE9EBF1)   // outer app canvas
val DeviceGrey = Color(0xFFF4F5F9)   // screen background
val SurfaceWhite = Color(0xFFFFFFFF)
val CardBorder = Color(0xFFE9EBF1)
val CardBorderStrong = Color(0xFFE4E7EC)
val Divider = Color(0xFFF0F2F7)

// ── Text tiers ──────────────────────────────────────────────────────────────
val Ink = Color(0xFF101828)        // headings
val InkBody = Color(0xFF344054)    // primary body
val InkMuted = Color(0xFF667085)   // secondary
val InkFaint = Color(0xFF98A2B3)   // tertiary / labels

// ── Trust / success ─────────────────────────────────────────────────────────
val TrustGreen = Color(0xFF12855F)
val TrustGreenDeep = Color(0xFF0E6B4C)
val TrustGreenBg = Color(0xFFE8F5EE)
val TrustGreenBorder = Color(0xFFC2E5D2)
val TrustGreenLight = Color(0xFF7FE0AE)

// ── Danger ──────────────────────────────────────────────────────────────────
val Danger = Color(0xFFD92D20)
val DangerBg = Color(0xFFFEF3F2)
val DangerBorder = Color(0xFFF1C0BB)

// ── Accent ──────────────────────────────────────────────────────────────────
val EuGold = Color(0xFFFFD617)

// ── Dark debug console ──────────────────────────────────────────────────────
val ConsoleBg = Color(0xFF0D1220)
val ConsolePanel = Color(0xFF151C30)
val ConsoleChipActive = Color(0xFF26335C)
val ConsoleBorder = Color(0xFF2A3350)
val ConsoleText = Color(0xFFDCE4F8)
val ConsoleTextDim = Color(0xFF7684AC)
val LogInfo = Color(0xFF5BA4F5)
val LogWarn = Color(0xFFE8B44C)
val LogError = Color(0xFFF06A5E)

/** Document card gradients (top-left → bottom-right). Keyed by a stable document kind. */
object DocGradients {
    val Pid = listOf(Color(0xFF101F52), Color(0xFF1D3FA8), Color(0xFF2E63E7))
    val Mdl = listOf(Color(0xFF0B3B35), Color(0xFF116A5C), Color(0xFF1B9A82))
    val Age = listOf(Color(0xFF4A1140), Color(0xFF7E1E5F), Color(0xFFB03A80))
    val PhotoId = listOf(Color(0xFF0C3C4E), Color(0xFF156579), Color(0xFF2492A8))
    val Health = listOf(Color(0xFF0E4E8F), Color(0xFF1B74C9), Color(0xFF3D97E8))
    val Education = listOf(Color(0xFF3A1F63), Color(0xFF5B35A8), Color(0xFF8557E0))
    val Residence = listOf(Color(0xFF5F2D0C), Color(0xFF9A4E17), Color(0xFFD0742B))
    val Finance = listOf(Color(0xFF232A3A), Color(0xFF3D485F), Color(0xFF5B6880))
    val Neutral = listOf(Color(0xFF2A3550), Color(0xFF44557C))

    /** Rotation used for document kinds we have no dedicated palette for, keyed deterministically. */
    val palette = listOf(Education, Residence, Finance, Health, Neutral)
}

@Immutable
data class WalletColors(
    val canvas: Color = CanvasGrey,
    val screen: Color = DeviceGrey,
    val card: Color = SurfaceWhite,
    val cardBorder: Color = CardBorder,
    val cardBorderStrong: Color = CardBorderStrong,
    val divider: Color = Divider,
    val ink: Color = Ink,
    val inkBody: Color = InkBody,
    val inkMuted: Color = InkMuted,
    val inkFaint: Color = InkFaint,
    val brand: Color = BrandBlue,
    val brandPressed: Color = BrandBluePressed,
    val brandSoftBg: Color = BrandBlueSoftBg,
    val brandSoftBorder: Color = BrandBlueSoftBorder,
    val trust: Color = TrustGreen,
    val trustDeep: Color = TrustGreenDeep,
    val trustBg: Color = TrustGreenBg,
    val trustBorder: Color = TrustGreenBorder,
    val danger: Color = Danger,
    val dangerBg: Color = DangerBg,
    val dangerBorder: Color = DangerBorder,
    val gold: Color = EuGold,
)

val LocalWalletColors = staticCompositionLocalOf { WalletColors() }
