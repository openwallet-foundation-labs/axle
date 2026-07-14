package com.hopae.eudi.demo.ui.theme

import android.app.Activity
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat

private val WalletScheme = lightColorScheme(
    primary = BrandBlue,
    onPrimary = SurfaceWhite,
    primaryContainer = BrandBlueSoftBg,
    onPrimaryContainer = BrandBlueDeep,
    secondary = InkBody,
    onSecondary = SurfaceWhite,
    secondaryContainer = BrandBlueSoftBg,
    onSecondaryContainer = BrandBlueDeep,
    tertiary = TrustGreen,
    onTertiary = SurfaceWhite,
    background = DeviceGrey,
    onBackground = Ink,
    surface = SurfaceWhite,
    onSurface = Ink,
    surfaceVariant = DeviceGrey,
    onSurfaceVariant = InkMuted,
    // Neutralise the surface-container roles (menus, sheets, elevated surfaces) — otherwise they fall back to
    // Material's baseline purple/pink palette. surfaceTint is brand blue so elevation never tints toward pink.
    surfaceTint = BrandBlue,
    surfaceContainerLowest = SurfaceWhite,
    surfaceContainerLow = Color(0xFFF7F8FB),
    surfaceContainer = SurfaceWhite,
    surfaceContainerHigh = Color(0xFFF2F3F7),
    surfaceContainerHighest = Color(0xFFECEEF3),
    outline = CardBorderStrong,
    outlineVariant = Divider,
    error = Danger,
    onError = SurfaceWhite,
    errorContainer = DangerBg,
    onErrorContainer = Danger,
)

private val WalletShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(24.dp),
)

@Composable
fun WalletTheme(content: @Composable () -> Unit) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = DeviceGrey.toArgb()
            window.navigationBarColor = SurfaceWhite.toArgb()
            val controller = WindowCompat.getInsetsController(window, view)
            controller.isAppearanceLightStatusBars = true
            controller.isAppearanceLightNavigationBars = true
        }
    }
    CompositionLocalProvider(LocalWalletColors provides WalletColors()) {
        MaterialTheme(
            colorScheme = WalletScheme,
            typography = WalletTypography,
            shapes = WalletShapes,
            content = content,
        )
    }
}

/** Convenience accessor for the extended brand tokens: `WalletTheme.colors.trust`, etc. */
object WalletTheme {
    val colors: WalletColors
        @Composable get() = LocalWalletColors.current
}
