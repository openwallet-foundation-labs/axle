package com.hopae.eudi.demo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.hopae.eudi.demo.security.BiometricAuth
import com.hopae.eudi.demo.security.WalletSecurity
import com.hopae.eudi.demo.ui.components.Keypad
import com.hopae.eudi.demo.ui.components.PinDots
import com.hopae.eudi.demo.ui.components.PrimaryButton
import com.hopae.eudi.demo.ui.components.SecondaryButton
import com.hopae.eudi.demo.ui.theme.DocGradients
import com.hopae.eudi.demo.ui.theme.EuGold
import com.hopae.eudi.demo.ui.theme.WalletTheme
import kotlinx.coroutines.delay

private enum class Step { Welcome, CreatePin, ConfirmPin, Biometric, Done }

@Composable
fun OnboardingScreen(activity: FragmentActivity, onDone: () -> Unit) {
    val c = WalletTheme.colors
    val ctx = LocalContext.current
    var step by remember { mutableStateOf(Step.Welcome) }
    var firstPin by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    val canBiometric = remember { BiometricAuth.canUse(activity) }

    fun finish(biometric: Boolean) { WalletSecurity.completeOnboarding(ctx, firstPin, biometric); step = Step.Done }

    LaunchedEffect(pin, step) {
        if (pin.length < 6) return@LaunchedEffect
        when (step) {
            Step.CreatePin -> { firstPin = pin; delay(140); pin = ""; step = Step.ConfirmPin }
            Step.ConfirmPin ->
                if (pin == firstPin) { delay(120); if (canBiometric) step = Step.Biometric else finish(false) }
                else { error = true; delay(650); pin = ""; error = false }
            else -> {}
        }
    }

    Box(Modifier.fillMaxSize().background(c.screen).padding(24.dp), contentAlignment = Alignment.Center) {
        when (step) {
            Step.Welcome -> Welcome { step = Step.CreatePin }
            Step.CreatePin -> PinStep(
                title = "Create a wallet PIN",
                subtitle = "You'll use this 6-digit PIN to unlock your wallet.",
                filled = pin.length, error = false,
                onDigit = { if (pin.length < 6) pin += it }, onDelete = { pin = pin.dropLast(1) },
            )
            Step.ConfirmPin -> PinStep(
                title = "Confirm your PIN",
                subtitle = if (error) "PINs didn't match — try again." else "Re-enter the PIN to confirm.",
                filled = pin.length, error = error,
                onDigit = { if (pin.length < 6) pin += it }, onDelete = { pin = pin.dropLast(1) },
            )
            Step.Biometric -> BiometricStep(
                activity = activity,
                onEnable = { finish(true) },
                onSkip = { finish(false) },
            )
            Step.Done -> Done(onDone)
        }
    }
}

@Composable
private fun Welcome(onContinue: () -> Unit) {
    val c = WalletTheme.colors
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier.size(76.dp).clip(RoundedCornerShape(22.dp)).background(Brush.linearGradient(DocGradients.Pid)),
            contentAlignment = Alignment.Center,
        ) { Text("★", color = EuGold, style = MaterialTheme.typography.titleLarge) }
        Spacer(Modifier.height(24.dp))
        Text("Axle Wallet", style = MaterialTheme.typography.titleLarge, color = c.ink, textAlign = TextAlign.Center)
        Spacer(Modifier.height(8.dp))
        Text(
            "eIDAS 2.0 EU Digital Identity Wallet",
            style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center,
            modifier = Modifier.widthIn(max = 320.dp),
        )
        Spacer(Modifier.height(36.dp))
        PrimaryButton("Get started", onContinue, Modifier.widthIn(max = 320.dp))
    }
}

@Composable
private fun PinStep(title: String, subtitle: String, filled: Int, error: Boolean, onDigit: (String) -> Unit, onDelete: () -> Unit) {
    val c = WalletTheme.colors
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(title, style = MaterialTheme.typography.titleMedium, color = c.ink)
        Spacer(Modifier.height(8.dp))
        Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = if (error) c.danger else c.inkMuted, textAlign = TextAlign.Center, modifier = Modifier.widthIn(max = 300.dp))
        Spacer(Modifier.height(28.dp))
        PinDots(filled = filled, error = error)
        Spacer(Modifier.height(40.dp))
        Keypad(onDigit = onDigit, onDelete = onDelete)
    }
}

@Composable
private fun BiometricStep(activity: FragmentActivity, onEnable: () -> Unit, onSkip: () -> Unit) {
    val c = WalletTheme.colors
    val label = remember { BiometricAuth.label(activity) }
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(Modifier.size(76.dp).clip(RoundedCornerShape(99.dp)).background(c.brandSoftBg), contentAlignment = Alignment.Center) {
            Icon(Icons.Filled.Fingerprint, null, tint = c.brand, modifier = Modifier.size(38.dp))
        }
        Spacer(Modifier.height(24.dp))
        Text("Unlock with $label", style = MaterialTheme.typography.titleMedium, color = c.ink)
        Spacer(Modifier.height(8.dp))
        Text("Use $label to unlock your wallet instead of typing your PIN each time.", style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center, modifier = Modifier.widthIn(max = 320.dp))
        Spacer(Modifier.height(36.dp))
        PrimaryButton("Enable $label", modifier = Modifier.widthIn(max = 320.dp), onClick = {
            BiometricAuth.prompt(activity, "Enable $label", "Confirm to enable biometric unlock", onSuccess = onEnable)
        })
        Spacer(Modifier.height(10.dp))
        SecondaryButton("Not now", onSkip, Modifier.widthIn(max = 320.dp))
    }
}

@Composable
private fun Done(onDone: () -> Unit) {
    val c = WalletTheme.colors
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(Modifier.size(84.dp).clip(RoundedCornerShape(99.dp)).background(c.trustBg), contentAlignment = Alignment.Center) {
            Icon(Icons.Filled.Check, null, tint = c.trust, modifier = Modifier.size(40.dp))
        }
        Spacer(Modifier.height(24.dp))
        Text("Your wallet is ready", style = MaterialTheme.typography.titleLarge, color = c.ink)
        Spacer(Modifier.height(12.dp))
        Text("Keys are protected by this device's secure hardware.", style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center, modifier = Modifier.widthIn(max = 300.dp))
        Spacer(Modifier.height(36.dp))
        PrimaryButton("Enter wallet", onDone, Modifier.widthIn(max = 320.dp))
    }
}
