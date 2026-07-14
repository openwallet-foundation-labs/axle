package com.hopae.eudi.demo

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.hopae.eudi.demo.security.BiometricAuth
import com.hopae.eudi.demo.security.WalletSecurity
import com.hopae.eudi.demo.ui.components.InfoRow
import com.hopae.eudi.demo.ui.components.PrimaryButton
import com.hopae.eudi.demo.ui.components.SecondaryButton
import com.hopae.eudi.demo.ui.components.SectionLabel
import com.hopae.eudi.demo.ui.components.TrustBadge
import com.hopae.eudi.demo.ui.components.TrustRow
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.screens.GroupHeader
import com.hopae.eudi.demo.ui.theme.WalletTheme

/** One requested credential in a DC API consent: a label (vct / docType) and the elements to disclose. */
class ConsentItem(val label: String, val elements: List<String>)

/**
 * The consent for a Digital Credentials API request, shown as a bottom sheet over the calling app: the
 * requester and what will be shared, with a Share/Decline choice. On Share it hands off immediately (no
 * success screen — the activity finishes and the caller receives the response). Used by both DC API paths
 * (raw-mdoc ISO 18013-7 and OpenID4VP).
 */
/** The requester shown on a DC API consent: display name, subtitle ("via …" / origin), and trust flags. */
class DcApiVerifier(
    val name: String,
    val subtitle: String,
    /** Whether the signed request verified to a trust anchor (false for an unsigned/origin-only request). */
    val signedRequestVerified: Boolean,
    /** WRPRC registrar-verified, or null when the request carries no registration (e.g. raw-mdoc). */
    val wrprcVerified: Boolean?,
)

@Composable
fun DcApiConsentSheet(
    verifier: DcApiVerifier,
    items: List<ConsentItem>,
    onApprove: () -> Unit,
    onDecline: () -> Unit,
) {
    val c = WalletTheme.colors
    val ctx = LocalContext.current
    val activity = ctx as? FragmentActivity
    var sharing by remember { mutableStateOf(false) }

    fun share() {
        val go = { sharing = true; onApprove() }
        val useBio = activity != null && WalletSecurity.biometricEnabled(ctx) && BiometricAuth.canUse(activity)
        if (useBio) BiometricAuth.prompt(activity, "Confirm sharing", "Verify to share the requested data", onSuccess = { go() }, negativeText = "Cancel")
        else go()
    }
    BackHandler { if (!sharing) onDecline() }

    val bottomInset = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
    Box(Modifier.fillMaxSize()) {
        // Scrim over the caller — tap to dismiss (declines).
        Box(
            Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.45f))
                .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) { if (!sharing) onDecline() },
        )
        // Bottom sheet.
        Column(
            Modifier.align(Alignment.BottomCenter).fillMaxWidth()
                .clip(RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp)).background(c.screen)
                .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) {} // swallow taps
                .padding(start = 20.dp, end = 20.dp, top = 10.dp, bottom = bottomInset + 20.dp),
        ) {
            Box(Modifier.align(Alignment.CenterHorizontally).size(38.dp, 4.dp).clip(RoundedCornerShape(99.dp)).background(c.cardBorderStrong))
            Spacer(Modifier.height(16.dp))
            Text("Sharing request", style = MaterialTheme.typography.titleMedium, color = c.ink)
            Spacer(Modifier.height(14.dp))

            // Requester
            WalletCard {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Box(Modifier.size(42.dp).clip(RoundedCornerShape(12.dp)).background(c.ink), contentAlignment = Alignment.Center) {
                        Icon(Icons.Filled.Public, null, tint = Color.White, modifier = Modifier.size(22.dp))
                    }
                    Column(Modifier.weight(1f)) {
                        Text(verifier.name, style = MaterialTheme.typography.titleSmall, color = c.ink, maxLines = 2)
                        Text(verifier.subtitle, style = MaterialTheme.typography.bodySmall, color = c.inkMuted, maxLines = 1)
                    }
                    TrustBadge(verifier.signedRequestVerified, trustedText = "Verified", untrustedText = "Unverified")
                }
            }
            Spacer(Modifier.height(10.dp))
            WalletCard(padding = PaddingValues(0.dp)) {
                TrustRow("Signed request", if (verifier.signedRequestVerified) "Verified" else "Not verified", verifier.signedRequestVerified)
                verifier.wrprcVerified?.let { ok ->
                    TrustRow("Registration (WRPRC)", if (ok) "Verified by registrar" else "Self-declared", ok)
                }
            }
            Spacer(Modifier.height(16.dp))
            SectionLabel("You'll share")
            Spacer(Modifier.height(8.dp))
            Column(
                Modifier.heightIn(max = 300.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items.forEach { item ->
                    WalletCard(padding = PaddingValues(0.dp)) {
                        Text(item.label, style = MaterialTheme.typography.titleSmall, color = c.ink, modifier = Modifier.padding(16.dp, 12.dp))
                        Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
                        if (item.elements.isEmpty()) InfoRow("Attributes", "—")
                        else {
                            GroupHeader("Shared")
                            item.elements.forEach { InfoRow(elementLabel(it), "Shared", c.trust) }
                        }
                    }
                }
            }
            Spacer(Modifier.height(18.dp))
            if (sharing) {
                Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.5.dp, color = c.brand)
                    Spacer(Modifier.size(12.dp))
                    Text("Sharing…", style = MaterialTheme.typography.bodyLarge, color = c.inkMuted)
                }
            } else {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SecondaryButton("Decline", onDecline, Modifier.weight(1f))
                    PrimaryButton("Share", { share() }, Modifier.weight(1.5f))
                }
            }
        }
    }
}

private fun elementLabel(id: String): String = id.replace('_', ' ').replaceFirstChar { it.uppercase() }
