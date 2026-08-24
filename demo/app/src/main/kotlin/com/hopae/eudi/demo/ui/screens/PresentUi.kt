package com.hopae.eudi.demo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.ui.components.PrimaryButton
import com.hopae.eudi.demo.ui.theme.WalletTheme

/**
 * Shared building blocks for the sharing screens (remote OpenID4VP and in-person proximity), so both read the
 * same: a centred terminal state (progress / success / failure), an in-card group label, and the claim-path
 * label rule.
 */

@Composable
internal fun Centered(content: @Composable ColumnScope.() -> Unit) =
    Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center, content = content)

@Composable
internal fun PresentProgress(title: String, subtitle: String) {
    val c = WalletTheme.colors
    CircularProgressIndicator(color = c.brand)
    Spacer(Modifier.height(20.dp)); Text(title, style = MaterialTheme.typography.titleMedium, color = c.ink)
    Spacer(Modifier.height(8.dp)); Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center)
}

@Composable
internal fun PresentDone(title: String, subtitle: String, buttonLabel: String = "Done", onDone: () -> Unit) {
    val c = WalletTheme.colors
    Box(Modifier.size(84.dp).clip(RoundedCornerShape(99.dp)).background(c.trustBg), contentAlignment = Alignment.Center) {
        Icon(Icons.Filled.Check, null, tint = c.trust, modifier = Modifier.size(40.dp))
    }
    Spacer(Modifier.height(20.dp)); Text(title, style = MaterialTheme.typography.titleLarge, color = c.ink)
    Spacer(Modifier.height(8.dp)); Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center)
    Spacer(Modifier.height(28.dp)); PrimaryButton(buttonLabel, onDone)
}

/**
 * The shared failure block. [message] is the line a User reads; [detail] is the underlying technical reason
 * (an SDK exception message), rendered smaller in its own card — this is an interop demo, so the reason a
 * verifier was rejected has to be visible on the device, not only in the Debug log.
 */
@Composable
internal fun PresentFailed(
    title: String,
    message: String,
    buttonLabel: String = "Close",
    detail: String? = null,
    onClose: () -> Unit,
) {
    val c = WalletTheme.colors
    Box(Modifier.size(84.dp).clip(RoundedCornerShape(99.dp)).background(c.dangerBg), contentAlignment = Alignment.Center) {
        Text("!", style = MaterialTheme.typography.titleLarge, color = c.danger)
    }
    Spacer(Modifier.height(20.dp)); Text(title, style = MaterialTheme.typography.titleMedium, color = c.ink)
    Spacer(Modifier.height(8.dp)); Text(message, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center)
    if (!detail.isNullOrBlank() && detail != message) {
        Spacer(Modifier.height(16.dp))
        Box(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(c.dangerBg).padding(14.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(detail, style = MaterialTheme.typography.bodySmall, color = c.danger, textAlign = TextAlign.Center)
        }
    }
    Spacer(Modifier.height(28.dp)); PrimaryButton(buttonLabel, onClose)
}

@Composable
internal fun PresentDeclined(subtitle: String, onClose: () -> Unit) {
    val c = WalletTheme.colors
    Text("Declined", style = MaterialTheme.typography.titleMedium, color = c.ink)
    Spacer(Modifier.height(8.dp)); Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center)
    Spacer(Modifier.height(28.dp)); PrimaryButton("Close", onClose)
}

/** A small uppercase group label inside a card (e.g. "SHARED", "NOT SHARED"). */
@Composable
internal fun GroupHeader(text: String) {
    Text(
        text.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = WalletTheme.colors.inkFaint,
        modifier = Modifier.padding(16.dp, 10.dp, 16.dp, 2.dp),
    )
}

/** Human label for a claim path — drops an mdoc namespace prefix and title-cases the element. */
internal fun claimPathLabel(path: List<String>): String {
    val p = if (path.size > 1 && path.first().contains('.')) path.drop(1) else path
    return p.joinToString(" › ") { it.replace('_', ' ').replaceFirstChar { ch -> ch.uppercase() } }
}
