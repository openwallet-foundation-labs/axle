package com.hopae.eudi.demo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.ui.components.InfoRow
import com.hopae.eudi.demo.ui.components.Pill
import com.hopae.eudi.demo.ui.components.SectionLabel
import com.hopae.eudi.demo.ui.components.TrustBadge
import com.hopae.eudi.demo.ui.components.TrustRow
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.components.absorbTouches
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.txlog.LocalizedText
import com.hopae.eudi.wallet.txlog.LoggedDocument
import com.hopae.eudi.wallet.txlog.TransactionLogEntry
import com.hopae.eudi.wallet.txlog.TransactionTransport
import com.hopae.eudi.wallet.txlog.TransactionType
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun TransactionDetailScreen(e: TransactionLogEntry, onBack: () -> Unit) {
    val c = WalletTheme.colors
    val present = e.type == TransactionType.PRESENTATION
    val topInset = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
    val bottomInset = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
    val arrow = if (present) "↑" else "↓"
    val tint = if (present) c.brand else c.trust
    val bg = if (present) c.brandSoftBg else c.trustBg
    val rp = e.relyingParty
    val title = rp?.name ?: rp?.id ?: e.issuerName ?: e.issuer?.let { hostOf(it) }
        ?: if (present) "Presentation" else "Credential issued"

    Column(
        Modifier.fillMaxSize().background(c.screen).absorbTouches().verticalScroll(rememberScrollState())
            .padding(start = 20.dp, end = 20.dp, top = topInset + 12.dp, bottom = bottomInset + 28.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(36.dp).clip(RoundedCornerShape(99.dp)).background(c.card).clickable { onBack() }, contentAlignment = Alignment.Center) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = c.ink, modifier = Modifier.size(18.dp))
            }
            Spacer(Modifier.width(10.dp))
            Text(if (present) "Shared" else "Issued", style = MaterialTheme.typography.titleMedium, color = c.ink)
        }

        // header
        WalletCard {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(13.dp)) {
                Box(Modifier.size(44.dp).clip(RoundedCornerShape(99.dp)).background(bg), contentAlignment = Alignment.Center) {
                    Text(arrow, color = tint, style = MaterialTheme.typography.titleMedium)
                }
                Column(Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.titleSmall, color = c.ink)
                    Text(fullTime.format(Date(e.timestamp * 1000)), style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
                }
                Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    val ok = e.status.name == "SUCCESS"
                    Text(e.status.name, style = MaterialTheme.typography.labelSmall, color = if (ok) c.trust else c.danger, fontWeight = FontWeight(700))
                    e.transport?.let { Pill(transportLabel(it), c.screen, c.inkMuted) }
                }
            }
        }

        // counterparty
        if (present && rp != null) {
            SectionLabel("Relying party")
            WalletCard(padding = PaddingValues(0.dp)) {
                rp.name?.let { InfoRow("Name", it) }
                InfoRow("Identifier", rp.id)
                rp.subject?.takeIf { it.isNotBlank() }?.let { InfoRow("Registered as", it) }
                TrustRow("Signed request", if (rp.trusted) "Verified" else "Not verified", rp.trusted)
                rp.attested?.let { TrustRow("Registration (WRPRC)", if (it) "Verified by registrar" else "Self-declared", it) }
                rp.statusValid?.let { InfoRow("Registration status", if (it) "Valid" else "Revoked", if (it) null else c.danger) }
                rp.intermediaryName?.let { InfoRow("Via intermediary", it) }
            }
            // Purpose with the same compact in-scope / out-of-scope (RPRC_21) badge as the consent screen.
            if (purposeText(rp.purpose).isNotBlank() || rp.outOfScope != null) {
                SectionLabel("Purpose")
                WalletCard {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text(purposeText(rp.purpose).ifBlank { "Attribute request" }, style = MaterialTheme.typography.bodyMedium, color = c.ink, modifier = Modifier.weight(1f))
                        rp.outOfScope?.let { TrustBadge(!it, trustedText = "In scope", untrustedText = "Out of scope") }
                    }
                }
            }
            if (rp.entitlements.isNotEmpty()) {
                SectionLabel("Entitlements")
                WalletCard(padding = PaddingValues(0.dp)) {
                    rp.entitlements.forEachIndexed { i, ent ->
                        if (i > 0) Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
                        Text(ent, style = MaterialTheme.typography.bodyMedium, color = c.inkBody, modifier = Modifier.padding(16.dp, 13.dp))
                    }
                }
            }
        } else if (!present) {
            SectionLabel("Issuer")
            WalletCard(padding = PaddingValues(0.dp)) {
                InfoRow("Issuer", e.issuerName ?: e.issuer?.let { hostOf(it) } ?: "—")
                e.issuer?.let { InfoRow("Identifier", hostOf(it)) }
                e.issuerRegistered?.let { TrustRow("Registered issuer", if (it) "Yes" else "No", it) }
            }
        }

        // documents + claims
        if (e.documents.isNotEmpty()) {
            SectionLabel(if (present) "Data shared" else "Data received")
            e.documents.forEach { doc ->
                WalletCard(padding = PaddingValues(0.dp)) {
                    Text(doc.type ?: doc.format, style = MaterialTheme.typography.titleSmall, color = c.ink, modifier = Modifier.padding(16.dp, 12.dp))
                    Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
                    if (doc.claims.isEmpty()) InfoRow("Claims", "—")
                    else doc.claims.forEach { claim -> InfoRow(claimLabel(doc, claim.path), claim.value ?: "Disclosed") }
                }
            }
        }

        e.error?.let { WalletCard { Text(it, style = MaterialTheme.typography.bodyMedium, color = c.danger) } }
    }
}

private fun transportLabel(t: TransactionTransport): String = when (t) {
    TransactionTransport.PROXIMITY -> "In person"
    else -> "Online" // REMOTE (QR) and DC_API (browser) are both online channels
}

/** Pick the purpose text in the device language, falling back to the first entry. */
private fun purposeText(purpose: List<LocalizedText>): String {
    if (purpose.isEmpty()) return ""
    val lang = Locale.getDefault().language
    return (purpose.firstOrNull { it.lang.startsWith(lang, true) } ?: purpose.first()).value
}

private fun claimLabel(doc: LoggedDocument, path: List<String>): String {
    val p = if (doc.format.contains("mdoc", true) && path.size > 1) path.drop(1) else path
    return p.joinToString(" › ") { it.replace('_', ' ').replaceFirstChar { ch -> ch.uppercase() } }
}

private fun hostOf(url: String): String = runCatching { java.net.URI(url).host ?: url }.getOrDefault(url)

private val fullTime = SimpleDateFormat("EEE, d MMM yyyy · HH:mm", Locale.getDefault())
