package com.hopae.eudi.demo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.outlined.CreditCard
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.ui.DocumentRow
import com.hopae.eudi.demo.ui.byRecentUse
import com.hopae.eudi.demo.ui.credGradient
import com.hopae.eudi.demo.ui.credKicker
import com.hopae.eudi.demo.ui.credTitle
import com.hopae.eudi.demo.ui.components.Pill
import com.hopae.eudi.demo.ui.components.SecuredPill
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.theme.EuGold
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.txlog.TransactionLogEntry
import java.time.LocalTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

@Composable
fun HomeScreen(
    wallet: Wallet,
    refreshKey: Int,
    onScan: () -> Unit,
    onReadMdl: () -> Unit,
    onProximity: () -> Unit,
    onOpenDoc: (Credential) -> Unit,
    onSeeDocuments: () -> Unit,
    onSeeActivity: () -> Unit,
    onOpenActivity: (TransactionLogEntry) -> Unit,
) {
    val c = WalletTheme.colors
    var creds by remember { mutableStateOf<List<Credential>>(emptyList()) }
    var recent by remember { mutableStateOf<List<TransactionLogEntry>>(emptyList()) }
    suspend fun reload() {
        runCatching { wallet.credentials.list() }.onSuccess { creds = it }
        runCatching { wallet.transactions.history() }.onSuccess { recent = it }
    }
    LaunchedEffect(refreshKey) {
        reload()
        runCatching { wallet.credentials.changes.collect { reload() } }
    }
    // Surface the most-recently-used documents first (hero = the top one, then a short preview).
    val ordered = remember(creds, recent) { creds.byRecentUse(recent) }
    val previewCount = 3

    LazyColumn(
        Modifier.fillMaxWidth().background(c.screen),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(20.dp, 16.dp, 20.dp, 24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        item {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(greeting(), style = MaterialTheme.typography.bodyMedium, color = c.inkMuted)
                    Text(holderName(creds), style = MaterialTheme.typography.titleLarge, color = c.ink)
                }
                SecuredPill()
            }
        }

        item {
            val hero = ordered.firstOrNull()
            if (hero == null) EmptyHero(onScan) else HeroCard(hero) { onOpenDoc(hero) }
        }

        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                QuickAction("Scan", Icons.Filled.QrCodeScanner, primary = true, modifier = Modifier.weight(1f), onClick = onScan)
                QuickAction("Proximity", Icons.Filled.Sensors, primary = false, modifier = Modifier.weight(1f), onClick = onProximity)
                QuickAction("Read mDL", Icons.Filled.Sensors, primary = false, modifier = Modifier.weight(1f), onClick = onReadMdl)
            }
        }

        if (ordered.size > 1) {
            item {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text("Documents", style = MaterialTheme.typography.titleSmall, color = c.ink, modifier = Modifier.weight(1f))
                    if (ordered.size - 1 > previewCount) {
                        Text("See all", style = MaterialTheme.typography.labelMedium, color = c.brand, modifier = Modifier.clickable { onSeeDocuments() })
                    }
                }
            }
            items(ordered.drop(1).take(previewCount)) { d -> DocumentRow(d) { onOpenDoc(d) } }
        }

        if (recent.isNotEmpty()) {
            item {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text("Recent activity", style = MaterialTheme.typography.titleSmall, color = c.ink, modifier = Modifier.weight(1f))
                    Text("See all", style = MaterialTheme.typography.labelMedium, color = c.brand, modifier = Modifier.clickable { onSeeActivity() })
                }
            }
            items(recent.take(3)) { e -> ActivityRow(e, onClick = { onOpenActivity(e) }) }
        }
    }
}

@Composable
private fun HeroCard(cred: Credential, onClick: () -> Unit) {
    Box(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(Brush.linearGradient(credGradient(cred)))
            .clickable { onClick() }.padding(20.dp),
    ) {
        Column {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    credKicker(cred).uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                    color = Color.White.copy(alpha = 0.85f),
                    modifier = Modifier.weight(1f),
                )
                Pill("eIDAS 2.0", Color.White.copy(alpha = 0.12f), Color.White)
            }
            Spacer(Modifier.height(26.dp))
            Text(credTitle(cred), style = MaterialTheme.typography.titleMedium, color = Color.White)
            cred.issuer?.displayName?.let {
                Spacer(Modifier.height(3.dp))
                Text(it, style = MaterialTheme.typography.bodySmall, color = Color.White.copy(alpha = 0.75f))
            }
            Spacer(Modifier.height(18.dp))
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(validityLine(cred), style = MaterialTheme.typography.bodySmall, color = Color.White.copy(alpha = 0.75f), modifier = Modifier.weight(1f))
                val trusted = cred.issuer?.trusted == true
                if (trusted) Text("✓ Verified", style = MaterialTheme.typography.labelSmall, color = EuGold)
            }
        }
    }
}

@Composable
private fun EmptyHero(onScan: () -> Unit) {
    val c = WalletTheme.colors
    WalletCard(onClick = onScan, padding = androidx.compose.foundation.layout.PaddingValues(22.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            Box(Modifier.size(46.dp).clip(RoundedCornerShape(14.dp)).background(c.brandSoftBg), contentAlignment = Alignment.Center) {
                Icon(Icons.Outlined.CreditCard, null, tint = c.brand, modifier = Modifier.size(24.dp))
            }
            Column(Modifier.weight(1f)) {
                Text("No documents yet", style = MaterialTheme.typography.titleSmall, color = c.ink)
                Text("Scan an issuer QR to add your first credential.", style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
            }
            Icon(Icons.Filled.ChevronRight, null, tint = c.inkFaint)
        }
    }
}

@Composable
private fun QuickAction(label: String, icon: ImageVector, primary: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val c = WalletTheme.colors
    val bg = if (primary) c.brand else c.card
    val fg = if (primary) Color.White else c.ink
    Column(
        modifier.clip(RoundedCornerShape(14.dp)).background(bg)
            .then(if (primary) Modifier else Modifier.border(1.dp, c.cardBorderStrong, RoundedCornerShape(14.dp)))
            .clickable { onClick() }.padding(vertical = 14.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Icon(icon, null, tint = fg, modifier = Modifier.size(18.dp))
        Text(label, style = MaterialTheme.typography.labelMedium, color = fg)
    }
}

@Composable
private fun ActivityRow(e: TransactionLogEntry, onClick: () -> Unit) {
    val c = WalletTheme.colors
    val shared = e.type.name.contains("Present", ignoreCase = true)
    val issued = e.type.name.contains("Issu", ignoreCase = true)
    val arrow = when { shared -> "↑"; issued -> "↓"; else -> "✓" }
    val tint = when { shared -> c.brand; issued -> c.trust; else -> c.inkMuted }
    val bg = when { shared -> c.brandSoftBg; issued -> c.trustBg; else -> c.screen }
    val title = e.relyingParty?.name ?: e.relyingParty?.id
        ?: when { issued -> "Credential issued"; shared -> "Presentation"; else -> "Verification" }
    val status = e.status.name.lowercase().replaceFirstChar { it.uppercase() }
    WalletCard(onClick = onClick, padding = androidx.compose.foundation.layout.PaddingValues(11.dp, 14.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Box(Modifier.size(32.dp).clip(RoundedCornerShape(99.dp)).background(bg), contentAlignment = Alignment.Center) {
                Text(arrow, color = tint, style = MaterialTheme.typography.titleSmall)
            }
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyMedium, color = c.ink, maxLines = 1, overflow = TextOverflow.Ellipsis)
                // Time folded into the subtitle so it sits next to the content instead of pinned far right.
                Text("$status · ${relTime(e.timestamp)}", style = MaterialTheme.typography.bodySmall, color = c.inkFaint)
            }
            Icon(Icons.Filled.ChevronRight, null, tint = c.cardBorderStrong, modifier = Modifier.size(16.dp))
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

private fun greeting(): String = when (LocalTime.now().hour) {
    in 0..11 -> "Good morning"
    in 12..17 -> "Good afternoon"
    else -> "Good evening"
}

/** Best-effort holder name from a PID credential's given/family name claims; falls back to a generic title. */
private fun holderName(creds: List<Credential>): String {
    for (cred in creds) {
        val claims = (cred.lifecycle as? Lifecycle.Issued)?.claims ?: continue
        val given = claims.firstOrNull { it.path.lastOrNull()?.equals("given_name", true) == true }?.value?.display()
        val family = claims.firstOrNull { it.path.lastOrNull()?.equals("family_name", true) == true }?.value?.display()
        val name = listOfNotNull(given, family).joinToString(" ").trim()
        if (name.isNotBlank()) return name
    }
    return "Your wallet"
}

private fun validityLine(cred: Credential): String {
    val until = (cred.lifecycle as? Lifecycle.Issued)?.validity?.validUntil ?: return ""
    val d = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(Locale.getDefault()).withZone(ZoneId.systemDefault())
    return "Valid until ${d.format(until)}"
}

private fun relTime(epochSeconds: Long): String {
    val now = System.currentTimeMillis() / 1000
    val diff = now - epochSeconds
    return when {
        diff < 60 -> "now"
        diff < 3600 -> "${diff / 60}m"
        diff < 86400 -> "${diff / 3600}h"
        else -> "${diff / 86400}d"
    }
}
