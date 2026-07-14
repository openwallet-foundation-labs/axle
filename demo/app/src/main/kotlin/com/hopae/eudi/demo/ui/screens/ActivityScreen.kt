package com.hopae.eudi.demo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.txlog.TransactionLogEntry
import com.hopae.eudi.wallet.txlog.TransactionType
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ActivityScreen(wallet: Wallet, refreshKey: Int, onOpenActivity: (TransactionLogEntry) -> Unit) {
    val c = WalletTheme.colors
    var entries by remember { mutableStateOf<List<TransactionLogEntry>>(emptyList()) }
    LaunchedEffect(refreshKey) { runCatching { wallet.transactions.history() }.onSuccess { entries = it } }

    LazyColumn(
        Modifier.fillMaxSize().background(c.screen),
        contentPadding = PaddingValues(20.dp, 16.dp, 20.dp, 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { Text("Activity", style = MaterialTheme.typography.titleLarge, color = c.ink) }
        if (entries.isEmpty()) {
            item { Text("Nothing yet — your issuances and presentations will appear here.", style = MaterialTheme.typography.bodyMedium, color = c.inkMuted) }
        }
        items(entries) { e -> ActivityCard(e) { onOpenActivity(e) } }
    }
}

@Composable
private fun ActivityCard(e: TransactionLogEntry, onClick: () -> Unit) {
    val c = WalletTheme.colors
    val present = e.type == TransactionType.PRESENTATION
    val arrow = if (present) "↑" else "↓"
    val tint = if (present) c.brand else c.trust
    val bg = if (present) c.brandSoftBg else c.trustBg
    WalletCard(onClick = onClick, padding = PaddingValues(13.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Box(Modifier.size(34.dp).clip(RoundedCornerShape(99.dp)).background(bg), contentAlignment = Alignment.Center) {
                Text(arrow, color = tint, style = MaterialTheme.typography.titleSmall)
            }
            Column(Modifier.weight(1f)) {
                Text(
                    e.relyingParty?.name ?: e.relyingParty?.id ?: (if (present) "Presentation" else "Issuance"),
                    style = MaterialTheme.typography.titleSmall, color = c.ink, maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
                val docs = e.documents.joinToString(", ") { it.type ?: it.format }.ifBlank { "${e.documents.size} document(s)" }
                Text(docs, style = MaterialTheme.typography.bodySmall, color = c.inkMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Column(horizontalAlignment = Alignment.End) {
                val ok = e.status.name == "SUCCESS"
                Text(e.status.name, style = MaterialTheme.typography.labelSmall, color = if (ok) c.trust else c.danger, fontWeight = FontWeight(700))
                Text(timeFmt.format(Date(e.timestamp * 1000)), style = MaterialTheme.typography.bodySmall, color = c.inkFaint)
            }
        }
    }
}

private val timeFmt = SimpleDateFormat("MMM d, HH:mm", Locale.getDefault())
