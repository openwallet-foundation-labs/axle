package com.hopae.eudi.demo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.ui.DocumentRow
import com.hopae.eudi.demo.ui.byRecentUse
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.txlog.TransactionLogEntry

@Composable
fun DocumentsScreen(wallet: Wallet, refreshKey: Int, onOpenDoc: (Credential) -> Unit) {
    val c = WalletTheme.colors
    var creds by remember { mutableStateOf<List<Credential>>(emptyList()) }
    var txs by remember { mutableStateOf<List<TransactionLogEntry>>(emptyList()) }
    suspend fun reload() {
        runCatching { wallet.credentials.list() }.onSuccess { creds = it }
        runCatching { wallet.transactions.history() }.onSuccess { txs = it }
    }
    LaunchedEffect(refreshKey) {
        reload()
        runCatching { wallet.credentials.changes.collect { reload() } }
    }
    val ordered = remember(creds, txs) { creds.byRecentUse(txs) }

    LazyColumn(
        Modifier.fillMaxSize().background(c.screen),
        contentPadding = PaddingValues(20.dp, 16.dp, 20.dp, 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { Text("Documents", style = MaterialTheme.typography.titleLarge, color = c.ink) }
        if (ordered.isEmpty()) {
            item { Text("No documents yet — tap Scan on Home to add your first credential.", style = MaterialTheme.typography.bodyMedium, color = c.inkMuted) }
        }
        items(ordered) { cred -> DocumentRow(cred) { onOpenDoc(cred) } }
    }
}
