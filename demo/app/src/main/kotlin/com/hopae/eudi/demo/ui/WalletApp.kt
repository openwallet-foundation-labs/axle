package com.hopae.eudi.demo.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.ReceiptLong
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.CredentialOffer
import com.hopae.eudi.wallet.IssuanceRequest
import com.hopae.eudi.wallet.IssuanceState
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.PresentationRequest
import com.hopae.eudi.wallet.PresentationSelection
import com.hopae.eudi.wallet.PresentationSession
import com.hopae.eudi.wallet.PresentationState
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.txlog.TransactionLogEntry
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private class PendingConsent(val session: PresentationSession, val request: PresentationRequest)

@Composable
fun WalletApp(wallet: Wallet) {
    var tab by remember { mutableStateOf(0) }
    var refreshKey by remember { mutableStateOf(0) }
    var txCodeFor by remember { mutableStateOf<CredentialOffer?>(null) }
    var consent by remember { mutableStateOf<PendingConsent?>(null) }
    val scope = rememberCoroutineScope()

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val uri = result.contents
        if (uri == null) { LogStore.log("Scan cancelled"); return@rememberLauncherForActivityResult }
        LogStore.log("Scanned: ${uri.take(140)}${if (uri.length > 140) "…" else ""}")
        when {
            isOffer(uri) -> scope.launch {
                runCatching {
                    LogStore.log("Resolving credential offer…")
                    val offer = wallet.issuance.resolveOffer(uri)
                    LogStore.log("Offer: issuer=${offer.credentialIssuer}, configs=${offer.credentialConfigurationIds}, txCode=${offer.requiresTxCode}")
                    if (offer.requiresTxCode) { txCodeFor = offer } else { runIssuance(wallet, offer, null); refreshKey++ }
                }.onFailure { LogStore.log("❌ resolveOffer: ${it.message}") }
            }
            isVpRequest(uri) -> scope.launch {
                runCatching {
                    LogStore.log("Resolving presentation request…")
                    val session = wallet.presentation.start(uri)
                    when (val r = session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed }) {
                        is PresentationState.RequestResolved -> {
                            LogStore.log("Verifier: ${r.request.verifier.commonName ?: r.request.verifier.clientId} · trusted=${r.request.verifier.trusted} · satisfiable=${r.request.satisfiable}")
                            consent = PendingConsent(session, r.request)
                        }
                        is PresentationState.Failed -> LogStore.log("❌ ${r.error.message}")
                        else -> {}
                    }
                }.onFailure { LogStore.log("❌ presentation: ${it.message}") }
            }
            else -> LogStore.log("⚠️ Unrecognized QR (not a credential offer or VP request)")
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(selected = tab == 0, onClick = { tab = 0 },
                    icon = { Icon(Icons.Filled.CreditCard, null) }, label = { Text("Credentials") })
                NavigationBarItem(selected = tab == 1, onClick = { tab = 1; refreshKey++ },
                    icon = { Icon(Icons.Filled.ReceiptLong, null) }, label = { Text("Transactions") })
                NavigationBarItem(selected = tab == 2, onClick = { tab = 2 },
                    icon = { Icon(Icons.Filled.BugReport, null) }, label = { Text("Debug Log") })
            }
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = {
                    scanLauncher.launch(ScanOptions().apply {
                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        setPrompt("Scan a credential offer or verifier request")
                        setBeepEnabled(false)
                        setOrientationLocked(false)
                    })
                },
                icon = { Icon(Icons.Filled.QrCodeScanner, null) },
                text = { Text("Scan QR") },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            when (tab) {
                0 -> CredentialsScreen(wallet, refreshKey)
                1 -> TransactionsScreen(wallet, refreshKey)
                else -> DebugLogScreen()
            }
        }
    }

    txCodeFor?.let { offer ->
        TxCodeDialog(
            onSubmit = { code ->
                txCodeFor = null
                scope.launch { runIssuance(wallet, offer, code); refreshKey++ }
            },
            onDismiss = { txCodeFor = null; LogStore.log("Issuance cancelled (no tx_code)") },
        )
    }

    consent?.let { p ->
        ConsentDialog(
            request = p.request,
            onApprove = {
                consent = null
                scope.launch {
                    LogStore.log("Presenting (auto-select)…")
                    p.session.respond(PresentationSelection.auto(p.request))
                    val t = p.session.state.first { it.isTerminal }
                    LogStore.log(
                        when (t) {
                            is PresentationState.Completed -> "✅ Presented" + (t.redirectUri?.let { " → $it" } ?: "")
                            is PresentationState.Failed -> "❌ ${t.error.message}"
                            else -> t::class.simpleName ?: ""
                        },
                    )
                    refreshKey++
                }
            },
            onDecline = { consent = null; scope.launch { p.session.decline(); LogStore.log("Declined presentation") } },
        )
    }
}

private suspend fun runIssuance(wallet: Wallet, offer: CredentialOffer, txCode: String?) {
    val configId = offer.credentialConfigurationIds.first()
    LogStore.log("Issuance: start (config=$configId)")
    runCatching {
        val session = wallet.issuance.start(IssuanceRequest.fromOffer(offer, configId, txCode = txCode))
        session.state.first { s ->
            LogStore.log("  issuance → ${s::class.simpleName}")
            when (s) {
                is IssuanceState.TxCodeRequired -> txCode?.let { session.submitTxCode(it) }
                is IssuanceState.AuthorizationRequired -> LogStore.log("  authorize in a browser: ${s.authorizationUrl}")
                is IssuanceState.Completed -> LogStore.log("✅ Issued ${s.result.issued.size} credential(s)")
                is IssuanceState.Failed -> LogStore.log("❌ ${s.error.message}")
                else -> {}
            }
            s.isTerminal
        }
    }.onFailure { LogStore.log("❌ Issuance: ${it.message}") }
}

private fun isOffer(uri: String) =
    uri.startsWith("openid-credential-offer://") || uri.contains("credential_offer=") || uri.contains("credential_offer_uri=")

private fun isVpRequest(uri: String) =
    uri.startsWith("openid4vp://") || uri.startsWith("eudi-openid4vp://") || uri.startsWith("mdoc-openid4vp://") ||
        uri.startsWith("haip://") || uri.contains("request_uri=") || uri.contains("response_uri=")

@Composable
private fun CredentialsScreen(wallet: Wallet, refreshKey: Int) {
    var creds by remember { mutableStateOf<List<Credential>>(emptyList()) }
    val scope = rememberCoroutineScope()
    suspend fun reload() {
        runCatching { wallet.credentials.list() }
            .onSuccess { creds = it; LogStore.log("Credentials list → ${it.size}") }
            .onFailure { LogStore.log("❌ credentials.list: ${it.javaClass.simpleName}: ${it.message}") }
    }
    LaunchedEffect(refreshKey) {
        reload()
        runCatching { wallet.credentials.changes.collect { reload() } }  // live-update on add/remove
    }
    Column(Modifier.padding(16.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Credentials (${creds.size})", style = MaterialTheme.typography.titleLarge)
            TextButton(onClick = { scope.launch { reload() } }) { Text("Refresh") }
        }
        Spacer(Modifier.height(8.dp))
        if (creds.isEmpty()) Text("No credentials yet — tap Scan QR to issue one.", style = MaterialTheme.typography.bodyMedium)
        LazyColumn { items(creds) { CredentialCard(it) } }
    }
}

@Composable
private fun CredentialCard(c: Credential) {
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text(typeLabel(c), style = MaterialTheme.typography.titleMedium)
            c.issuer?.displayName?.let { Text("Issuer: $it", style = MaterialTheme.typography.bodySmall) }
            when (val lc = c.lifecycle) {
                is Lifecycle.Issued -> lc.claims.take(10).forEach {
                    Text("${it.path.joinToString(".")}: ${it.value.display()}", style = MaterialTheme.typography.bodySmall)
                }
                else -> Text(lc::class.simpleName ?: "", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

private fun typeLabel(c: Credential): String = when (val f = c.format) {
    is CredentialFormat.SdJwtVc -> "SD-JWT VC · ${f.vct}"
    is CredentialFormat.MsoMdoc -> "mdoc · ${f.docType}"
}

@Composable
private fun TransactionsScreen(wallet: Wallet, refreshKey: Int) {
    var entries by remember { mutableStateOf<List<TransactionLogEntry>>(emptyList()) }
    LaunchedEffect(refreshKey) { entries = wallet.transactions.history() }
    val fmt = remember { SimpleDateFormat("MM-dd HH:mm:ss", Locale.US) }
    Column(Modifier.padding(16.dp)) {
        Text("Transaction Log (${entries.size})", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        if (entries.isEmpty()) Text("No presentations yet. (In-memory; resets on restart.)", style = MaterialTheme.typography.bodyMedium)
        LazyColumn {
            items(entries) { e ->
                Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Column(Modifier.padding(12.dp)) {
                        Text("${e.type} · ${e.status}", style = MaterialTheme.typography.titleMedium)
                        Text(fmt.format(Date(e.timestamp * 1000)), style = MaterialTheme.typography.bodySmall)
                        e.relyingParty?.let { rp ->
                            Text("→ ${rp.name ?: rp.id}  ${if (rp.trusted) "✅ trusted" else "⚠️ untrusted"}", style = MaterialTheme.typography.bodySmall)
                        }
                        e.documents.forEach { d ->
                            Text("${d.type ?: d.format}: ${d.claims.joinToString(", ") { it.path.joinToString(".") }}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DebugLogScreen() {
    val lines by LogStore.lines.collectAsState()
    val clipboard = LocalClipboardManager.current
    Column(Modifier.padding(16.dp).fillMaxSize()) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Debug Log (${lines.size})", style = MaterialTheme.typography.titleLarge)
            Row {
                TextButton(onClick = { clipboard.setText(AnnotatedString(LogStore.asText())) }) { Text("Copy") }
                TextButton(onClick = { LogStore.clear() }) { Text("Clear") }
            }
        }
        Spacer(Modifier.height(8.dp))
        SelectionContainer {
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                lines.forEach { Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp) }
            }
        }
    }
}

@Composable
private fun TxCodeDialog(onSubmit: (String) -> Unit, onDismiss: () -> Unit) {
    var code by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Transaction code") },
        text = {
            OutlinedTextField(code, { code = it }, label = { Text("tx_code") }, singleLine = true)
        },
        confirmButton = { TextButton(onClick = { onSubmit(code) }, enabled = code.isNotBlank()) { Text("Issue") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ConsentDialog(request: PresentationRequest, onApprove: () -> Unit, onDecline: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDecline,
        title = { Text("Present to verifier?") },
        text = {
            Column {
                Text(request.verifier.commonName ?: request.verifier.clientId, style = MaterialTheme.typography.titleMedium)
                Text(if (request.verifier.trusted) "✅ trusted" else "⚠️ not verified", style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(8.dp))
                request.queries.forEach { q ->
                    Text("• ${q.queryId}: ${q.candidates.size} candidate(s)", style = MaterialTheme.typography.bodySmall)
                }
                if (!request.satisfiable) Text("No matching credential.", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = onApprove, enabled = request.satisfiable) { Text("Present") } },
        dismissButton = { TextButton(onClick = onDecline) { Text("Decline") } },
    )
}
