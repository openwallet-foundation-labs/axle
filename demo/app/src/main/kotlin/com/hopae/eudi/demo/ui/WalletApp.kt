package com.hopae.eudi.demo.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.IssuanceRequest
import com.hopae.eudi.wallet.IssuanceState
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.PresentationRequest
import com.hopae.eudi.wallet.PresentationSelection
import com.hopae.eudi.wallet.PresentationSession
import com.hopae.eudi.wallet.PresentationState
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.spi.CredentialFormat
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

@Composable
fun WalletApp(wallet: Wallet) {
    var tab by remember { mutableStateOf(0) }
    val tabs = listOf("Credentials", "Issue", "Present")
    Scaffold(topBar = {
        TabRow(selectedTabIndex = tab) {
            tabs.forEachIndexed { i, title ->
                Tab(selected = tab == i, onClick = { tab = i }, text = { Text(title) })
            }
        }
    }) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            when (tab) {
                0 -> CredentialsScreen(wallet)
                1 -> IssueScreen(wallet)
                else -> PresentScreen(wallet)
            }
        }
    }
}

@Composable
private fun CredentialsScreen(wallet: Wallet) {
    var creds by remember { mutableStateOf<List<Credential>>(emptyList()) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(Unit) { creds = wallet.credentials.list() }
    Column(Modifier.padding(16.dp)) {
        Button(onClick = { scope.launch { creds = wallet.credentials.list() } }) { Text("Refresh") }
        Spacer(Modifier.height(8.dp))
        if (creds.isEmpty()) {
            Text("No credentials yet — use the Issue tab.", style = MaterialTheme.typography.bodyLarge)
        }
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
                is Lifecycle.Issued -> lc.claims.take(8).forEach {
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
private fun IssueScreen(wallet: Wallet) {
    var offerUri by remember { mutableStateOf("") }
    var txCode by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Paste a credential offer (openid-credential-offer://…).") }
    val scope = rememberCoroutineScope()
    Column(Modifier.padding(16.dp).verticalScroll(rememberScrollState())) {
        OutlinedTextField(offerUri, { offerUri = it }, Modifier.fillMaxWidth(), label = { Text("Credential Offer URI") }, minLines = 2)
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(txCode, { txCode = it }, Modifier.fillMaxWidth(), label = { Text("tx_code (pre-authorized, if required)") })
        Spacer(Modifier.height(8.dp))
        Button(enabled = offerUri.isNotBlank(), onClick = {
            scope.launch {
                status = "Resolving offer…"
                runCatching {
                    val offer = wallet.issuance.resolveOffer(offerUri.trim())
                    val configId = offer.credentialConfigurationIds.first()
                    val session = wallet.issuance.start(IssuanceRequest.fromOffer(offer, configId, txCode = txCode.ifBlank { null }))
                    session.state.first { s ->
                        status = when (s) {
                            is IssuanceState.TxCodeRequired -> { session.submitTxCode(txCode); "Submitting tx_code…" }
                            is IssuanceState.AuthorizationRequired -> "Open in a browser to authorize:\n${s.authorizationUrl}"
                            is IssuanceState.Completed -> "✅ Issued ${s.result.issued.size} credential(s). Check the Credentials tab."
                            is IssuanceState.Failed -> "❌ ${s.error.message}"
                            else -> "…${s::class.simpleName}"
                        }
                        s.isTerminal
                    }
                }.onFailure { status = "❌ ${it.message}" }
            }
        }) { Text("Issue") }
        Spacer(Modifier.height(16.dp))
        Text(status)
    }
}

@Composable
private fun PresentScreen(wallet: Wallet) {
    var requestUri by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Paste a verifier request (openid4vp://…).") }
    var request by remember { mutableStateOf<PresentationRequest?>(null) }
    var session by remember { mutableStateOf<PresentationSession?>(null) }
    val scope = rememberCoroutineScope()
    Column(Modifier.padding(16.dp).verticalScroll(rememberScrollState())) {
        OutlinedTextField(requestUri, { requestUri = it }, Modifier.fillMaxWidth(), label = { Text("Verifier Request URI") }, minLines = 2)
        Spacer(Modifier.height(8.dp))
        Button(enabled = requestUri.isNotBlank(), onClick = {
            scope.launch {
                status = "Resolving request…"; request = null
                val s = wallet.presentation.start(requestUri.trim())
                session = s
                when (val resolved = s.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed }) {
                    is PresentationState.RequestResolved -> {
                        request = resolved.request
                        val v = resolved.request.verifier
                        status = "Verifier: ${v.commonName ?: v.clientId} · trusted=${v.trusted}"
                    }
                    is PresentationState.Failed -> status = "❌ ${resolved.error.message}"
                    else -> {}
                }
            }
        }) { Text("Resolve") }

        request?.let { req ->
            Spacer(Modifier.height(12.dp))
            Text("${req.queries.size} query(ies) · satisfiable=${req.satisfiable}", style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            Button(enabled = req.satisfiable, onClick = {
                scope.launch {
                    val s = session ?: return@launch
                    s.respond(PresentationSelection.auto(req))
                    status = when (val t = s.state.first { it.isTerminal }) {
                        is PresentationState.Completed -> "✅ Presented" + (t.redirectUri?.let { " → $it" } ?: "")
                        is PresentationState.Failed -> "❌ ${t.error.message}"
                        else -> t::class.simpleName ?: ""
                    }
                    request = null
                }
            }) { Text("Present (auto-select)") }
            Button(onClick = { scope.launch { session?.decline(); request = null; status = "Declined." } }) { Text("Decline") }
        }
        Spacer(Modifier.height(16.dp))
        Text(status)
    }
}
