package com.hopae.eudi.demo.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.demo.security.AppLock
import com.hopae.eudi.demo.security.BiometricAuth
import com.hopae.eudi.demo.security.WalletSecurity
import com.hopae.eudi.demo.ui.components.InfoRow
import com.hopae.eudi.demo.ui.components.PrimaryButton
import com.hopae.eudi.demo.ui.components.SecondaryButton
import com.hopae.eudi.demo.ui.components.SectionLabel
import com.hopae.eudi.demo.ui.components.TrustBadge
import com.hopae.eudi.demo.ui.components.TrustRow
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.components.absorbTouches
import com.hopae.eudi.demo.ui.credTitle
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.ClaimCategory
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.PresentationRequest
import com.hopae.eudi.wallet.PresentationSelection
import com.hopae.eudi.wallet.PresentationSession
import com.hopae.eudi.wallet.PresentationState
import com.hopae.eudi.wallet.PurposeText
import com.hopae.eudi.wallet.QueryPresentation
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.spi.CredentialId
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.util.Locale

private enum class PresentStep { Review, Sharing, Shared, Failed }

@Composable
fun PresentScreen(
    request: PresentationRequest,
    session: PresentationSession,
    wallet: Wallet,
    onDone: () -> Unit,
    onCancel: () -> Unit,
) {
    val c = WalletTheme.colors
    val ctx = LocalContext.current
    val activity = ctx as? FragmentActivity
    val scope = rememberCoroutineScope()
    var step by remember { mutableStateOf(PresentStep.Review) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirmCancel by remember { mutableStateOf(false) }

    var credsById by remember { mutableStateOf<Map<String, Credential>>(emptyMap()) }
    LaunchedEffect(Unit) {
        credsById = runCatching { wallet.credentials.list().associateBy { it.id.value } }.getOrDefault(emptyMap())
    }

    // Per-query chosen credential(s) — one for a radio (multiple:false) query, ≥1 for a checkbox
    // (multiple:true) query — and whether an optional query is included.
    val chosen = remember { mutableStateMapOf<String, List<CredentialId>>() }
    val included = remember { mutableStateMapOf<String, Boolean>() }
    LaunchedEffect(request) {
        request.queries.forEach { q ->
            chosen[q.queryId] = q.candidates.firstOrNull()?.let { listOf(it.credentialId) } ?: emptyList()
            included[q.queryId] = q.required // required always on; optional off until opted-in
        }
    }

    fun buildSelection(): PresentationSelection {
        val map = buildMap {
            request.queries.forEach { q ->
                if (q.candidates.isEmpty()) return@forEach
                if (q.required || included[q.queryId] == true) {
                    val ids = chosen[q.queryId]?.takeIf { it.isNotEmpty() } ?: listOf(q.candidates.first().credentialId)
                    put(q.queryId, ids)
                }
            }
        }
        return PresentationSelection(map)
    }

    fun doShare() {
        step = PresentStep.Sharing
        scope.launch {
            runCatching {
                session.respond(buildSelection())
                when (val t = session.state.first { it.isTerminal }) {
                    is PresentationState.Completed -> {
                        LogStore.log("✅ Presented")
                        // Same-device return: the verifier supplies a redirect_uri (carrying a one-time
                        // response_code) the wallet MUST follow — it hands the user back to the verifier, which
                        // shows the result. On success reset to home (the verifier now owns the result screen);
                        // with no redirect (cross-device) or if the browser can't open, fall back to Shared.
                        val redirect = t.redirectUri
                        val opened = redirect != null && runCatching {
                            AppLock.suppressResumeLock() // returning from the browser shouldn't demand a re-unlock
                            ctx.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse(redirect)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                            )
                        }.onFailure { LogStore.log("❌ open redirect_uri: ${it.message}") }.isSuccess
                        if (opened) onDone() else step = PresentStep.Shared
                    }
                    is PresentationState.Failed -> { error = t.error.message; step = PresentStep.Failed }
                    else -> { error = "Unexpected state"; step = PresentStep.Failed }
                }
            }.onFailure { error = it.message; step = PresentStep.Failed; LogStore.log("❌ Present: ${it.message}") }
        }
    }

    fun share() {
        val useBio = activity != null && WalletSecurity.biometricEnabled(ctx) && BiometricAuth.canUse(activity)
        if (useBio) BiometricAuth.prompt(activity, "Confirm sharing", "Verify to share the selected data", onSuccess = { doShare() }, negativeText = "Cancel")
        else doShare()
    }

    fun back() {
        when (step) {
            PresentStep.Review -> confirmCancel = true
            PresentStep.Shared -> onDone()
            PresentStep.Failed -> onCancel()
            PresentStep.Sharing -> {}
        }
    }
    BackHandler { back() }

    val topInset = WindowInsets.statusBars.asPaddingValues().calculateTopPadding()
    val bottomInset = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()

    Column(
        Modifier.fillMaxSize().background(c.screen).absorbTouches()
            .padding(start = 20.dp, end = 20.dp, top = topInset + 12.dp, bottom = bottomInset + 20.dp),
    ) {
        if (step == PresentStep.Review) {
            Text("Sharing request", style = MaterialTheme.typography.titleMedium, color = c.ink)
            Spacer(Modifier.height(16.dp))
        }
        Box(Modifier.weight(1f).fillMaxWidth()) {
            when (step) {
                PresentStep.Review -> ReviewRequest(request, credsById, chosen, included, onShare = { share() }, onDecline = { confirmCancel = true })
                PresentStep.Sharing -> Centered { PresentProgress("Sharing…", "Sending the selected data to the verifier.") }
                PresentStep.Shared -> Centered { PresentDone("Shared", "The verifier received the selected data.", onDone = onDone) }
                PresentStep.Failed -> Centered { PresentFailed("Couldn't share", error ?: "The presentation failed.", onClose = onCancel) }
            }
        }
    }

    if (confirmCancel) {
        AlertDialog(
            onDismissRequest = { confirmCancel = false },
            title = { Text("Decline this request?") },
            text = { Text("Nothing will be shared with the verifier.") },
            confirmButton = { TextButton(onClick = { confirmCancel = false; scope.launch { runCatching { session.decline() }; onCancel() } }) { Text("Decline", color = c.danger) } },
            dismissButton = { TextButton(onClick = { confirmCancel = false }) { Text("Keep") } },
        )
    }
}

@Composable
private fun ReviewRequest(
    request: PresentationRequest,
    credsById: Map<String, Credential>,
    chosen: MutableMap<String, List<CredentialId>>,
    included: MutableMap<String, Boolean>,
    onShare: () -> Unit,
    onDecline: () -> Unit,
) {
    val c = WalletTheme.colors
    val v = request.verifier
    val reg = v.registration
    // Show the actual (final) relying party. For an intermediated request the signing cert's commonName is the
    // intermediary, so prefer the WRPRC subject name and surface the intermediary separately as "via …".
    val rpName = reg?.subjectName ?: reg?.subject?.takeIf { it.isNotBlank() } ?: v.commonName ?: v.clientId
    val rpSubtitle = reg?.intermediaryName?.let { "via $it" } ?: v.clientId
    // Required queries first, so the screen reads shared-then-optional overall.
    val orderedQueries = request.queries.sortedByDescending { it.required }
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            // Verifier
            WalletCard {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Box(Modifier.size(42.dp).clip(RoundedCornerShape(12.dp)).background(c.ink), contentAlignment = Alignment.Center) {
                        Text(rpName.take(1).uppercase(), color = Color.White, style = MaterialTheme.typography.titleMedium)
                    }
                    Column(Modifier.weight(1f)) {
                        Text(rpName, style = MaterialTheme.typography.titleSmall, color = c.ink)
                        Text(rpSubtitle, style = MaterialTheme.typography.bodySmall, color = c.inkMuted, maxLines = 1)
                    }
                    TrustBadge(v.trusted, trustedText = "Verified", untrustedText = "Unverified")
                }
            }
            // Trust: whether the signed request and the RP's registration (WRPRC) verified.
            SectionLabel("Trust")
            WalletCard(padding = PaddingValues(0.dp)) {
                TrustRow("Signed request", if (v.trusted) "Verified" else "Not verified", v.trusted)
                if (reg != null) {
                    val wrprcOk = reg.attested || reg.registrarVerified
                    val wrprcText = when {
                        reg.attested -> "Verified by registrar"
                        reg.registrarVerified -> "Confirmed online"
                        else -> "Self-declared"
                    }
                    TrustRow("Registration (WRPRC)", wrprcText, wrprcOk)
                    reg.statusValid?.let { TrustRow("Registration status", if (it) "Valid" else "Revoked", it) }
                } else {
                    TrustRow("Registration (WRPRC)", "None", false)
                }
            }
            // Purpose
            purposeText(reg?.purpose)?.let {
                SectionLabel("Purpose")
                WalletCard { Text(it, style = MaterialTheme.typography.bodyMedium, color = c.ink) }
            }
            // Over-asking warning (RPRC_21)
            reg?.unregisteredClaims?.takeIf { it.isNotEmpty() }?.let {
                WalletCard {
                    Text("⚠ This verifier is requesting attributes it isn't registered for.", style = MaterialTheme.typography.bodyMedium, color = c.danger)
                }
            }

            // Per-query documents + claims
            SectionLabel("You'll share")
            orderedQueries.forEach { q ->
                QueryCard(q, credsById, chosen, included)
            }
            Text("Required attributes are always shared; optional ones are off unless you turn them on. Everything else stays on this device.", style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            SecondaryButton("Decline", onDecline, Modifier.weight(1f))
            PrimaryButton("Share", onShare, Modifier.weight(1.5f), enabled = request.satisfiable)
        }
    }
}

@Composable
private fun QueryCard(
    q: QueryPresentation,
    credsById: Map<String, Credential>,
    chosen: MutableMap<String, List<CredentialId>>,
    included: MutableMap<String, Boolean>,
) {
    val c = WalletTheme.colors
    val willShare = q.required || included[q.queryId] == true
    val selectedIds = chosen[q.queryId].orEmpty()
    val primaryId = selectedIds.firstOrNull() ?: q.candidates.firstOrNull()?.credentialId
    val primaryCand = q.candidates.firstOrNull { it.credentialId == primaryId } ?: q.candidates.firstOrNull()
    val primaryCred = credsById[primaryId?.value]

    // Split the chosen credential's Subject claims into requested (shared/optional) vs. the rest (private).
    val allClaims = (primaryCred?.lifecycle as? Lifecycle.Issued)?.claims.orEmpty()
    val metadataPaths = allClaims.filter { it.category == ClaimCategory.Metadata }.map { it.path }.toSet()
    val disclosedSet = primaryCand?.disclosedPaths?.toSet().orEmpty()
    val disclosedSubject = disclosedSet.filter { it !in metadataPaths }
    // A leaf is disclosed if a requested path equals it or is a prefix of it (an object request covers its leaves).
    fun disclosed(path: List<String>) = disclosedSet.any { d -> d.size <= path.size && path.subList(0, d.size) == d }
    val notShared = allClaims.filter { it.category == ClaimCategory.Subject && !disclosed(it.path) }.map { it.path }

    WalletCard(padding = PaddingValues(0.dp)) {
        // header: document + optional toggle
        Row(Modifier.fillMaxWidth().padding(16.dp, 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                val title = primaryCred?.let { credTitle(it) } ?: q.queryId
                Text(title, style = MaterialTheme.typography.titleSmall, color = if (willShare) c.ink else c.inkFaint)
                Text(if (q.required) "Required" else "Optional", style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
            }
            if (!q.required) {
                Switch(
                    checked = willShare, onCheckedChange = { included[q.queryId] = it },
                    colors = SwitchDefaults.colors(checkedThumbColor = Color.White, checkedTrackColor = c.brand),
                )
            }
        }

        if (q.candidates.isEmpty()) {
            Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
            Text("No matching document in your wallet.", style = MaterialTheme.typography.bodySmall, color = c.danger, modifier = Modifier.padding(16.dp, 12.dp))
            return@WalletCard
        }

        // Credential picker when the query matches more than one stored credential:
        // radio for a single-pick query, checkboxes for a multiple:true query.
        if (q.candidates.size > 1) {
            Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
            q.candidates.forEach { cand ->
                val checked = cand.credentialId in selectedIds
                val onPick: () -> Unit = {
                    chosen[q.queryId] = if (q.multiple) {
                        if (checked) (selectedIds - cand.credentialId).ifEmpty { selectedIds } // keep ≥1
                        else selectedIds + cand.credentialId
                    } else listOf(cand.credentialId)
                }
                CandidateRow(
                    label = credsById[cand.credentialId.value]?.let { credTitle(it) } ?: cand.credentialId.value,
                    checked = checked, multiple = q.multiple, onClick = onPick,
                )
            }
        }

        // Requested attributes — "Shared" (required) or the optional group's disclosure.
        Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
        GroupHeader(if (q.required) "Shared" else "Optional")
        if (disclosedSubject.isEmpty()) {
            Text("No personal attributes.", style = MaterialTheme.typography.bodySmall, color = c.inkMuted, modifier = Modifier.padding(16.dp, 6.dp, 16.dp, 12.dp))
        } else {
            disclosedSubject.forEach { path ->
                InfoRow(claimPathLabel(path), if (willShare) "Shared" else "Off", if (willShare) c.trust else c.inkFaint)
            }
        }

        // The chosen credential's remaining attributes — shown for transparency, never sent.
        if (notShared.isNotEmpty()) {
            GroupHeader("Not shared")
            notShared.forEach { path -> InfoRow(claimPathLabel(path), "Private", c.inkFaint) }
        }
    }
}

/** A radio (single-pick) or checkbox (multiple) credential-selection row. */
@Composable
private fun CandidateRow(label: String, checked: Boolean, multiple: Boolean, onClick: () -> Unit) {
    val c = WalletTheme.colors
    val shape = if (multiple) RoundedCornerShape(5.dp) else RoundedCornerShape(99.dp)
    Row(
        Modifier.fillMaxWidth().clickable { onClick() }.padding(16.dp, 10.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            Modifier.size(18.dp).clip(shape)
                .border(2.dp, if (checked) c.brand else c.cardBorderStrong, shape)
                .background(if (checked) c.brand else Color.Transparent),
            contentAlignment = Alignment.Center,
        ) { if (checked) Icon(Icons.Filled.Check, null, tint = Color.White, modifier = Modifier.size(11.dp)) }
        Text(label, style = MaterialTheme.typography.bodyMedium, color = c.ink, modifier = Modifier.weight(1f))
    }
}

private fun purposeText(purpose: List<PurposeText>?): String? {
    if (purpose.isNullOrEmpty()) return null
    val lang = Locale.getDefault().language
    return (purpose.firstOrNull { it.lang.startsWith(lang, true) } ?: purpose.first()).value
}
