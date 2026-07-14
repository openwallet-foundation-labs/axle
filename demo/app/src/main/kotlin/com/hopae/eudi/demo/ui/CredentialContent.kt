package com.hopae.eudi.demo.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.ui.components.InfoRow
import com.hopae.eudi.demo.ui.components.Pill
import com.hopae.eudi.demo.ui.components.PrimaryButton
import com.hopae.eudi.demo.ui.components.SectionLabel
import com.hopae.eudi.demo.ui.components.TrustRow
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.theme.DocGradients
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.Claim
import com.hopae.eudi.wallet.ClaimCategory
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.spi.CredentialFormat

/** The gradient credential card (kicker + format pill + title + issuer). Shared by document/issue detail. */
@Composable
fun CredentialGradientCard(cred: Credential) {
    Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(Brush.linearGradient(credGradient(cred))).padding(20.dp)) {
        Column {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(credKicker(cred).uppercase(), style = MaterialTheme.typography.labelSmall, color = Color.White.copy(alpha = 0.85f), modifier = Modifier.weight(1f))
                Pill(credFormatLabel(cred), Color.White.copy(alpha = 0.12f), Color.White)
            }
            Spacer(Modifier.height(22.dp))
            Text(credTitle(cred), style = MaterialTheme.typography.titleMedium, color = Color.White)
            cred.issuer?.displayName?.let {
                Spacer(Modifier.height(3.dp))
                Text(it, style = MaterialTheme.typography.bodySmall, color = Color.White.copy(alpha = 0.75f))
            }
        }
    }
}

/** The welcoming "add your first document" empty state, shown on Home and the Documents tab when nothing is stored. */
@Composable
fun AddFirstDocument(onScan: () -> Unit) {
    val c = WalletTheme.colors
    WalletCard(padding = PaddingValues(24.dp)) {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            Box(Modifier.size(60.dp).clip(RoundedCornerShape(18.dp)).background(Brush.linearGradient(DocGradients.Pid)), contentAlignment = Alignment.Center) {
                Icon(Icons.Outlined.CreditCard, null, tint = Color.White, modifier = Modifier.size(28.dp))
            }
            Spacer(Modifier.height(16.dp))
            Text("Add your first document", style = MaterialTheme.typography.titleMedium, color = c.ink)
            Spacer(Modifier.height(6.dp))
            Text(
                "Scan an issuer's QR to add your ID, driving licence and more — stored securely on this device.",
                style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(20.dp))
            PrimaryButton("Scan to add", onScan)
        }
    }
}

/** Trust panel: 2A issuer registration + 2B credential signature. */
@Composable
fun CredentialTrustCard(cred: Credential) {
    val c = WalletTheme.colors
    WalletCard(padding = PaddingValues(0.dp)) {
        TrustRow("Credential signature", trustText(cred.issuer?.trusted), cred.issuer?.trusted == true)
        Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
        TrustRow("Issuer registration", trustText(cred.issuer?.registered), cred.issuer?.registered == true)
    }
}

/** "Claims" and "Metadata" sections (SDK-classified), sensitive values masked unless [reveal]. */
@Composable
fun CredentialClaimSections(cred: Credential, reveal: Boolean) {
    val claims = (cred.lifecycle as? Lifecycle.Issued)?.claims.orEmpty()
    val personal = claims.filter { it.category != ClaimCategory.Metadata }
    val metadata = claims.filter { it.category == ClaimCategory.Metadata }
    if (personal.isNotEmpty()) {
        SectionLabel("Claims")
        ClaimsCard(cred, personal, reveal)
    }
    if (metadata.isNotEmpty()) {
        SectionLabel("Metadata")
        ClaimsCard(cred, metadata, reveal)
    }
}

/** Whether the credential has any sensitive claim (so a caller can offer a reveal toggle). */
fun hasSensitiveClaims(cred: Credential): Boolean =
    (cred.lifecycle as? Lifecycle.Issued)?.claims.orEmpty().any { isSensitive(it.path) }

@Composable
private fun ClaimsCard(cred: Credential, items: List<Claim>, reveal: Boolean) {
    WalletCard(padding = PaddingValues(0.dp)) {
        items.forEach { claim ->
            val raw = claim.value.display()
            val value = if (isSensitive(claim.path) && !reveal) mask(raw) else raw
            InfoRow(claimLabel(cred, claim.path), value)
        }
    }
}

private fun trustText(flag: Boolean?): String = when (flag) {
    true -> "Trusted"
    false -> "Not verified"
    null -> "Not checked"
}

/** mdoc claim paths start with the namespace (same for every element) — drop it for readability. */
private fun claimLabel(cred: Credential, path: List<String>): String {
    val p = if (cred.format is CredentialFormat.MsoMdoc && path.size > 1) path.drop(1) else path
    return p.joinToString(" › ") { it.replace('_', ' ').replaceFirstChar { ch -> ch.uppercase() } }
}

private val SENSITIVE = listOf("number", "identifier", "birth", "national", "iban", "administrative", "document", "passport", "ssn", "tax")
private fun isSensitive(path: List<String>): Boolean {
    val key = path.lastOrNull()?.lowercase() ?: return false
    return SENSITIVE.any { it in key }
}

private fun mask(v: String): String = v.map { if (it.isLetterOrDigit()) '•' else it }.joinToString("")
