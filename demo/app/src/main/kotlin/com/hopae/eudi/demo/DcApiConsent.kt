package com.hopae.eudi.demo

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** One requested credential in a DC API consent: a label (vct / docType) and the elements to disclose. */
class ConsentItem(val label: String, val elements: List<String>)

/**
 * The consent shown before a Digital Credentials API response is returned — the verifier and what will be
 * shared, with a Share/Decline choice (parity with the QR/link OpenID4VP flow, which also asks first).
 */
@Composable
fun DcApiConsentScreen(
    verifier: String,
    trusted: Boolean,
    items: List<ConsentItem>,
    onApprove: () -> Unit,
    onDecline: () -> Unit,
) {
    MaterialTheme {
        AlertDialog(
            onDismissRequest = onDecline,
            title = { Text("Share with verifier?") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(verifier + if (trusted) "  ✓ trusted" else "", style = MaterialTheme.typography.titleMedium)
                    items.forEach { item ->
                        Text(item.label, style = MaterialTheme.typography.labelMedium)
                        item.elements.forEach { Text("• $it", style = MaterialTheme.typography.bodyMedium) }
                    }
                }
            },
            confirmButton = { Button(onClick = onApprove) { Text("Share") } },
            dismissButton = { TextButton(onClick = onDecline) { Text("Decline") } },
        )
    }
}
