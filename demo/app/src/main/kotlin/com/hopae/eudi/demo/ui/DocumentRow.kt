package com.hopae.eudi.demo.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.foundation.layout.Column
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.ui.components.DocTile
import com.hopae.eudi.demo.ui.components.Pill
import com.hopae.eudi.demo.ui.components.WalletCard
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.Credential

/** A tappable document list row (tile + title + issuer + validity chip). Shared by Home and Documents. */
@Composable
fun DocumentRow(cred: Credential, onClick: () -> Unit) {
    val c = WalletTheme.colors
    WalletCard(onClick = onClick, padding = PaddingValues(13.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(13.dp)) {
            DocTile(credGlyph(cred), credGradient(cred))
            Column(Modifier.weight(1f)) {
                Text(credTitle(cred), style = MaterialTheme.typography.titleSmall, color = c.ink, maxLines = 1, overflow = TextOverflow.Ellipsis)
                cred.issuer?.displayName?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = c.inkMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            Pill("Valid", c.trustBg, c.trustDeep)
            Spacer(Modifier.size(4.dp))
            Icon(Icons.Filled.ChevronRight, null, tint = c.cardBorderStrong, modifier = Modifier.size(16.dp))
        }
    }
}
