package com.hopae.eudi.demo.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import com.hopae.eudi.demo.ui.theme.WalletTheme
import java.util.Base64

/**
 * mdoc image-carrying elements (ISO 23220-2 / 18013-5: portrait, signature) arrive in the claim tree as
 * base64url text — the SDK projects CBOR bstr that way for DCQL matching — and on the reader side as raw
 * bytes. Every claim-listing surface (document detail, presentation consents, proximity, reader results)
 * detects them by element name and renders an image row instead of text.
 */
private val IMAGE_CLAIM_ELEMENTS = setOf("portrait", "enrolment_portrait_image", "signature_usual_mark")

fun isImageElement(key: String?): Boolean = key != null && key.lowercase() in IMAGE_CLAIM_ELEMENTS

fun isImageClaim(path: List<String>): Boolean = isImageElement(path.lastOrNull())

@Composable
fun rememberClaimImage(base64url: String?): ImageBitmap? = remember(base64url) {
    runCatching {
        val bytes = Base64.getUrlDecoder().decode(base64url ?: return@runCatching null)
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap()
    }.getOrNull()
}

@Composable
fun rememberClaimImage(bytes: ByteArray): ImageBitmap? = remember(bytes) {
    runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap() }.getOrNull()
}

/** An InfoRow whose value is an image thumbnail (portrait aspect, rounded) — same bottom hairline as InfoRow. */
@Composable
fun ClaimImageRow(label: String, image: ImageBitmap) {
    val c = WalletTheme.colors
    Column {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 13.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(label, style = MaterialTheme.typography.bodySmall, color = c.inkMuted, modifier = Modifier.weight(1f))
            Spacer(Modifier.width(12.dp))
            Image(
                image,
                contentDescription = label,
                modifier = Modifier.size(width = 64.dp, height = 84.dp).clip(RoundedCornerShape(8.dp)),
                contentScale = ContentScale.Crop,
            )
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(c.divider))
    }
}
