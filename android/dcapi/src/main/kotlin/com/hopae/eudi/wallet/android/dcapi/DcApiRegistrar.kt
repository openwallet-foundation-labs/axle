package com.hopae.eudi.wallet.android.dcapi

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.google.android.gms.identitycredentials.IdentityCredentialManager
import com.google.android.gms.identitycredentials.RegistrationRequest
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.Lifecycle
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.WalletLogger
import java.io.ByteArrayOutputStream

/** How one credential appears in the OS Digital Credentials selector: a title, subtitle, and icon (PNG bytes). */
class DcApiCredentialDisplay(val title: String, val subtitle: String, val iconPng: ByteArray?)

/**
 * Wallet branding for the Digital Credentials selector. [logoPng] is the default per-credential icon (any
 * size; it is scaled to the selector's height). Override [display] to fully control each credential's title /
 * subtitle / icon. Defaults derive the title from the credential's display name (falling back to vct/docType),
 * the subtitle from the issuer, and the icon from [logoPng].
 */
class DcApiBranding(
    val logoPng: ByteArray? = null,
    val display: (Credential) -> DcApiCredentialDisplay = { DcApiRegistrar.defaultDisplay(it, logoPng) },
)

/**
 * Registers the wallet's credentials with the Credential Manager (Digital Credentials API) using an
 * OpenID4VP-1.0-capable WASM matcher (bundled) and the low-level GMS IdentityCredentials API. The androidx
 * `OpenId4VpRegistry` bundles a matcher that does not yet handle the `openid4vp-v1-*` protocols current
 * verifiers use, so the matcher is registered directly and the v1 protocols are declared in the database.
 *
 * Per-credential title/subtitle/icon shown in the OS selector come from [DcApiBranding]; the wallet app's own
 * name and icon are shown by the platform from the app manifest.
 */
object DcApiRegistrar {
    private const val MATCHER_ASSET = "identitycredentialmatcher.wasm"
    private val PROTOCOLS = listOf(
        "openid4vp-v1-signed", "openid4vp-v1-unsigned", "openid4vp-v1-multisigned", "org-iso-mdoc",
    )

    /**
     * @param branding per-credential selector display (title/subtitle/icon); defaults derive from metadata.
     * @param matcherWasm overrides the bundled matcher; null loads the library's default asset.
     * @param logger optional trace sink (null = no logging).
     */
    suspend fun register(
        context: Context,
        wallet: Wallet,
        branding: DcApiBranding = DcApiBranding(),
        matcherWasm: ByteArray? = null,
        logger: WalletLogger? = null,
    ) {
        val creds = runCatching { wallet.credentials.list() }.getOrDefault(emptyList())
        val db = buildDatabase(creds, branding)
        val matcher = matcherWasm
            ?: runCatching { context.assets.open(MATCHER_ASSET).use { it.readBytes() } }.getOrNull()
        if (matcher == null) { logger?.log(WalletLogger.Level.Error, "DC API: matcher wasm missing"); return }
        val client = IdentityCredentialManager.getClient(context)
        // Two registrations: the androidx digital-credential type + the legacy Credman type.
        listOf("androidx.credentials.TYPE_DIGITAL_CREDENTIAL", "com.credman.IdentityCredential").forEach { type ->
            client.registerCredentials(
                RegistrationRequest(credentials = db, matcher = matcher, type = type, requestType = "", protocolTypes = emptyList()),
            )
                .addOnSuccessListener { if (type.startsWith("androidx")) logger?.log(WalletLogger.Level.Debug, "DC API: registered ${creds.size} credential(s) $PROTOCOLS") }
                .addOnFailureListener { logger?.log(WalletLogger.Level.Warn, "DC API register ($type): ${it.message}") }
        }
    }

    /** Default selector display: title = display name / vct / docType, subtitle = issuer, icon = [logoPng]. */
    fun defaultDisplay(c: Credential, logoPng: ByteArray?): DcApiCredentialDisplay {
        val type = when (val f = c.format) {
            is CredentialFormat.SdJwtVc -> f.vct
            is CredentialFormat.MsoMdoc -> f.docType
        }
        return DcApiCredentialDisplay(c.display?.name ?: type, c.issuer?.displayName ?: "", logoPng)
    }

    // ---- Credential database CBOR (matcher format) ----

    private fun txt(s: String) = Cbor.Text(s)
    private fun map(entries: List<Pair<String, Cbor>>) = Cbor.CborMap(entries.map { txt(it.first) to it.second })
    private fun field(displayName: String, value: String) =
        Cbor.Array(listOf(txt(displayName), txt(value), txt(if (value.length < 128) value else "")))

    private fun buildDatabase(creds: List<Credential>, branding: DcApiBranding): ByteArray {
        val entries = creds.mapNotNull { credentialEntry(it, branding) }
        val db = map(
            listOf(
                "protocols" to Cbor.Array(PROTOCOLS.map { txt(it) }),
                "credentials" to Cbor.Array(entries),
            ),
        )
        return CborEncoder.encode(db)
    }

    private fun credentialEntry(c: Credential, branding: DcApiBranding): Cbor? {
        val issued = c.lifecycle as? Lifecycle.Issued ?: return null
        val d = branding.display(c)
        val common = listOf(
            "title" to txt(d.title),
            "subtitle" to txt(d.subtitle),
            "bitmap" to Cbor.Bytes(resizeIcon(d.iconPng) ?: ByteArray(0)),
        )
        return when (val f = c.format) {
            is CredentialFormat.MsoMdoc -> {
                val namespaces = issued.claims.filter { it.path.size >= 2 }.groupBy { it.path[0] }.map { (ns, claims) ->
                    ns to map(claims.distinctBy { it.path[1] }.map { it.path[1] to field(it.path[1], it.value.display()) })
                }
                map(common + ("mdoc" to map(listOf(
                    "documentId" to txt(c.id.value),
                    "docType" to txt(f.docType),
                    "namespaces" to map(namespaces),
                ))))
            }
            is CredentialFormat.SdJwtVc -> {
                val claims = issued.claims.map { claim ->
                    val name = claim.path.joinToString(".")
                    name to field(name, claim.value.display())
                }
                map(common + ("sdjwt" to map(listOf(
                    "documentId" to txt(c.id.value),
                    "vct" to txt(f.vct),
                    "claims" to map(claims),
                ))))
            }
        }
    }

    /** Scales an icon to the selector height (48px, preserving aspect) and re-encodes as PNG. */
    private fun resizeIcon(png: ByteArray?): ByteArray? {
        val bitmap = BitmapFactory.decodeByteArray(png ?: return null, 0, png.size) ?: return null
        val dstHeight = 48
        val dstWidth = (dstHeight * bitmap.width / bitmap.height).coerceAtLeast(1)
        val scaled = Bitmap.createScaledBitmap(bitmap, dstWidth, dstHeight, true)
        return ByteArrayOutputStream().also { scaled.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
    }
}
