package com.hopae.eudi.demo.ui

import androidx.compose.ui.graphics.Color
import com.hopae.eudi.demo.ui.theme.DocGradients
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.spi.CredentialFormat
import kotlin.math.absoluteValue

/** Stable "kind" of a credential, derived from its type string, used to pick a friendly name / glyph / gradient. */
private enum class DocKind { PID, MDL, AGE, PHOTOID, HEALTH, EDUCATION, RESIDENCE, FINANCE, OTHER }

private fun typeKey(c: Credential): String = when (val f = c.format) {
    is CredentialFormat.SdJwtVc -> f.vct
    is CredentialFormat.MsoMdoc -> f.docType
}

/** The credential's type identifier (SD-JWT `vct` or mdoc `docType`) — used to match transaction-log entries. */
fun credType(c: Credential): String = typeKey(c)

private fun kindOf(c: Credential): DocKind {
    val t = typeKey(c).lowercase()
    return when {
        ".av." in t || "proof_of_age" in t || "age_verification" in t -> DocKind.AGE
        "photoid" in t || "photo_id" in t -> DocKind.PHOTOID
        "pid" in t || "eudi.pid" in t || "identity" in t -> DocKind.PID
        "mdl" in t || "mdoc" in t && "18013" in t || "18013.5.1.mdl" in t || "driving" in t -> DocKind.MDL
        "ehic" in t || "health" in t || "insurance" in t -> DocKind.HEALTH
        "diploma" in t || "education" in t || "degree" in t -> DocKind.EDUCATION
        "residence" in t || "address" in t -> DocKind.RESIDENCE
        "iban" in t || "bank" in t || "account" in t || "payment" in t -> DocKind.FINANCE
        else -> DocKind.OTHER
    }
}

/** A short human title for the credential card (e.g. "Personal ID", "Mobile Driving Licence"). */
fun credTitle(c: Credential): String = when (kindOf(c)) {
    DocKind.PID -> "Personal ID"
    DocKind.MDL -> "Mobile Driving Licence"
    DocKind.AGE -> "Proof of Age"
    DocKind.PHOTOID -> "Photo ID"
    DocKind.HEALTH -> "Health Insurance Card"
    DocKind.EDUCATION -> "Education Credential"
    DocKind.RESIDENCE -> "Residence Certificate"
    DocKind.FINANCE -> "Bank Account"
    DocKind.OTHER -> prettifyType(typeKey(c))
}

/** The all-caps kicker shown on the card (e.g. "PERSONAL ID · PID"). */
fun credKicker(c: Credential): String = when (kindOf(c)) {
    DocKind.PID -> "Personal ID · PID"
    DocKind.MDL -> "Driving Licence · mDL"
    DocKind.AGE -> "Age Verification · 18+"
    DocKind.PHOTOID -> "Photo ID · ISO 23220"
    DocKind.HEALTH -> "Health · EHIC"
    DocKind.EDUCATION -> "Education"
    DocKind.RESIDENCE -> "Residence"
    DocKind.FINANCE -> "Finance"
    DocKind.OTHER -> "Credential"
}

/** The 2-letter glyph on the document tile. */
fun credGlyph(c: Credential): String = when (kindOf(c)) {
    DocKind.PID -> "ID"
    DocKind.MDL -> "DL"
    DocKind.AGE -> "18"
    DocKind.PHOTOID -> "PH"
    DocKind.HEALTH -> "HC"
    DocKind.EDUCATION -> "ED"
    DocKind.RESIDENCE -> "RC"
    DocKind.FINANCE -> "BA"
    DocKind.OTHER -> initials(credTitle(c))
}

/** The card gradient for the credential's kind (deterministic for unknown kinds). */
fun credGradient(c: Credential): List<Color> = when (kindOf(c)) {
    DocKind.PID -> DocGradients.Pid
    DocKind.MDL -> DocGradients.Mdl
    DocKind.AGE -> DocGradients.Age
    DocKind.PHOTOID -> DocGradients.PhotoId
    DocKind.HEALTH -> DocGradients.Health
    DocKind.EDUCATION -> DocGradients.Education
    DocKind.RESIDENCE -> DocGradients.Residence
    DocKind.FINANCE -> DocGradients.Finance
    DocKind.OTHER -> DocGradients.palette[(typeKey(c).hashCode().absoluteValue) % DocGradients.palette.size]
}

/** The credential format label ("mdoc" / "SD-JWT VC"). */
fun credFormatLabel(c: Credential): String = when (c.format) {
    is CredentialFormat.SdJwtVc -> "SD-JWT VC"
    is CredentialFormat.MsoMdoc -> "mdoc"
}

/** True for a Mobile Driving Licence — the one credential kind that also presents over proximity. */
fun credIsMdl(c: Credential): Boolean = kindOf(c) == DocKind.MDL

/** True for any ISO mdoc — the format that presents over proximity (ISO 18013-5 / 23220-4). */
fun credIsMdoc(c: Credential): Boolean = c.format is CredentialFormat.MsoMdoc

/** True for a Personal ID (PID) — the wallet's primary identity credential, featured as the home hero. */
fun credIsPid(c: Credential): Boolean = kindOf(c) == DocKind.PID

private fun prettifyType(raw: String): String {
    val tail = raw.substringAfterLast('/').substringAfterLast(':').substringAfterLast('.')
    return tail.replace('_', ' ').replaceFirstChar { it.uppercase() }.ifBlank { "Credential" }
}

private fun initials(name: String): String =
    name.split(' ', '-').filter { it.isNotBlank() }.take(2).joinToString("") { it.first().uppercase() }.ifBlank { "DC" }
