package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import java.security.MessageDigest
import java.time.Instant

/**
 * The Document Signer resolved from an mdoc `issuerAuth` x5chain: the key that signed the MSO, plus the
 * validity window of the certificate carrying it.
 *
 * [notBefore]/[notAfter] exist for ISO 18013-5 §9.3.1 step 5 — "the 'signed' date is within the validity
 * period of the certificate in the MSO header" — a check on the *signing moment*, distinct from the chain
 * validation of step 1, which runs at the verifier's own clock. Null means the trust implementation could not
 * supply the window, and the check is skipped; the shipped `X5cMdocIssuerTrust` always supplies it.
 */
class MdocIssuerKey(
    val key: EcPublicKey,
    val notBefore: Instant? = null,
    val notAfter: Instant? = null,
)

/**
 * Resolves the mdoc issuer's Document Signer from the `issuerAuth` x5chain, validating the chain to
 * a trust anchor. Implemented by the `trust` module (mirrors SD-JWT VC's IssuerKeyResolver).
 */
fun interface MdocIssuerTrust {
    suspend fun issuerKey(x5chain: List<ByteArray>): MdocIssuerKey
}

/** A verified mdoc: integrity-checked disclosed elements plus the holder (device) binding. */
class VerifiedMdoc(
    val docType: String,
    val deviceKey: EcPublicKey,
    /** namespace -> (elementIdentifier -> value). */
    val elements: Map<String, Map<String, Cbor>>,
    val signed: Instant,
    val validFrom: Instant,
    val validUntil: Instant,
)

/**
 * Verifies an mdoc `IssuerSigned` (ISO 18013-5 §9.1.2): resolves + trusts the issuer key from
 * the COSE x5chain, verifies the `issuerAuth` COSE_Sign1 over the MSO, checks every disclosed
 * element's digest against the MSO `valueDigests`, and enforces `validityInfo`.
 */
class MdocVerifier(
    private val trust: MdocIssuerTrust,
    private val now: () -> Instant = { Instant.now() },
) {
    suspend fun verify(issuerSigned: IssuerSigned): VerifiedMdoc {
        val x5chain = issuerSigned.issuerCertChain ?: throw MdocException("issuerAuth has no x5chain")
        val issuer = trust.issuerKey(x5chain) // §9.3.1 step 1: chain validated to a trust anchor

        val cose = issuerSigned.issuerAuth
        if (!cose.verify(issuer.key)) throw MdocException("issuerAuth signature invalid") // step 2

        val mso = issuerSigned.parseMso()

        // ISO 18013-5 §9.1.2.5 / Table 21: readers must support SHA-256, SHA-384 and SHA-512.
        val digestAlgorithm = when (mso.digestAlgorithm.uppercase()) {
            "SHA-256" -> "SHA-256"
            "SHA-384" -> "SHA-384"
            "SHA-512" -> "SHA-512"
            else -> throw MdocException("unsupported MSO digest algorithm ${mso.digestAlgorithm}")
        }

        // §9.3.1 step 5: validate ValidityInfo. The 'signed' date must fall inside the Document Signer
        // certificate's own validity period — an MSO signed before the DS existed, or after it expired, is not
        // something that certificate ever vouched for, however the chain validates at the verifier's clock.
        mso.signed.let { signed ->
            issuer.notBefore?.let {
                if (signed.isBefore(it)) throw MdocException("MSO signed=$signed predates the DS certificate (notBefore=$it)")
            }
            issuer.notAfter?.let {
                if (signed.isAfter(it)) throw MdocException("MSO signed=$signed postdates the DS certificate (notAfter=$it)")
            }
        }
        val instant = now()
        if (instant.isBefore(mso.validFrom)) throw MdocException("mdoc not yet valid (validFrom=${mso.validFrom})")
        if (instant.isAfter(mso.validUntil)) throw MdocException("mdoc expired (validUntil=${mso.validUntil})")

        val elements = mutableMapOf<String, MutableMap<String, Cbor>>()
        for ((namespace, items) in issuerSigned.nameSpaces) {
            val nsDigests = mso.valueDigests[namespace]
                ?: throw MdocException("MSO has no digests for namespace '$namespace'")
            for (entry in items) {
                val expected = nsDigests[entry.item.digestId]
                    ?: throw MdocException("no MSO digest for ${namespace}/${entry.item.digestId}")
                val actual = MessageDigest.getInstance(digestAlgorithm).digest(entry.itemBytes)
                if (!actual.contentEquals(expected)) {
                    throw MdocException("digest mismatch for ${namespace}/${entry.item.elementIdentifier}")
                }
                elements.getOrPut(namespace) { mutableMapOf() }[entry.item.elementIdentifier] = entry.item.elementValue
            }
        }

        return VerifiedMdoc(
            docType = mso.docType,
            deviceKey = mso.deviceKey,
            elements = elements,
            signed = mso.signed,
            validFrom = mso.validFrom,
            validUntil = mso.validUntil,
        )
    }
}
