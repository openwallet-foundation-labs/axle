package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.cbor.cose.Ecdsa
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwtTimeValidator
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm
import com.hopae.eudi.wallet.vp.RegisteredCredential

/** A localized string (BCP-47 `lang` + `value`) as used in WRPRC `purpose` / `srv_description`. */
data class LocalizedText(val lang: String, val value: String)

/** The intermediary a Relying Party operates through (ETSI TS 119 475 Table 10 `intermediary`). */
data class Intermediary(
    /** The intermediary's semantic identifier (matches its own WRPAC; also carried in `act.sub`). */
    val sub: String,
    /** The intermediary's user-facing name (`sname`). */
    val name: String?,
)

/** The result of validating a Wallet-Relying Party Registration Certificate. */
data class VerifiedWRPRC(
    /**
     * `sub` — the registered semantic identifier (e.g. `VATLU-12345678`), bound to the WRPAC. For an
     * intermediated request this is always the **final** relying party, never the intermediary.
     */
    val subject: String,
    /** `name` — the relying party's display name (the final RP for an intermediated request), if present. */
    val name: String?,
    /** `entitlements` — the EU-level roles asserted for the relying party (>=1). */
    val entitlements: List<String>,
    /** `purpose` — the declared intended-use, for display on the consent screen. */
    val purpose: List<LocalizedText>,
    /** The intermediary the RP operates through, when the request is intermediated (else null). */
    val intermediary: Intermediary?,
    /**
     * The `credentials` the RP is registered to request (ETSI TS 119 475 §5.2.4) — each with its format,
     * type meta and claim paths. Registrar-attested, so it is the authoritative input to the attribute-scope
     * check (RPRC_21). Empty when the WRPRC declares no `credentials`.
     */
    val registeredCredentials: List<RegisteredCredential>,
    /** The full decoded payload, for any claim not surfaced above. */
    val claims: JsonValue.Obj,
    /** The raw `status` claim (`{ status_list: { idx, uri } }`) to feed a Token Status List check. */
    val status: JsonValue?,
)

/**
 * Validates a Wallet-Relying Party Registration Certificate (ETSI TS 119 475), a `rc-wrp+jwt` signed as
 * a JAdES baseline (B-B) signature. It verifies the JAdES signature against the registrar CA and binds the
 * WRPRC to the already-validated WRPAC that signed the request: for a direct request the WRPAC
 * `organizationIdentifier` must equal the WRPRC `sub` (GEN-5.1.1-02); for an intermediated request the
 * request is signed by the intermediary, so the WRPAC must equal `intermediary.sub`/`act.sub` (RPRC_04)
 * while `sub` remains the final RP. It also extracts the entitlements / intended-use for the consent screen.
 * The caller is responsible for the Token Status List check using the returned `status` claim.
 *
 * @param validator a chain validator built over the **registrar CA** trust anchors.
 */
class WRPRCVerifier(
    private val validator: X509ChainValidator,
    private val time: JwtTimeValidator,
) {
    /** Verify [wrprc] and bind it to the WRPAC leaf ([wrpacLeafDer], already validated by the request verifier). */
    suspend fun verify(wrprc: String, wrpacLeafDer: ByteArray): VerifiedWRPRC {
        val jws = Jws.parse(wrprc)

        // --- Protected header (ETSI TS 119 475 Table 5 + JAdES) ---
        if ((jws.header["typ"] as? JsonValue.Str)?.value != TYP) {
            throw TrustException("WRPRC typ must be $TYP")
        }
        if ((jws.header["alg"] as? JsonValue.Str)?.value != "ES256") {
            throw TrustException("WRPRC alg must be ES256")
        }
        // `crit` must only list extensions we understand, else reject (RFC 7515 §4.1.11).
        (jws.header["crit"] as? JsonValue.Arr)?.items?.forEach { entry ->
            val name = (entry as? JsonValue.Str)?.value
            if (name == null || name !in UNDERSTOOD_CRIT) {
                throw TrustException("WRPRC declares an unsupported critical header")
            }
        }
        // RFC 7797: only the standard base64url-encoded payload is supported (b64 true / absent).
        if ((jws.header["b64"] as? JsonValue.Bool)?.value == false) {
            throw TrustException("WRPRC with an unencoded (b64=false) payload is not supported")
        }

        // --- Signature: chain to the registrar CA, then verify directly (JAdES has `crit`, so
        //     Jws.verify would reject it — RFC 7515 §4.1.11). ---
        val x5c = jws.x5c ?: throw TrustException("WRPRC without x5c")
        val chain = validator.validate(x5c)
        val leaf = chain.first()

        (jws.header["x5t#S256"] as? JsonValue.Str)?.value?.let { thumb ->
            if (X509Support.sha256Thumbprint(leaf) != thumb) {
                throw TrustException("WRPRC x5t#S256 does not match the signing certificate")
            }
        }

        val key = X509Support.ecPublicKey(leaf)
        if (!Ecdsa.verify(key, SigningAlgorithm.ES256.coseAlgorithm, jws.signingInput, jws.signature)) {
            throw TrustException("WRPRC signature invalid")
        }

        // --- Payload ---
        val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw TrustException("WRPRC payload is not a JSON object")
        time.validate(payload) // `exp` is optional per TS 119 475 Table 10; iat sanity only

        val subject = (payload["sub"] as? JsonValue.Str)?.value?.takeIf { it.isNotEmpty() }
            ?: throw TrustException("WRPRC missing `sub`")
        val name = (payload["name"] as? JsonValue.Str)?.value?.takeIf { it.isNotEmpty() }

        // intermediary (Table 10) + actor claim binding (GEN-5.2.4-09): when the RP operates through an
        // intermediary, `act.sub` must equal the intermediary's identifier.
        val intermediaryObj = payload["intermediary"] as? JsonValue.Obj
        val intermediary = (intermediaryObj?.get("sub") as? JsonValue.Str)?.value?.let { intSub ->
            val actSub = ((payload["act"] as? JsonValue.Obj)?.get("sub") as? JsonValue.Str)?.value
            if (actSub != null && actSub != intSub) {
                throw TrustException("WRPRC act.sub ($actSub) does not match intermediary.sub ($intSub)")
            }
            Intermediary(intSub, (intermediaryObj["sname"] as? JsonValue.Str)?.value)
        }

        // Linkability (GEN-5.1.1-02 / RPRC_04): the Request Object is signed by a WRPAC whose
        // organizationIdentifier must equal the entity that actually sent the request. For a DIRECT request
        // that entity is the relying party itself (WRPRC `sub`); for an INTERMEDIATED request the signer is
        // the *intermediary*, so bind the presented WRPAC to `act`/`intermediary.sub` (the intermediary's own
        // access certificate) — `sub` stays the final RP, for display only.
        val orgId = X509Support.organizationIdentifierFromDer(wrpacLeafDer)
            ?: throw TrustException("WRPAC has no organizationIdentifier to bind the WRPRC against")
        val boundIdentity = intermediary?.sub ?: subject
        if (orgId != boundIdentity) {
            val role = if (intermediary != null) "intermediary.sub" else "`sub`"
            throw TrustException("WRPRC $role ($boundIdentity) does not match WRPAC organizationIdentifier ($orgId)")
        }

        // entitlements (>=1 EU-level role, GEN-5.2.4-03).
        val entitlements = (payload["entitlements"] as? JsonValue.Arr)?.items
            ?.mapNotNull { (it as? JsonValue.Str)?.value } ?: emptyList()
        if (entitlements.isEmpty()) throw TrustException("WRPRC declares no entitlements")

        // purpose (intended-use, localized).
        val purpose = (payload["purpose"] as? JsonValue.Arr)?.items?.mapNotNull { item ->
            val obj = item as? JsonValue.Obj ?: return@mapNotNull null
            val lang = (obj["lang"] as? JsonValue.Str)?.value ?: return@mapNotNull null
            val value = (obj["value"] as? JsonValue.Str)?.value ?: return@mapNotNull null
            LocalizedText(lang, value)
        } ?: emptyList()

        // `credentials` (§5.2.4) — the attestation types + claim paths the RP is registered to request.
        val registeredCredentials = RegisteredCredential.listFromJson(payload["credentials"] as? JsonValue.Arr)

        return VerifiedWRPRC(subject, name, entitlements, purpose, intermediary, registeredCredentials, payload, payload["status"])
    }

    companion object {
        const val TYP = "rc-wrp+jwt"
        private val UNDERSTOOD_CRIT = setOf("sigT", "b64")
    }
}
