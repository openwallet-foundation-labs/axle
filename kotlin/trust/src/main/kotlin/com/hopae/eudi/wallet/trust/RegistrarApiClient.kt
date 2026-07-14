package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.sdjwt.IssuerKeyResolver
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.vp.RegisteredCredential
import java.net.URLEncoder

class RegistrarApiException(message: String) : Exception(message)

/**
 * Client for the Registrar's TS5 *RP registration* API (ETSI TS 119 472-3 / EUDI Wallet TS5), used on the
 * **dataset-only** presentation path (ETSI TS 119 475): when the request carries a self-declared
 * `registrar_dataset` but no registrar-sealed WRPRC, and the User has opted in (RPRC_16), the wallet fetches
 * the same information *registrar-signed* to confirm what the RP is registered to request (RPRC_18).
 *
 * Responses are `application/jwt` — a JWS with `typ` `wrp-registry+jwt` whose `x5c` chains to the registrar
 * CA; the signature is verified through the same [IssuerKeyResolver] the status-list client uses.
 */
class RegistrarApiClient(
    private val http: HttpTransport,
    private val keyResolver: IssuerKeyResolver,
) {
    /**
     * Fetches `GET {registryURI}/wrp/{identifier}` (the RP record), verifies the JWS against the registrar CA,
     * and returns the credentials/claims the RP is registered to request for the given intended use — the
     * authoritative input to the attribute-scope check (RPRC_21). Throws on fetch/verify failure.
     */
    suspend fun fetchRegisteredCredentials(
        registryURI: String,
        identifier: String,
        intendedUseIdentifier: String?,
    ): List<RegisteredCredential> {
        val url = "${registryURI.trimEnd('/')}/wrp/${URLEncoder.encode(identifier, Charsets.UTF_8.name())}"
        val resp = http.execute(HttpRequest(HttpMethod.GET, url, listOf("Accept" to "application/jwt")))
        if (resp.status !in 200..299) throw RegistrarApiException("registry fetch failed: HTTP ${resp.status}")

        val jws = Jws.parse(resp.body.decodeToString().trim())
        val typ = (jws.header["typ"] as? JsonValue.Str)?.value
        if (typ != null && typ != "wrp-registry+jwt") throw RegistrarApiException("unexpected registry token typ '$typ'")
        val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw RegistrarApiException("registry token payload must be JSON")
        val iss = (payload["iss"] as? JsonValue.Str)?.value ?: registryURI
        val key = keyResolver.resolve(iss, jws.header) // verifies x5c to the registrar CA (throws if untrusted)
        if (!jws.verify(key.publicKey, key.algorithm)) throw RegistrarApiException("registry token signature invalid")

        // Pick the intended-use matching the dataset's identifier (else the first) and read its credentials.
        val intendedUses = (payload["intendedUse"] as? JsonValue.Arr)?.items?.filterIsInstance<JsonValue.Obj>() ?: emptyList()
        val iu = intendedUseIdentifier
            ?.let { id -> intendedUses.firstOrNull { (it["intendedUseIdentifier"] as? JsonValue.Str)?.value == id } }
            ?: intendedUses.firstOrNull()
        return RegisteredCredential.listFromJson(iu?.get("credential") as? JsonValue.Arr)
    }
}
