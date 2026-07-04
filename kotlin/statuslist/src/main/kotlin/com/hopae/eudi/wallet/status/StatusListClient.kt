package com.hopae.eudi.wallet.status

import com.hopae.eudi.wallet.sdjwt.IssuerKeyResolver
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport

/**
 * Fetches, verifies, caches and reads IETF Token Status Lists to resolve credential revocation
 * (draft-ietf-oauth-status-list). The status list token (`statuslist+jwt`) is verified through an
 * [IssuerKeyResolver] — the same port the `trust` module implements for x5c, so chain validation
 * is reused. Lists are cached until `ttl`/`exp`, so a batch of checks costs one fetch.
 */
class StatusListClient(
    private val http: HttpTransport,
    private val keyResolver: IssuerKeyResolver,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
    /** Fallback cache lifetime when the token carries neither `ttl` nor `exp`. */
    private val defaultTtlSeconds: Long = 300,
) {
    private class Cached(val list: StatusList, val expiresAt: Long)

    private val cache = HashMap<String, Cached>()
    private val mutex = Any()

    /** Resolves the status of the credential pointed at by [reference]. */
    suspend fun check(reference: StatusReference): CredentialStatus =
        fetchList(reference.uri).statusAt(reference.index)

    /** Convenience: resolve a credential's status from its claims, VALID-by-default if unlisted. */
    suspend fun check(claims: JsonValue.Obj): CredentialStatus {
        val reference = StatusReference.fromClaims(claims) ?: return CredentialStatus.VALID
        return check(reference)
    }

    private suspend fun fetchList(uri: String): StatusList {
        val now = clock()
        synchronized(mutex) { cache[uri]?.let { if (it.expiresAt > now) return it.list } }

        val resp = http.execute(HttpRequest(HttpMethod.GET, uri, listOf("Accept" to "application/statuslist+jwt")))
        if (resp.status !in 200..299) throw StatusListException("status list fetch failed: HTTP ${resp.status}")

        val jws = Jws.parse(resp.body.decodeToString().trim())
        val header = jws.header
        val typ = (header["typ"] as? JsonValue.Str)?.value
        if (typ != null && typ != "statuslist+jwt") throw StatusListException("unexpected status list token typ '$typ'")

        val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw StatusListException("status list token payload must be JSON")
        val sub = (payload["sub"] as? JsonValue.Str)?.value
        if (sub != null && sub != uri) throw StatusListException("status list token sub '$sub' does not match its URI")
        (payload["exp"] as? JsonValue.NumInt)?.value?.let { if (it <= now) throw StatusListException("status list token expired") }

        val iss = (payload["iss"] as? JsonValue.Str)?.value ?: sub ?: uri
        val key = keyResolver.resolve(iss, header) // verifies x5c / resolves the signer (throws if untrusted)
        if (!jws.verify(key.publicKey, key.algorithm)) throw StatusListException("status list token signature invalid")

        val list = StatusList.fromTokenPayload(payload)
        val ttl = (payload["ttl"] as? JsonValue.NumInt)?.value
        val exp = (payload["exp"] as? JsonValue.NumInt)?.value
        val expiresAt = when {
            ttl != null -> now + ttl
            exp != null -> exp
            else -> now + defaultTtlSeconds
        }
        synchronized(mutex) { cache[uri] = Cached(list, expiresAt) }
        return list
    }
}
