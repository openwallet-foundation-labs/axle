package com.hopae.eudi.wallet.status

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport

/**
 * Resolves the CWT status list signer's key from the COSE `x5chain` (leaf-first DER), validating
 * the chain to a trust anchor. Implemented by the `trust` module — the same shape as mdoc's
 * issuer trust — so chain validation is reused for CWT status lists (mdoc credentials).
 */
fun interface CoseStatusKeyResolver {
    suspend fun resolve(x5chain: List<ByteArray>): EcPublicKey
}

private fun Cbor.CborMap.byText(name: String): Cbor? =
    entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == name }?.second

private fun Cbor.CborMap.byInt(label: Long): Cbor? =
    entries.firstOrNull { (k, _) ->
        when (k) {
            is Cbor.UInt -> k.value.toLong() == label
            is Cbor.NInt -> -1L - k.n.toLong() == label
            else -> false
        }
    }?.second

/** Extracts an mdoc CBOR `status = { status_list: { idx, uri } }` reference (null if absent). */
fun StatusReference.Companion.fromCbor(status: Cbor?): StatusReference? {
    val sl = (status as? Cbor.CborMap)?.byText("status_list") as? Cbor.CborMap ?: return null
    val idx = (sl.byText("idx") as? Cbor.UInt)?.value?.toLong() ?: return null
    val uri = (sl.byText("uri") as? Cbor.Text)?.value ?: return null
    return StatusReference(idx, uri)
}

/**
 * Fetches, verifies, caches and reads a **CWT** Token Status List (`statuslist+cwt`, a COSE_Sign1)
 * — the CBOR sibling of [StatusListClient] used by mdoc credentials (IETF Token Status List §5.2).
 * CWT claim keys: `sub`=2, `exp`=4, `ttl`=65534, `status_list`=65533; the `status_list` value is a
 * CBOR map `{ "bits": uint, "lst": bstr }` (raw zlib bytes, not base64url).
 */
class CwtStatusListClient(
    private val http: HttpTransport,
    private val keyResolver: CoseStatusKeyResolver,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
    private val defaultTtlSeconds: Long = 300,
) {
    private class Cached(val list: StatusList, val expiresAt: Long)

    private val cache = HashMap<String, Cached>()
    private val mutex = Any()

    suspend fun check(reference: StatusReference): CredentialStatus =
        fetchList(reference.uri).statusAt(reference.index)

    private suspend fun fetchList(uri: String): StatusList {
        val now = clock()
        synchronized(mutex) { cache[uri]?.let { if (it.expiresAt > now) return it.list } }

        val resp = http.execute(HttpRequest(HttpMethod.GET, uri, listOf("Accept" to "application/statuslist+cwt")))
        if (resp.status !in 200..299) throw StatusListException("status list fetch failed: HTTP ${resp.status}")

        val cose = CoseSign1.fromCbor(CborDecoder.decode(resp.body))
        val typ = (cose.protected.map.byInt(16) as? Cbor.Text)?.value
        if (typ != null && typ != "statuslist+cwt") throw StatusListException("unexpected status list token typ '$typ'")

        val x5chain = cose.protected.x5chain ?: cose.unprotected.x5chain
            ?: throw StatusListException("CWT status list has no x5chain")
        val key = keyResolver.resolve(x5chain) // verifies chain (throws if untrusted)
        if (!cose.verify(key)) throw StatusListException("status list token signature invalid")

        val payload = cose.payload ?: throw StatusListException("CWT status list has no payload")
        val claims = CborDecoder.decode(payload) as? Cbor.CborMap ?: throw StatusListException("CWT payload must be a map")

        val sub = (claims.byInt(2) as? Cbor.Text)?.value
        if (sub != null && sub != uri) throw StatusListException("status list token sub '$sub' does not match its URI")
        val exp = (claims.byInt(4) as? Cbor.UInt)?.value?.toLong()
        if (exp != null && exp <= now) throw StatusListException("status list token expired")

        val slClaim = claims.byInt(65533) as? Cbor.CborMap ?: throw StatusListException("missing status_list (CWT claim 65533)")
        val bits = (slClaim.byText("bits") as? Cbor.UInt)?.value?.toInt() ?: throw StatusListException("missing bits")
        val lst = (slClaim.byText("lst") as? Cbor.Bytes)?.value ?: throw StatusListException("missing lst")
        val list = StatusList.fromBitsAndCompressed(bits, lst)

        val ttl = (claims.byInt(65534) as? Cbor.UInt)?.value?.toLong()
        val expiresAt = when {
            ttl != null -> now + ttl
            exp != null -> exp
            else -> now + defaultTtlSeconds
        }
        synchronized(mutex) { cache[uri] = Cached(list, expiresAt) }
        return list
    }
}
