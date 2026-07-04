package com.hopae.eudi.wallet.status

import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.IssuerKeyResolver
import com.hopae.eudi.wallet.sdjwt.IssuerSigningKey
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import kotlinx.coroutines.runBlocking
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.zip.Deflater
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class StatusListTest {

    private val uri = "https://issuer.example/statuslists/1"

    // ---- test key + signer ----
    private val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val publicKey: EcPublicKey = run {
        val pub = keyPair.public as ECPublicKey
        fun fixed(b: BigInteger) = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray().let { ByteArray(32 - it.size) + it }
        EcPublicKey(EcCurve.P256, fixed(pub.w.affineX), fixed(pub.w.affineY))
    }
    private val signer = object : JwsSigner {
        override val algorithm = SigningAlgorithm.ES256
        override suspend fun sign(signingInput: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(keyPair.private); update(signingInput); Der.derSignatureToRaw(sign(), 32) }
    }
    private val resolver = IssuerKeyResolver { _, _ -> IssuerSigningKey(publicKey, SigningAlgorithm.ES256) }

    private fun deflate(data: ByteArray): ByteArray {
        val d = Deflater(); d.setInput(data); d.finish()
        val out = ByteArray(data.size * 2 + 64); val n = d.deflate(out); d.end()
        return out.copyOf(n)
    }

    private fun packLst(bits: Int, statuses: List<Int>): String {
        val perByte = 8 / bits
        val unpacked = ByteArray((statuses.size + perByte - 1) / perByte)
        statuses.forEachIndexed { i, s -> unpacked[i / perByte] = (unpacked[i / perByte].toInt() or (s shl ((i % perByte) * bits))).toByte() }
        return Base64Url.encode(deflate(unpacked))
    }

    private fun token(bits: Int, statuses: List<Int>, sub: String = uri, exp: Long? = null, ttl: Long? = null): String = runBlocking {
        val payload = buildList {
            add("sub" to JsonValue.Str(sub))
            add("iat" to JsonValue.NumInt(1_700_000_000))
            exp?.let { add("exp" to JsonValue.NumInt(it)) }
            ttl?.let { add("ttl" to JsonValue.NumInt(it)) }
            add("status_list" to JsonValue.Obj(listOf("bits" to JsonValue.NumInt(bits.toLong()), "lst" to JsonValue.Str(packLst(bits, statuses)))))
        }
        val header = JsonValue.Obj(listOf("typ" to JsonValue.Str("statuslist+jwt"), "alg" to JsonValue.Str("ES256")))
        Jws.sign(header, JsonValue.Obj(payload).serialize().encodeToByteArray(), signer).compact()
    }

    private class CountingTransport(val body: String, val status: Int = 200) : HttpTransport {
        var calls = 0
        override suspend fun execute(request: HttpRequest): HttpResponse {
            calls++
            return HttpResponse(status, emptyList(), body.encodeToByteArray())
        }
    }

    private fun transport(body: String, status: Int = 200) = CountingTransport(body, status)

    private fun client(t: HttpTransport, now: Long = 1_700_000_100) = StatusListClient(t, resolver, clock = { now })

    // ---- tests ----

    @Test
    fun readsStatusesAcrossBits() = runBlocking {
        // bits=2: idx0 VALID, idx1 INVALID, idx2 SUSPENDED, idx3 VALID
        val client = client(transport(token(2, listOf(0, 1, 2, 0))))
        assertEquals(CredentialStatus.VALID, client.check(StatusReference(0, uri)))
        assertEquals(CredentialStatus.INVALID, client.check(StatusReference(1, uri)))
        assertEquals(CredentialStatus.SUSPENDED, client.check(StatusReference(2, uri)))
        assertEquals(CredentialStatus.VALID, client.check(StatusReference(3, uri)))
    }

    @Test
    fun oneBitRevocation() = runBlocking {
        val statuses = (0 until 20).map { if (it == 7 || it == 13) 1 else 0 }
        val client = client(transport(token(1, statuses)))
        assertEquals(CredentialStatus.VALID, client.check(StatusReference(6, uri)))
        assertEquals(CredentialStatus.INVALID, client.check(StatusReference(7, uri)))
        assertEquals(CredentialStatus.INVALID, client.check(StatusReference(13, uri)))
    }

    @Test
    fun cachesAcrossChecks() = runBlocking {
        val t = transport(token(1, List(16) { 0 }, ttl = 3600))
        val client = client(t)
        repeat(5) { client.check(StatusReference(it.toLong(), uri)) }
        assertEquals(1, t.calls, "a cached (ttl) list must be fetched only once for a batch of checks")
    }

    @Test
    fun fromClaimsExtractsReference() {
        val claims = JsonValue.parse("""{"vct":"x","status":{"status_list":{"idx":42,"uri":"$uri"}}}""") as JsonValue.Obj
        val ref = StatusReference.fromClaims(claims)!!
        assertEquals(42L, ref.index)
        assertEquals(uri, ref.uri)
    }

    @Test
    fun unlistedCredentialIsValid() = runBlocking {
        val claims = JsonValue.parse("""{"vct":"x"}""") as JsonValue.Obj
        assertEquals(CredentialStatus.VALID, client(transport("")).check(claims))
    }

    @Test
    fun tamperedTokenRejected(): Unit = runBlocking {
        val good = token(1, List(16) { 0 })
        val parts = good.split(".")
        val forged = parts[0] + "." + Base64Url.encode("""{"sub":"$uri","status_list":{"bits":1,"lst":"eJw"}}""") + "." + parts[2]
        assertFailsWith<StatusListException> { client(transport(forged)).check(StatusReference(0, uri)) }
    }

    @Test
    fun subMismatchRejected(): Unit = runBlocking {
        val client = client(transport(token(1, List(16) { 0 }, sub = "https://evil.example/list")))
        assertFailsWith<StatusListException> { client.check(StatusReference(0, uri)) }
    }

    @Test
    fun expiredTokenRejected(): Unit = runBlocking {
        val client = client(transport(token(1, List(16) { 0 }, exp = 1_700_000_050)), now = 1_700_000_100)
        assertFailsWith<StatusListException> { client.check(StatusReference(0, uri)) }
    }

    @Test
    fun indexOutOfRangeRejected(): Unit = runBlocking {
        val client = client(transport(token(1, List(8) { 0 })))
        assertFailsWith<StatusListException> { client.check(StatusReference(9999, uri)) }
    }
}
