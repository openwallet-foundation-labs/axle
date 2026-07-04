package com.hopae.eudi.wallet.status

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseHeaders
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.cbor.cose.CoseSigner
import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm
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

class CwtStatusListTest {

    private val uri = "https://issuer.example/statuslists/cwt/1"

    private val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val publicKey: EcPublicKey = run {
        val pub = keyPair.public as ECPublicKey
        fun fixed(b: BigInteger) = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray().let { ByteArray(32 - it.size) + it }
        EcPublicKey(EcCurve.P256, fixed(pub.w.affineX), fixed(pub.w.affineY))
    }
    private val coseSigner = object : CoseSigner {
        override val algorithm = SigningAlgorithm.ES256.coseAlgorithm
        override suspend fun sign(toBeSigned: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(keyPair.private); update(toBeSigned); Der.derSignatureToRaw(sign(), 32) }
    }
    private val resolver = CoseStatusKeyResolver { publicKey }

    private fun deflate(data: ByteArray): ByteArray {
        val d = Deflater(); d.setInput(data); d.finish()
        val out = ByteArray(data.size * 2 + 64); val n = d.deflate(out); d.end()
        return out.copyOf(n)
    }

    private fun packLst(bits: Int, statuses: List<Int>): ByteArray {
        val perByte = 8 / bits
        val unpacked = ByteArray((statuses.size + perByte - 1) / perByte)
        statuses.forEachIndexed { i, s -> unpacked[i / perByte] = (unpacked[i / perByte].toInt() or (s shl ((i % perByte) * bits))).toByte() }
        return deflate(unpacked)
    }

    private fun cwt(bits: Int, statuses: List<Int>, sub: String = uri, exp: Long? = null, ttl: Long? = null, typ: String = "statuslist+cwt"): ByteArray = runBlocking {
        val claims = buildList {
            add(Cbor.int(2) to Cbor.Text(sub))
            add(Cbor.int(6) to Cbor.int(1_700_000_000))
            exp?.let { add(Cbor.int(4) to Cbor.int(it)) }
            ttl?.let { add(Cbor.int(65534) to Cbor.int(it)) }
            add(Cbor.int(65533) to Cbor.CborMap(listOf(Cbor.Text("bits") to Cbor.int(bits.toLong()), Cbor.Text("lst") to Cbor.Bytes(packLst(bits, statuses)))))
        }
        val protected = CoseHeaders(Cbor.CborMap(listOf(Cbor.int(1) to Cbor.int(-7), Cbor.int(16) to Cbor.Text(typ))))
        val unprotected = CoseHeaders(Cbor.CborMap(listOf(Cbor.int(33) to Cbor.Array(listOf(Cbor.Bytes(byteArrayOf(0x30, 0x01)))))))
        val cose = CoseSign1.sign(protected = protected, unprotected = unprotected, payload = CborEncoder.encode(Cbor.CborMap(claims)), signer = coseSigner)
        CborEncoder.encode(cose.toCbor(tagged = false))
    }

    private class CountingTransport(val body: ByteArray, val status: Int = 200) : HttpTransport {
        var calls = 0
        override suspend fun execute(request: HttpRequest): HttpResponse { calls++; return HttpResponse(status, emptyList(), body) }
    }

    private fun client(t: HttpTransport, now: Long = 1_700_000_100) = CwtStatusListClient(t, resolver, clock = { now })

    @Test
    fun readsStatusesFromCwt() = runBlocking {
        val c = client(CountingTransport(cwt(2, listOf(0, 1, 2, 0))))
        assertEquals(CredentialStatus.VALID, c.check(StatusReference(0, uri)))
        assertEquals(CredentialStatus.INVALID, c.check(StatusReference(1, uri)))
        assertEquals(CredentialStatus.SUSPENDED, c.check(StatusReference(2, uri)))
    }

    @Test
    fun cwtRevocationAndCache() = runBlocking {
        val t = CountingTransport(cwt(1, (0 until 16).map { if (it == 5) 1 else 0 }, ttl = 3600))
        val c = client(t)
        assertEquals(CredentialStatus.INVALID, c.check(StatusReference(5, uri)))
        assertEquals(CredentialStatus.VALID, c.check(StatusReference(4, uri)))
        assertEquals(1, t.calls, "cached CWT list fetched once")
    }

    @Test
    fun tamperedCwtRejected(): Unit = runBlocking {
        val good = cwt(1, List(16) { 0 })
        good[good.size - 1] = (good[good.size - 1] + 1).toByte() // corrupt the signature
        assertFailsWith<Exception> { client(CountingTransport(good)).check(StatusReference(0, uri)) }
    }

    @Test
    fun cwtSubMismatchRejected(): Unit = runBlocking {
        assertFailsWith<StatusListException> {
            client(CountingTransport(cwt(1, List(16) { 0 }, sub = "https://evil.example/list"))).check(StatusReference(0, uri))
        }
    }

    @Test
    fun cwtExpiredRejected(): Unit = runBlocking {
        assertFailsWith<StatusListException> {
            client(CountingTransport(cwt(1, List(16) { 0 }, exp = 1_700_000_050)), now = 1_700_000_100).check(StatusReference(0, uri))
        }
    }

    @Test
    fun referenceFromMdocCborStatus() {
        val status = Cbor.CborMap(
            listOf(Cbor.Text("status_list") to Cbor.CborMap(listOf(Cbor.Text("idx") to Cbor.int(99), Cbor.Text("uri") to Cbor.Text(uri))))
        )
        val ref = StatusReference.fromCbor(status)!!
        assertEquals(99L, ref.index)
        assertEquals(uri, ref.uri)
    }
}
