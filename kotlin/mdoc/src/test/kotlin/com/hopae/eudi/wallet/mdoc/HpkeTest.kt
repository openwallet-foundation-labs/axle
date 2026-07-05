package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import java.math.BigInteger
import java.security.spec.ECPoint
import kotlin.test.Test
import kotlin.test.assertEquals

/** Verifies the HPKE seal against RFC 9180 Appendix A.3 (DHKEM-P256-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM, base mode). */
class HpkeTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    @Test
    fun rfc9180AppendixA3BaseSeq0() {
        val info = hex("4f6465206f6e2061204772656369616e2055726e")
        val skEm = hex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb")
        val pkEm = hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
        val pkRm = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
        val aad = hex("436f756e742d30")
        val pt = hex("4265617574792069732074727574682c20747275746820626561757479")
        val expectedCt = "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"

        val recipient = EcPublicKey(EcCurve.P256, pkRm.copyOfRange(1, 33), pkRm.copyOfRange(33, 65))
        val ephPoint = ECPoint(BigInteger(1, pkEm.copyOfRange(1, 33)), BigInteger(1, pkEm.copyOfRange(33, 65)))
        val ephemeral = Hpke.Ephemeral.of(skEm, ephPoint)

        val sealed = Hpke.sealBaseP256(recipient, info, aad, pt, ephemeral)

        assertEquals(pkEm.hex(), sealed.enc.hex(), "enc must equal pkEm")
        assertEquals(expectedCt, sealed.ciphertext.hex(), "ciphertext must match RFC 9180 A.3 seq0")
    }
}
