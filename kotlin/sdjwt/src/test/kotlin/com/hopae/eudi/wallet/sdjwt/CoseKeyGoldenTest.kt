package com.hopae.eudi.wallet.sdjwt

import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseKey
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import kotlin.test.Test
import kotlin.test.assertEquals

/** Cross-language golden vectors for COSE_Key EC2 encoding (RFC 9052 §7) — shared with Swift. */
class CoseKeyGoldenTest {

    @Test
    fun coseKeyEncodingMatchesGolden() {
        val vectors = (GoldenVectors.load("cose/cose-key.json")["vectors"] as JsonValue.Arr).items
        for (v in vectors) {
            val o = v as JsonValue.Obj
            val name = (o["name"] as JsonValue.Str).value
            val curve = when ((o["crv"] as JsonValue.Str).value) {
                "P-256" -> EcCurve.P256; "P-384" -> EcCurve.P384; "P-521" -> EcCurve.P521
                else -> error("unknown curve")
            }
            val key = EcPublicKey(curve, GoldenVectors.hexToBytes((o["x"] as JsonValue.Str).value), GoldenVectors.hexToBytes((o["y"] as JsonValue.Str).value))
            val hex = GoldenVectors.toHex(CborEncoder.encode(CoseKey.encode(key)))
            assertEquals((o["hex"] as JsonValue.Str).value, hex, "cose-key '$name'")
        }
    }
}
