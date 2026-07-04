package com.hopae.eudi.wallet.sdjwt

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.cbor.cose.Ecdsa
import com.hopae.eudi.wallet.spi.AuthorizationHint
import com.hopae.eudi.wallet.spi.KeyHandle
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm
import java.util.Base64

class JoseException(message: String) : Exception(message)

object Base64Url {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)
    fun encode(text: String): String = encode(text.encodeToByteArray())
    fun decode(text: String): ByteArray = decoder.decode(text)
    fun decodeToString(text: String): String = decode(text).decodeToString()
}

val SigningAlgorithm.jwsName: String
    get() = when (this) {
        SigningAlgorithm.ES256 -> "ES256"
        SigningAlgorithm.ES384 -> "ES384"
        SigningAlgorithm.ES512 -> "ES512"
    }

fun signingAlgorithmFromJwsName(name: String): SigningAlgorithm? =
    SigningAlgorithm.entries.firstOrNull { it.jwsName == name }

/** JWS ECDSA signatures are raw r||s (RFC 7518 §3.4) — same shape the SecureArea port emits. */
interface JwsSigner {
    val algorithm: SigningAlgorithm
    suspend fun sign(signingInput: ByteArray): ByteArray
}

/** Production signer: private keys never leave the SecureArea port. */
class SecureAreaJwsSigner(
    private val area: SecureArea,
    private val key: KeyHandle,
    override val algorithm: SigningAlgorithm,
    private val hint: AuthorizationHint? = null,
) : JwsSigner {
    override suspend fun sign(signingInput: ByteArray): ByteArray =
        area.sign(key, algorithm, signingInput, hint)
}

/** Compact-serialization JWS (scratch implementation — no third-party JOSE). */
class Jws(
    val header: JsonValue.Obj,
    val headerB64: String,
    val payloadB64: String,
    val signature: ByteArray,
) {
    val payloadBytes: ByteArray get() = Base64Url.decode(payloadB64)
    val signingInput: ByteArray get() = "$headerB64.$payloadB64".encodeToByteArray()

    fun compact(): String = "$headerB64.$payloadB64.${Base64Url.encode(signature)}"

    /** Header `alg` must equal [expected] — no algorithm negotiation from attacker input. */
    fun verify(key: EcPublicKey, expected: SigningAlgorithm): Boolean {
        val alg = (header["alg"] as? JsonValue.Str)?.value ?: return false
        if (alg != expected.jwsName) return false
        return Ecdsa.verify(key, expected.coseAlgorithm, signingInput, signature)
    }

    companion object {
        fun parse(compact: String): Jws {
            val parts = compact.split('.')
            if (parts.size != 3 || parts.any { it.isEmpty() }) throw JoseException("malformed compact JWS")
            val header = runCatching { JsonValue.parse(Base64Url.decodeToString(parts[0])) }
                .getOrElse { throw JoseException("invalid JWS header") } as? JsonValue.Obj
                ?: throw JoseException("JWS header must be an object")
            return Jws(header, parts[0], parts[1], Base64Url.decode(parts[2]))
        }

        suspend fun sign(header: JsonValue.Obj, payload: ByteArray, signer: JwsSigner): Jws {
            require((header["alg"] as? JsonValue.Str)?.value == signer.algorithm.jwsName) {
                "header alg must match signer algorithm"
            }
            val h64 = Base64Url.encode(header.serialize())
            val p64 = Base64Url.encode(payload)
            val signature = signer.sign("$h64.$p64".encodeToByteArray())
            return Jws(header, h64, p64, signature)
        }
    }
}

/** cnf.jwk (EC) <-> EcPublicKey for holder key binding. */
object JwkEc {
    fun toJson(key: EcPublicKey): JsonValue.Obj = JsonValue.Obj(
        listOf(
            "kty" to JsonValue.Str("EC"),
            "crv" to JsonValue.Str(
                when (key.curve) {
                    EcCurve.P256 -> "P-256"
                    EcCurve.P384 -> "P-384"
                    EcCurve.P521 -> "P-521"
                }
            ),
            "x" to JsonValue.Str(Base64Url.encode(key.x)),
            "y" to JsonValue.Str(Base64Url.encode(key.y)),
        )
    )

    fun fromJson(jwk: JsonValue.Obj): EcPublicKey? {
        if ((jwk["kty"] as? JsonValue.Str)?.value != "EC") return null
        val curve = when ((jwk["crv"] as? JsonValue.Str)?.value) {
            "P-256" -> EcCurve.P256
            "P-384" -> EcCurve.P384
            "P-521" -> EcCurve.P521
            else -> return null
        }
        val x = (jwk["x"] as? JsonValue.Str)?.value ?: return null
        val y = (jwk["y"] as? JsonValue.Str)?.value ?: return null
        return EcPublicKey(curve, Base64Url.decode(x), Base64Url.decode(y))
    }
}
