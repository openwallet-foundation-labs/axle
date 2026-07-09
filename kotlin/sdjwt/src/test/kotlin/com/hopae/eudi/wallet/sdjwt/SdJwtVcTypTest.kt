package com.hopae.eudi.wallet.sdjwt

import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * draft-ietf-oauth-sd-jwt-vc §2.2.1: "The Issuer MUST include the `typ` header parameter in the SD-JWT.
 * The `typ` value MUST use `dc+sd-jwt`."
 *
 * The draft's non-normative note suggests also accepting the pre-2024-11 `vc+sd-jwt` "for a reasonable
 * transitional period". This SDK deliberately does not — these tests pin that decision so it cannot be
 * relaxed by accident.
 */
class SdJwtVcTypTest {

    private val now = Instant.parse("2026-06-01T00:00:00Z")

    private fun verifier(issuerKey: com.hopae.eudi.wallet.cbor.cose.EcPublicKey) = SdJwtVcVerifier(
        issuerKeyResolver = { _, _ -> IssuerSigningKey(issuerKey, SigningAlgorithm.ES256) },
        timeValidator = JwtTimeValidator(now = { now }),
    )

    /** Issues a PID-shaped SD-JWT VC with the given `typ` header. */
    private suspend fun issue(area: SoftwareSecureArea, typ: String): Pair<SdJwt, com.hopae.eudi.wallet.cbor.cose.EcPublicKey> {
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        var n = 0
        val sdJwt = SdJwtIssuer({ "salt-${++n}" }).issue(
            SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256),
            typ = typ,
        ) {
            claim("iss", "https://issuer.example")
            claim("vct", "urn:eudi:pid:1")
            sd("family_name", "Han")
        }
        return sdJwt to issuerKey.publicKey
    }

    @Test
    fun acceptsTheSpecifiedTyp() = runBlocking {
        val area = SoftwareSecureArea()
        val (sdJwt, issuerKey) = issue(area, "dc+sd-jwt")

        val verified = verifier(issuerKey).verify(sdJwt)

        assertEquals("urn:eudi:pid:1", verified.vct)
        assertEquals("https://issuer.example", verified.issuer)
    }

    /** The legacy value is rejected: the transition ended, and every accepted `typ` widens the type-confusion surface. */
    @Test
    fun rejectsTheLegacyVcSdJwtTyp() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val (sdJwt, issuerKey) = issue(area, "vc+sd-jwt")

        val error = assertFailsWith<SdJwtVcException> { verifier(issuerKey).verify(sdJwt) }
        assertTrue("vc+sd-jwt" in error.message!!, "the error names the offending typ: ${error.message}")
    }

    @Test
    fun rejectsAnUnrelatedTyp() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val (sdJwt, issuerKey) = issue(area, "JWT")

        assertFailsWith<SdJwtVcException> { verifier(issuerKey).verify(sdJwt) }
    }

    /** §2.2.1 makes `typ` mandatory, so an SD-JWT without one is not an SD-JWT VC. */
    @Test
    fun rejectsAMissingTyp() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val header = JsonValue.Obj(listOf("alg" to JsonValue.Str("ES256"))) // no typ
        val payload = JsonValue.Obj(
            listOf("iss" to JsonValue.Str("https://issuer.example"), "vct" to JsonValue.Str("urn:eudi:pid:1"))
        )
        val jws = Jws.sign(
            header, payload.serialize().encodeToByteArray(),
            SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256),
        ).compact()

        assertFailsWith<SdJwtVcException> { verifier(issuerKey.publicKey).verify(SdJwt.parse("$jws~")) }
    }
}
