package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.sdjwt.JwtTimeValidator
import kotlinx.coroutines.runBlocking
import java.time.Instant
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Verifies a real WRPRC (rc-wrp+jwt, JAdES B-B) issued by the deployed registrar, bound to a real WRPAC
 * leaf from the same relying party. Fixtures live in `src/test/resources`. [validAt] is inside the
 * certificate + fixture validity window (the fixtures were minted 2026-07-13).
 */
class WRPRCTest {
    private val validAt: Instant = Instant.ofEpochSecond(1_784_000_000)

    private fun bytes(res: String): ByteArray = javaClass.getResourceAsStream(res)!!.readBytes()
    private fun wrprcJwt(): String = bytes("/wrprc.jwt").decodeToString().trim()

    private fun verifier(): WRPRCVerifier {
        val ca = TrustAnchors(listOf(X509Support.parse(bytes("/registrar_ca.der"))))
        val validator = X509ChainValidator(ca, at = { Date.from(validAt) })
        return WRPRCVerifier(validator, JwtTimeValidator(now = { validAt }))
    }

    @Test
    fun realWRPRCVerifiesAndBindsToWRPAC() = runBlocking<Unit> {
        val result = verifier().verify(wrprcJwt(), bytes("/wrpac_leaf.der"))

        assertEquals("VATLU-12345678", result.subject)
        assertTrue(
            result.entitlements.contains("https://uri.etsi.org/19475/Entitlement/Service_Provider"),
        )
        assertEquals("Age verification", result.purpose.first().value)
        assertNotNull(result.status, "WRPRC should carry a status-list reference")
        assertNull(result.intermediary, "a direct (non-intermediated) WRPRC has no intermediary")
    }

    /** An intermediated WRPRC: `sub` is the final RP, and `intermediary` surfaces the intermediary. */
    @Test
    fun intermediatedWRPRC() = runBlocking<Unit> {
        val jwt = bytes("/wrprc_intermediated.jwt").decodeToString().trim()
        val result = verifier().verify(jwt, bytes("/wrpac_leaf_mediated.der"))

        assertEquals("VATLU-99998888", result.subject)
        assertEquals("LEIXG-INTERMEDIARY01", result.intermediary?.sub)
        assertEquals("Mediator", result.intermediary?.name)
    }

    /** Linkability: binding against a cert lacking the matching organizationIdentifier (the CA) is rejected. */
    @Test
    fun linkabilityMismatchRejected() = runBlocking<Unit> {
        val ex = assertFailsWith<TrustException> {
            verifier().verify(wrprcJwt(), bytes("/registrar_ca.der"))
        }
        assertTrue(ex.message!!.contains("organizationIdentifier"))
    }

    /** A tampered signature must be rejected. */
    @Test
    fun tamperedSignatureRejected() = runBlocking<Unit> {
        val jwt = wrprcJwt()
        val tampered = jwt.dropLast(1) + if (jwt.last() == 'A') 'B' else 'A'
        assertFailsWith<TrustException> {
            verifier().verify(tampered, bytes("/wrpac_leaf.der"))
        }
    }
}
