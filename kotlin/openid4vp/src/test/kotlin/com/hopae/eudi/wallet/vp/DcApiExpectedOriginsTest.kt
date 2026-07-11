package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * OpenID4VP 1.0 Appendix A.2 — `expected_origins` on the Digital Credentials API.
 *
 * A signed request object is a bearer artifact: a malicious site can replay one captured from a
 * legitimate verifier and the signature still checks out. `expected_origins` lives inside the signed
 * payload, so the wallet compares it to the platform-supplied Origin and rejects the mismatch.
 * The parameter is REQUIRED for signed requests and MUST be ignored in unsigned ones.
 */
class DcApiExpectedOriginsTest {

    private val origin = "https://verifier.example"
    private val evilOrigin = "https://evil.example"
    private val docType = "org.iso.18013.5.1.mDL"
    private val namespace = "org.iso.18013.5.1"

    private val noHttp = object : HttpTransport {
        override suspend fun execute(request: HttpRequest): HttpResponse = throw AssertionError("DC API must not do HTTP")
    }

    private fun client() = Openid4VpClient(noHttp, clock = { 1_700_000_000 })

    private fun claims(clientId: String? = "x509_san_dns:verifier.example", expectedOrigins: String? = "[\"$origin\"]"): String {
        val cid = clientId?.let { ",\"client_id\":\"$it\"" } ?: ""
        val eo = expectedOrigins?.let { ",\"expected_origins\":$it" } ?: ""
        return """{"response_type":"vp_token","response_mode":"dc_api","nonce":"dcapi-nonce"$cid$eo,
            "dcql_query":{"credentials":[{"id":"query_0","format":"mso_mdoc","meta":{"doctype_value":"$docType"},
            "claims":[{"path":["$namespace","family_name"]}]}]}}"""
    }

    /** A signed DC API request: `{"request": "<JWS>"}` (JAR), as the platform hands it to the wallet. */
    private fun signed(claimsJson: String): String = runBlocking {
        val area = SoftwareSecureArea()
        val key = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val header = JsonValue.Obj(listOf("alg" to JsonValue.Str("ES256"), "typ" to JsonValue.Str("oauth-authz-req+jwt")))
        val jws = Jws.sign(header, claimsJson.encodeToByteArray(), SecureAreaJwsSigner(area, key.handle, SigningAlgorithm.ES256)).compact()
        """{"request":"$jws"}"""
    }

    @Test
    fun signedRequestWithMatchingOriginResolves() = runBlocking {
        val request = client().resolveDcApiRequest(signed(claims()), origin)
        assertEquals(origin, request.origin)
        assertEquals("x509_san_dns:verifier.example", request.clientId) // from the signed claims
    }

    /** The attack: a signed request captured from verifier.example, replayed by evil.example. */
    @Test
    fun signedRequestReplayedOnAnotherOriginIsRejected() = runBlocking<Unit> {
        val stolen = signed(claims()) // expected_origins = [verifier.example]
        assertFailsWith<VpException.InvalidRequest> { client().resolveDcApiRequest(stolen, evilOrigin) }
    }

    @Test
    fun signedRequestWithoutExpectedOriginsIsRejected() = runBlocking<Unit> {
        assertFailsWith<VpException.InvalidRequest> {
            client().resolveDcApiRequest(signed(claims(expectedOrigins = null)), origin)
        }
    }

    @Test
    fun signedRequestWithEmptyExpectedOriginsIsRejected() = runBlocking<Unit> {
        assertFailsWith<VpException.InvalidRequest> {
            client().resolveDcApiRequest(signed(claims(expectedOrigins = "[]")), origin)
        }
    }

    @Test
    fun signedRequestMatchesAnyListedOrigin() = runBlocking {
        val many = claims(expectedOrigins = "[\"https://other.example\",\"$origin\"]")
        assertEquals(origin, client().resolveDcApiRequest(signed(many), origin).origin)
    }

    /** Appendix A.2: client_id MUST be present in a signed request — it selects the Client Identifier Prefix. */
    @Test
    fun signedRequestWithoutClientIdIsRejected() = runBlocking<Unit> {
        assertFailsWith<VpException.InvalidRequest> {
            client().resolveDcApiRequest(signed(claims(clientId = null)), origin)
        }
    }

    /** Unsigned: the Origin is the identity, so a `client_id` in the payload MUST be ignored (anti-spoofing). */
    @Test
    fun unsignedRequestIgnoresClientId() = runBlocking {
        val request = client().resolveDcApiRequest(claims(clientId = "x509_san_dns:bank.example", expectedOrigins = null), origin)
        assertEquals(origin, request.clientId)
        assertEquals("origin", request.verifier.clientIdScheme)
        assertEquals(false, request.verifier.trusted)
    }

    /** Unsigned: `expected_origins` MUST be ignored even when it contradicts the actual Origin. */
    @Test
    fun unsignedRequestIgnoresExpectedOrigins() = runBlocking {
        val request = client().resolveDcApiRequest(claims(clientId = null, expectedOrigins = "[\"https://somewhere.else\"]"), origin)
        assertEquals(origin, request.origin)
        assertEquals(origin, request.clientId)
    }

    /** 18013-7 C.5: the Origin binds the presentation, so a blank/whitespace Origin is rejected outright. */
    @Test
    fun blankOriginIsRejected() = runBlocking<Unit> {
        assertFailsWith<VpException.InvalidRequest> {
            client().resolveDcApiRequest(claims(clientId = null, expectedOrigins = null), "")
        }
        assertFailsWith<VpException.InvalidRequest> {
            client().resolveDcApiRequest(claims(clientId = null, expectedOrigins = null), "   ")
        }
    }
}
