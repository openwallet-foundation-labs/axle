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
 * OpenID4VP 1.0 Appendix A.1 — the Digital Credentials API exchange protocol identifier and the request it
 * announces must agree.
 *
 * The platform names the protocol (`openid4vp-v1-signed` / `-unsigned` / `-multisigned`) alongside the
 * request data. Resolving on the data shape alone lets a request announced as signed be processed as an
 * unsigned one, which drops the signature *and* the `expected_origins` replay check without a word — so the
 * wallet checks the two against each other. Multi-signed (Appendix A.3.2.2, JWS JSON Serialization) is not
 * implemented and is refused by name rather than misparsed.
 */
class DcApiProtocolGuardTest {

    private val origin = "https://verifier.example"
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

    /** A signed DC API request: `{"request": "<JWS>"}` (Appendix A.3.2.1, JWS Compact Serialization). */
    private fun signed(claimsJson: String): String = runBlocking {
        val area = SoftwareSecureArea()
        val key = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val header = JsonValue.Obj(listOf("alg" to JsonValue.Str("ES256"), "typ" to JsonValue.Str("oauth-authz-req+jwt")))
        val jws = Jws.sign(header, claimsJson.encodeToByteArray(), SecureAreaJwsSigner(area, key.handle, SigningAlgorithm.ES256)).compact()
        """{"request":"$jws"}"""
    }

    /** A multi-signed request (Appendix A.3.2.2): the parameters live in `payload`, one signature per client_id. */
    private fun jwsJsonSerialization(): String =
        """{"payload":"eyJub25jZSI6ImRjYXBpLW5vbmNlIn0",
            "signatures":[{"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"c2ln"}]}"""

    @Test
    fun declaredProtocolMatchingTheRequestResolves() = runBlocking {
        val fromSigned = client().resolveDcApiRequest(signed(claims()), origin, "openid4vp-v1-signed")
        assertEquals("x509_san_dns:verifier.example", fromSigned.clientId)
        val fromUnsigned = client().resolveDcApiRequest(claims(clientId = null, expectedOrigins = null), origin, "openid4vp-v1-unsigned")
        assertEquals(origin, fromUnsigned.clientId)
    }

    /** Announced signed, delivered unsigned: resolving it would show the caller Origin as a verified verifier. */
    @Test
    fun unsignedRequestDeclaredAsSignedIsRejected() = runBlocking<Unit> {
        assertFailsWith<VpException.InvalidRequest> {
            client().resolveDcApiRequest(claims(clientId = null, expectedOrigins = null), origin, "openid4vp-v1-signed")
        }
    }

    /** Announced unsigned, delivered signed: the wallet would then have to ignore a signature it can check. */
    @Test
    fun signedRequestDeclaredAsUnsignedIsRejected() = runBlocking<Unit> {
        assertFailsWith<VpException.InvalidRequest> {
            client().resolveDcApiRequest(signed(claims()), origin, "openid4vp-v1-unsigned")
        }
    }

    /** A bare JWS (no `{"request": …}` envelope) is a signed request too, and must not pass as unsigned. */
    @Test
    fun bareJwsDeclaredAsUnsignedIsRejected() = runBlocking<Unit> {
        val jws = JsonValue.parse(signed(claims())).let { (it as JsonValue.Obj)["request"] as JsonValue.Str }.value
        assertFailsWith<VpException.InvalidRequest> {
            client().resolveDcApiRequest(jws, origin, "openid4vp-v1-unsigned")
        }
    }

    @Test
    fun multiSignedProtocolIsRefusedByName() = runBlocking<Unit> {
        assertFailsWith<VpException.Unsupported> {
            client().resolveDcApiRequest(jwsJsonSerialization(), origin, "openid4vp-v1-multisigned")
        }
    }

    /** Recognised by shape as well: without the identifier this would fail as "missing nonce" instead. */
    @Test
    fun jwsJsonSerializationIsRefusedWithoutTheProtocolIdentifier() = runBlocking<Unit> {
        assertFailsWith<VpException.Unsupported> { client().resolveDcApiRequest(jwsJsonSerialization(), origin) }
        assertFailsWith<VpException.Unsupported> {
            client().resolveDcApiRequest("""{"request":${jwsJsonSerialization()}}""", origin)
        }
    }

    /** An identifier OpenID4VP does not define constrains nothing: the shape stays the only signal. */
    @Test
    fun unknownProtocolIdentifierFallsBackToTheShape() = runBlocking {
        val request = client().resolveDcApiRequest(claims(clientId = null, expectedOrigins = null), origin, "openid4vp")
        assertEquals(origin, request.clientId)
    }
}
