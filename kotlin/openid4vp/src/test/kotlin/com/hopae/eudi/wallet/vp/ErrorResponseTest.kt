package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import kotlinx.coroutines.runBlocking
import java.net.URLDecoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * OpenID4VP §8.5 Authorization Error Response: the wallet POSTs `error` / `error_description` /
 * `state` to the verifier's `response_uri`, exactly where a `vp_token` would have gone, and follows
 * any `redirect_uri` the verifier returns. Over the DC API there is no `response_uri` (§15.9.2).
 */
class ErrorResponseTest {

    private val responseUri = "https://verifier.example/response"

    private class CapturingTransport(private val body: String = "{}") : HttpTransport {
        var last: HttpRequest? = null
        override suspend fun execute(request: HttpRequest): HttpResponse {
            last = request
            return HttpResponse(200, listOf("Content-Type" to "application/json"), body.encodeToByteArray())
        }
    }

    private fun request(responseUri: String? = this.responseUri, state: String? = "xyz", origin: String? = null) =
        ResolvedRequest(
            clientId = "x509_san_dns:verifier.example",
            nonce = "n1",
            state = state,
            responseMode = if (origin != null) "dc_api" else "direct_post",
            responseUri = responseUri,
            redirectUri = null,
            dcqlQuery = DcqlQuery.parse(
                com.hopae.eudi.wallet.sdjwt.JsonValue.parse(
                    """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}"""
                ) as com.hopae.eudi.wallet.sdjwt.JsonValue.Obj
            ),
            clientMetadata = null,
            transactionData = null,
            verifier = VerifierInfo("x509_san_dns:verifier.example", "x509_san_dns", null, null, trusted = true),
            origin = origin,
        )

    private fun form(transport: CapturingTransport): Map<String, String> =
        (transport.last?.body?.decodeToString() ?: "").split("&").filter { it.isNotEmpty() }.associate {
            URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('=', ""), "UTF-8")
        }

    @Test
    fun postsErrorCodeDescriptionAndStateToResponseUri() = runBlocking {
        val transport = CapturingTransport()
        val client = Openid4VpClient(transport, clock = { 0 })

        val result = client.reportError(request(), VpErrorCode.ACCESS_DENIED, "the user declined")

        assertEquals(HttpMethod.POST, transport.last?.method)
        assertEquals(responseUri, transport.last?.url)
        assertTrue(transport.last?.headers.orEmpty().any { it.second.contains("x-www-form-urlencoded") })
        val form = form(transport)
        assertEquals("access_denied", form["error"])
        assertEquals("the user declined", form["error_description"])
        assertEquals("xyz", form["state"]) // echoed so the verifier can correlate the session
        assertTrue("vp_token" !in form)
        assertNull(result.redirectUri)
    }

    /** §8.2: the Response URI MAY return a redirect_uri for Error Responses; the wallet MUST follow it. */
    @Test
    fun returnsTheVerifiersRedirectUri() = runBlocking {
        val transport = CapturingTransport("""{"redirect_uri":"https://verifier.example/cancelled"}""")
        val client = Openid4VpClient(transport, clock = { 0 })

        val result = client.reportError(request(), VpErrorCode.ACCESS_DENIED)

        assertEquals("https://verifier.example/cancelled", result.redirectUri)
        assertTrue("error_description" !in form(transport)) // omitted when no description is given
    }

    @Test
    fun omitsStateWhenTheRequestHadNone() = runBlocking {
        val transport = CapturingTransport()
        Openid4VpClient(transport, clock = { 0 }).reportError(request(state = null), VpErrorCode.INVALID_REQUEST)
        assertTrue("state" !in form(transport))
    }

    /** No response_uri over the Digital Credentials API — the error goes back to the platform (§15.9.2). */
    @Test
    fun refusesToReportOverDcApi() = runBlocking<Unit> {
        val transport = CapturingTransport()
        val client = Openid4VpClient(transport, clock = { 0 })

        assertFailsWith<VpException.Unsupported> {
            client.reportError(request(responseUri = null, origin = "https://verifier.example"), VpErrorCode.ACCESS_DENIED)
        }
        assertNull(transport.last, "nothing may be sent")
    }

    /** The §8.5 taxonomy: refusals collapse to access_denied, so a verifier cannot tell "no credential" from "declined". */
    @Test
    fun mapsExceptionsToSpecCodes() {
        assertEquals(VpErrorCode.INVALID_REQUEST, VpException.InvalidRequest("x").errorCode)
        assertEquals(VpErrorCode.INVALID_REQUEST, VpException.Unsupported("x").errorCode)
        assertEquals(VpErrorCode.ACCESS_DENIED, VpException.QueryNotSatisfiable(setOf("pid")).errorCode)
        assertEquals(VpErrorCode.ACCESS_DENIED, VpException.VerifierNotTrusted("x").errorCode)
        assertEquals(VpErrorCode.ACCESS_DENIED, VpException.SelectionIncomplete("x").errorCode)
        assertEquals("wallet_unavailable", VpErrorCode.WALLET_UNAVAILABLE.code)
        assertEquals("invalid_request_uri_method", VpErrorCode.INVALID_REQUEST_URI_METHOD.code)
    }
}
