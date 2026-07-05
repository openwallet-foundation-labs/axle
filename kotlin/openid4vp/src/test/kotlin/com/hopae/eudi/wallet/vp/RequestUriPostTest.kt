package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import kotlinx.coroutines.runBlocking
import java.net.URLEncoder
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** OpenID4VP §5.10: request_uri may be fetched with GET (default) or POST (with wallet_metadata). */
class RequestUriPostTest {

    private class StubTransport(private val jws: String) : HttpTransport {
        var last: HttpRequest? = null
        override suspend fun execute(request: HttpRequest): HttpResponse {
            last = request
            return HttpResponse(200, emptyList(), jws.encodeToByteArray())
        }
    }

    private val payload = """{"client_id":"verifier.example","nonce":"n1","response_mode":"direct_post",""" +
        """"response_uri":"https://verifier.example/response",""" +
        """"dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}}"""

    private fun compactJws(): String {
        fun b64(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.encodeToByteArray())
        return "${b64("""{"alg":"ES256"}""")}.${b64(payload)}.${b64("sig")}"
    }

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    @Test
    fun fetchesRequestUriViaPostWithWalletMetadata() = runBlocking {
        val transport = StubTransport(compactJws())
        val resolver = AuthorizationRequestResolver(transport, trust = null)
        val uri = "openid4vp://?client_id=verifier.example" +
            "&request_uri=${enc("https://verifier.example/request")}&request_uri_method=post"

        val resolved = resolver.resolve(uri)

        assertEquals("verifier.example", resolved.clientId)
        assertEquals("n1", resolved.nonce)
        assertEquals(HttpMethod.POST, transport.last?.method)
        val body = transport.last?.body?.decodeToString() ?: ""
        assertTrue(body.startsWith("wallet_metadata="), "POST body must carry wallet_metadata: $body")
        assertTrue(body.contains("vp_formats_supported"), "wallet_metadata should advertise formats")
        assertTrue(
            transport.last?.headers.orEmpty().any { it.second.contains("x-www-form-urlencoded") },
            "POST must be form-encoded",
        )
    }

    @Test
    fun fetchesRequestUriViaGetByDefault() = runBlocking {
        val transport = StubTransport(compactJws())
        val resolver = AuthorizationRequestResolver(transport, trust = null)
        val uri = "openid4vp://?client_id=verifier.example&request_uri=${enc("https://verifier.example/request")}"

        resolver.resolve(uri)

        assertEquals(HttpMethod.GET, transport.last?.method)
        assertEquals(null, transport.last?.body)
    }
}
