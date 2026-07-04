package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest as JdkRequest
import java.net.http.HttpResponse as JdkResponse
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.util.Base64
import kotlin.test.Test

/**
 * Live presentation to the EUDI reference verifier (verifier.eudiw.dev). Opt-in via
 * EUDI_VP=1; the OpenID4VP request URL (from the verifier's "Open with your wallet") is
 * passed in EUDI_VP_REQUEST. Reads the real PID + holder key captured during issuance.
 */
class VpPresentTest {

    @Test
    fun presentPidToVerifier() = runBlocking {
        assumeTrue(System.getenv("EUDI_VP") == "1", "set EUDI_VP=1 to run live VP")
        val requestUrl = System.getenv("EUDI_VP_REQUEST") ?: error("set EUDI_VP_REQUEST=<openid4vp url>")
        val tmp = System.getProperty("java.io.tmpdir")
        val credential = File(tmp, "eudi-credential.txt").readText().trim()
        val holderKey = LoadedKey.fromJson(JsonValue.parse(File(tmp, "eudi-holder-key.json").readText()) as JsonValue.Obj)

        val transport = JdkHttp()
        val held = HeldSdJwtVc("pid", SdJwt.parse(credential), holderKey.signer())
        val client = Openid4VpClient(transport, clock = { System.currentTimeMillis() / 1000 })

        val request = client.resolveRequest(requestUrl)
        println("verifier client_id: ${request.clientId} (scheme ${request.verifier.clientIdScheme})")
        println("response_mode: ${request.responseMode}, nonce present: ${request.nonce.isNotEmpty()}")
        println("dcql queries: ${request.dcqlQuery.credentials.map { it.id + ":" + (it.meta?.vctValues ?: "") }}")

        val matches = client.match(request, listOf(held))
        println("satisfiable: ${matches.isSatisfiable()}, required: ${matches.requiredQueryIds}")
        matches.candidatesByQuery.forEach { (q, c) -> println("  $q -> ${c.size} candidate(s), disclose ${c.firstOrNull()?.disclosedPaths}") }

        val result = client.respond(request, matches, PresentationSelection.auto(matches), listOf(held))
        println("\n*** PRESENTATION ACCEPTED BY LIVE VERIFIER ***")
        println("redirect_uri: ${result.redirectUri}")
    }

    /** Minimal JVM HttpTransport (redirects off) for the live test. */
    private class JdkHttp : HttpTransport {
        private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(15)).build()

        override suspend fun execute(request: HttpRequest): HttpResponse {
            val builder = JdkRequest.newBuilder(URI.create(request.url)).timeout(Duration.ofSeconds(20))
            val body = request.body?.let { JdkRequest.BodyPublishers.ofByteArray(it) } ?: JdkRequest.BodyPublishers.noBody()
            when (request.method) {
                HttpMethod.GET -> builder.GET()
                HttpMethod.POST -> builder.POST(body)
                HttpMethod.PUT -> builder.PUT(body)
                HttpMethod.PATCH -> builder.method("PATCH", body)
                HttpMethod.DELETE -> builder.DELETE()
            }
            request.headers.forEach { (k, v) -> builder.header(k, v) }
            val resp = client.send(builder.build(), JdkResponse.BodyHandlers.ofByteArray())
            val headers = resp.headers().map().entries.flatMap { (k, vs) -> vs.map { k to it } }
            return HttpResponse(resp.statusCode(), headers, resp.body())
        }
    }

    /** Holder key loaded from the persisted issuance state (PKCS8 + public x/y). */
    private class LoadedKey(private val pkcs8: ByteArray, val publicKey: EcPublicKey) {
        fun signer(): JwsSigner = object : JwsSigner {
            override val algorithm = SigningAlgorithm.ES256
            private val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            override suspend fun sign(signingInput: ByteArray): ByteArray =
                Signature.getInstance("SHA256withECDSA").run { initSign(priv); update(signingInput); Der.derSignatureToRaw(sign(), 32) }
        }

        companion object {
            fun fromJson(o: JsonValue.Obj): LoadedKey {
                val pkcs8 = Base64.getDecoder().decode((o["pkcs8"] as JsonValue.Str).value)
                val x = Base64Url.decode((o["x"] as JsonValue.Str).value)
                val y = Base64Url.decode((o["y"] as JsonValue.Str).value)
                return LoadedKey(pkcs8, EcPublicKey(EcCurve.P256, x, y))
            }
        }
    }
}
