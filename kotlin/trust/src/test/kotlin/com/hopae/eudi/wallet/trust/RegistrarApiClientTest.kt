package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import kotlinx.coroutines.runBlocking
import java.security.PrivateKey
import java.security.Signature
import java.util.Base64
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** TS5 registry client: verifies the JWS record against the registrar CA and reads registered credentials. */
class RegistrarApiClientTest {

    private val validAt = { Date(1_700_000_000_000L) }

    private fun leafSigner(priv: PrivateKey): JwsSigner = object : JwsSigner {
        override val algorithm = SigningAlgorithm.ES256
        override suspend fun sign(signingInput: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(priv); update(signingInput); Der.derSignatureToRaw(sign(), 32) }
    }

    /** A compact `wrp-registry+jwt` token signed by [leaf], x5c = leaf DER. */
    private fun registryToken(leaf: TestCerts.Cert, payload: String): String = runBlocking {
        val header = JsonValue.Obj(
            listOf(
                "alg" to JsonValue.Str("ES256"),
                "typ" to JsonValue.Str("wrp-registry+jwt"),
                "x5c" to JsonValue.Arr(listOf(JsonValue.Str(Base64.getEncoder().encodeToString(leaf.der)))),
            ),
        )
        Jws.sign(header, payload.encodeToByteArray(), leafSigner(leaf.keyPair.private)).compact()
    }

    private class OneShotHttp(private val body: String, private val status: Int = 200) : HttpTransport {
        var lastUrl: String? = null
        override suspend fun execute(request: HttpRequest): HttpResponse {
            lastUrl = request.url
            return HttpResponse(status, emptyList(), body.encodeToByteArray())
        }
    }

    private val recordPayload = """
        {"iss":"https://r.example/registrar","legalName":"Demo RP",
         "intendedUse":[
           {"intendedUseIdentifier":"iu-1","credential":[{"format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claim":[{"path":["org.iso.18013.5.1","given_name"]}]}]},
           {"intendedUseIdentifier":"iu-2","credential":[{"format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claim":[{"path":["family_name"]}]}]}
         ]}
    """.trimIndent()

    private fun client(http: HttpTransport, ca: TestCerts.Cert) =
        RegistrarApiClient(http, X5cIssuerKeyResolver(X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)))

    @Test
    fun fetchesRegisteredCredentialsForIntendedUse() = runBlocking {
        val ca = TestCerts.makeCa("Registrar CA")
        val leaf = TestCerts.makeLeaf(ca, "Registrar Signer")
        val http = OneShotHttp(registryToken(leaf, recordPayload))
        val creds = client(http, ca).fetchRegisteredCredentials("https://r.example/registrar", "RP-1", "iu-2")

        assertEquals("https://r.example/registrar/wrp/RP-1", http.lastUrl)
        assertEquals(1, creds.size)
        assertEquals("dc+sd-jwt", creds.first().format)
        assertEquals(listOf(listOf("family_name")), creds.first().claims)
    }

    @Test
    fun defaultsToFirstIntendedUseWhenIdUnknown() = runBlocking {
        val ca = TestCerts.makeCa("Registrar CA")
        val leaf = TestCerts.makeLeaf(ca, "Registrar Signer")
        val creds = client(OneShotHttp(registryToken(leaf, recordPayload)), ca)
            .fetchRegisteredCredentials("https://r.example/registrar", "RP-1", null)
        assertEquals("mso_mdoc", creds.first().format, "no intended-use id → first entry")
    }

    @Test
    fun untrustedSignerRejected(): Unit = runBlocking {
        val ca = TestCerts.makeCa("Registrar CA")
        val rogue = TestCerts.makeCa("Rogue CA")
        val leaf = TestCerts.makeLeaf(rogue, "Rogue Signer") // not under the trusted registrar CA
        assertFailsWith<TrustException> {
            client(OneShotHttp(registryToken(leaf, recordPayload)), ca)
                .fetchRegisteredCredentials("https://r.example/registrar", "RP-1", "iu-1")
        }
    }

    @Test
    fun httpErrorRejected(): Unit = runBlocking {
        val ca = TestCerts.makeCa("Registrar CA")
        val ex = assertFailsWith<RegistrarApiException> {
            client(OneShotHttp("not found", status = 404), ca)
                .fetchRegisteredCredentials("https://r.example/registrar", "RP-1", "iu-1")
        }
        assertTrue(ex.message!!.contains("404"))
    }
}
