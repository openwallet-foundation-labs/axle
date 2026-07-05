package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.InMemoryStorageDriver
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import com.hopae.eudi.wallet.trust.TestCerts
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.net.URLEncoder
import java.security.PrivateKey
import java.security.Signature
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Phase D: reader trust — verify signed OpenID4VP request objects against configured reader anchors. */
class WalletReaderTrustTest {

    private val noHttp = object : HttpTransport {
        override suspend fun execute(request: HttpRequest): HttpResponse = HttpResponse(404, emptyList(), ByteArray(0))
    }

    private fun leafSigner(priv: PrivateKey): JwsSigner = object : JwsSigner {
        override val algorithm = SigningAlgorithm.ES256
        override suspend fun sign(signingInput: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(priv); update(signingInput); Der.derSignatureToRaw(sign(), 32) }
    }

    /** A JAR (signed request object) delivered inline via `request=`, with the reader cert in the x5c header. */
    private suspend fun signedRequestUrl(leaf: TestCerts.Cert, clientId: String, scheme: String): String {
        val claims = """{"nonce":"vp-nonce-123","response_mode":"direct_post","response_uri":"https://verifier.example/response",""" +
            """"state":"xyz","dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},""" +
            """"claims":[{"path":["family_name"]}]}]}}"""
        val header = JsonValue.Obj(
            listOf(
                "alg" to JsonValue.Str("ES256"),
                "typ" to JsonValue.Str("oauth-authz-req+jwt"),
                "x5c" to JsonValue.Arr(listOf(JsonValue.Str(Base64.getEncoder().encodeToString(leaf.der)))),
            ),
        )
        val jws = Jws.sign(header, claims.encodeToByteArray(), leafSigner(leaf.keyPair.private))
        return "openid4vp://?client_id=${URLEncoder.encode(clientId, "UTF-8")}&client_id_scheme=$scheme&request=${URLEncoder.encode(jws.compact(), "UTF-8")}"
    }

    @Test
    fun signedRequestFromTrustedReaderIsTrusted() = runBlocking {
        val ca = TestCerts.makeCa("Reader Root CA")
        val leaf = TestCerts.makeLeaf(ca, cn = "EUDI Verifier", dnsName = "verifier.example.com")
        val wallet = Wallet.create(
            WalletConfig(trust = TrustConfig(readerAnchorsDer = listOf(ca.der))),
            WalletPorts(listOf(SoftwareSecureArea()), InMemoryStorageDriver(), noHttp),
        )

        val session = wallet.presentation.start(signedRequestUrl(leaf, "x509_san_dns:verifier.example.com", "x509_san_dns"))
        val resolved = withTimeout(15_000) { session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed } }
        assertTrue(resolved is PresentationState.RequestResolved, "resolved: $resolved")
        val verifier = resolved.request.verifier
        assertTrue(verifier.trusted, "reader chaining to the configured anchor must be trusted")
        assertEquals("EUDI Verifier", verifier.commonName)
        assertEquals("x509_san_dns", verifier.clientIdScheme)
        session.decline()
        wallet.close()
    }

    @Test
    fun signedRequestFromUntrustedReaderFails() = runBlocking {
        val trustedCa = TestCerts.makeCa("Trusted Reader CA")
        val rogueCa = TestCerts.makeCa("Rogue CA")
        val rogueLeaf = TestCerts.makeLeaf(rogueCa, cn = "Rogue", dnsName = "verifier.example.com")
        val wallet = Wallet.create(
            WalletConfig(trust = TrustConfig(readerAnchorsDer = listOf(trustedCa.der))),
            WalletPorts(listOf(SoftwareSecureArea()), InMemoryStorageDriver(), noHttp),
        )

        val session = wallet.presentation.start(signedRequestUrl(rogueLeaf, "x509_san_dns:verifier.example.com", "x509_san_dns"))
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Failed, "terminal: $terminal")
        assertTrue(terminal.error is WalletError.Presentation.VerifierNotTrusted, "error: ${terminal.error}")
        wallet.close()
    }
}
