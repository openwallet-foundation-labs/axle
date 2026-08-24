package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import kotlinx.coroutines.runBlocking
import java.net.URLEncoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * OpenID4VP 1.0 §5.9.2 — Client Identifier Prefix parsing.
 *
 * The prefix is the part before the first `:`, but only when it is one of the values §5.9.3 defines;
 * "if a `:` character is not present in the Client Identifier, the Wallet MUST treat the Client Identifier
 * as referencing a pre-registered client", and a pre-registered identifier "MUST NOT contain a `:` character
 * preceded immediately by a supported Client Identifier Prefix value". So an unrecognised head is not a
 * prefix — a bare Redirect URI (`https://rp.example/cb`) is a pre-registered identifier, not `https:`.
 */
class ClientIdPrefixTest {

    private object DeadTransport : HttpTransport {
        override suspend fun execute(request: HttpRequest): HttpResponse = HttpResponse(500, emptyList(), ByteArray(0))
    }

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    /** An unsigned request, so the prefix is read straight off the query `client_id` with no trust verifier. */
    private fun schemeOf(clientId: String): String = runBlocking {
        val dcql = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}"""
        val uri = "openid4vp://?client_id=${enc(clientId)}&nonce=n1&response_mode=direct_post" +
            "&response_uri=${enc("https://rp.example/response")}&dcql_query=${enc(dcql)}"
        AuthorizationRequestResolver(DeadTransport).resolve(uri).verifier.clientIdScheme
    }

    @Test
    fun readsEveryPrefixDefinedBy593() {
        assertEquals("x509_san_dns", schemeOf("x509_san_dns:rp.example"))
        assertEquals("x509_hash", schemeOf("x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk"))
        // the fixture posts to https://rp.example/response, which §5.9.3 requires this identifier to name
        assertEquals("redirect_uri", schemeOf("redirect_uri:https://rp.example/response"))
        assertEquals("openid_federation", schemeOf("openid_federation:https://rp.example"))
        assertEquals("decentralized_identifier", schemeOf("decentralized_identifier:did:example:123"))
        assertEquals("verifier_attestation", schemeOf("verifier_attestation:rp.example"))
    }

    /** No `:` at all → pre-registered (§5.9.2). This is the shape the live mdoc.online verifier sends. */
    @Test
    fun treatsAnUnprefixedIdentifierAsPreRegistered() {
        assertEquals("pre-registered", schemeOf("rp.example"))
    }

    /**
     * A `:` whose head is not a defined prefix is part of the identifier, not a prefix. Splitting blindly
     * turned a bare Redirect URI into the non-existent prefix `https`, which then reached the trust verifier.
     */
    @Test
    fun treatsAnUnknownHeadAsPartOfAPreRegisteredIdentifier() {
        assertEquals("pre-registered", schemeOf("https://rp.example/cb"))
        assertEquals("pre-registered", schemeOf("urn:example:rp"))
        assertEquals("pre-registered", schemeOf("x509_san_uri:https://rp.example")) // not defined by §5.9.3
    }

    // ── §5.9.3 `redirect_uri` prefix ──────────────────────────────────────────────────────────────────

    private fun unsigned(clientId: String, responseMode: String, endpointParam: String?, endpoint: String?): String {
        val dcql = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}"""
        val ep = if (endpointParam != null && endpoint != null) "&$endpointParam=${enc(endpoint)}" else ""
        return "openid4vp://?client_id=${enc(clientId)}&nonce=n1&response_mode=$responseMode$ep&dcql_query=${enc(dcql)}"
    }

    private fun resolve(uri: String) = runBlocking { AuthorizationRequestResolver(DeadTransport).resolve(uri) }

    /** Under `direct_post` the identifier is the Response URI; a matching `response_uri` is accepted. */
    @Test
    fun acceptsAResponseUriThatMatchesTheIdentifier() {
        val r = resolve(unsigned("redirect_uri:https://rp.example/cb", "direct_post", "response_uri", "https://rp.example/cb"))
        assertEquals("https://rp.example/cb", r.responseUri)
    }

    /** A request may not name one Verifier and deliver the presentation to another endpoint. */
    @Test
    fun rejectsAResponseUriThatDiffersFromTheIdentifier() {
        assertFailsWith<VpException.InvalidRequest> {
            resolve(unsigned("redirect_uri:https://rp.example/cb", "direct_post", "response_uri", "https://attacker.example/cb"))
        }
    }

    /** §5.9.3: the Verifier "MAY omit" the parameter — the Client Identifier then supplies the endpoint. */
    @Test
    fun derivesTheEndpointWhenTheParameterIsOmitted() {
        val r = resolve(unsigned("redirect_uri:https://rp.example/cb", "direct_post", null, null))
        assertEquals("https://rp.example/cb", r.responseUri)
    }

    /**
     * §5.9.3: "Requests using the `redirect_uri` Client Identifier Prefix cannot be signed because there is no
     * method for the Wallet to obtain a trusted key for verification."
     */
    @Test
    fun rejectsASignedRequestUnderTheRedirectUriPrefix() {
        val jws = "e30.e30.c2ln" // never parsed — the prefix is rejected before the JWS is touched
        assertFailsWith<VpException.InvalidRequest> {
            resolve("openid4vp://?client_id=${enc("redirect_uri:https://rp.example/cb")}&request=${enc(jws)}")
        }
        assertFailsWith<VpException.InvalidRequest> {
            resolve("openid4vp://?client_id=${enc("redirect_uri:https://rp.example/cb")}&request_uri=${enc("https://rp.example/req")}")
        }
    }
}
