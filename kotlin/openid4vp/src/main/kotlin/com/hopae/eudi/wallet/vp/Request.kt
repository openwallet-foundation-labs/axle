package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.signingAlgorithmFromJwsName
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.net.URLDecoder
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

/** What the wallet shows on the consent screen about the verifier and its trust status. */
class VerifierInfo(
    val clientId: String,
    val clientIdScheme: String,
    /** X.509 chain from the request signature, leaf first (null for unsigned requests). */
    val certificateChain: List<X509Certificate>?,
    val commonName: String?,
    /** Signature verified against the leaf key and (for x509_san_dns) SAN matched client_id. */
    val signatureValid: Boolean,
)

class ResolvedRequest(
    val clientId: String,
    val nonce: String,
    val state: String?,
    val responseMode: String,
    val responseUri: String?,
    val redirectUri: String?,
    val dcqlQuery: DcqlQuery,
    val clientMetadata: JsonValue.Obj?,
    val transactionData: List<String>?,
    val verifier: VerifierInfo,
)

/**
 * Resolves an OpenID4VP authorization request (OpenID4VP §5): parses the request URI, follows
 * JAR (`request_uri`/`request`), and for `x509_san_dns` verifies the request-object signature
 * with the leaf certificate and matches its SAN dNSName to the client_id.
 *
 * Chain validation to a trust anchor is the trust module's job (M3); `signatureValid` here
 * means "signed by the presented leaf whose SAN matches the client_id".
 */
class AuthorizationRequestResolver(private val http: HttpTransport) {

    suspend fun resolve(requestUri: String): ResolvedRequest {
        val params = parseQuery(requestUri)
        val clientId = params["client_id"] ?: throw VpException.InvalidRequest("missing client_id")
        val scheme = clientIdScheme(clientId, params["client_id_scheme"])

        val (claims, verifier) = when {
            params["request_uri"] != null -> {
                val jwt = fetchRequestObject(params["request_uri"]!!)
                verifySignedRequest(jwt, clientId, scheme)
            }
            params["request"] != null -> verifySignedRequest(params["request"]!!, clientId, scheme)
            else -> unsignedRequest(params) to VerifierInfo(clientId, scheme, null, null, signatureValid = false)
        }

        return build(claims, clientId, scheme, verifier)
    }

    private fun build(claims: JsonValue.Obj, clientId: String, scheme: String, verifier: VerifierInfo): ResolvedRequest {
        val nonce = claims.str("nonce") ?: throw VpException.InvalidRequest("missing nonce")
        val dcqlObj = claims["dcql_query"] as? JsonValue.Obj
            ?: throw VpException.InvalidRequest("missing dcql_query (only DCQL is supported)")
        val responseMode = claims.str("response_mode") ?: "direct_post"
        if (responseMode != "direct_post" && responseMode != "direct_post.jwt") {
            throw VpException.Unsupported("response_mode '$responseMode'")
        }
        val txData = (claims["transaction_data"] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.value }
        return ResolvedRequest(
            clientId = clientId,
            nonce = nonce,
            state = claims.str("state"),
            responseMode = responseMode,
            responseUri = claims.str("response_uri"),
            redirectUri = claims.str("redirect_uri"),
            dcqlQuery = DcqlQuery.parse(dcqlObj),
            clientMetadata = claims["client_metadata"] as? JsonValue.Obj,
            transactionData = txData,
            verifier = verifier,
        )
    }

    private fun unsignedRequest(params: Map<String, String>): JsonValue.Obj {
        // Query-param requests carry dcql_query / client_metadata / transaction_data as JSON strings.
        val entries = params.map { (k, v) ->
            k to when (k) {
                "dcql_query", "client_metadata" -> JsonValue.parse(v)
                "transaction_data" -> JsonValue.parse(v)
                else -> JsonValue.Str(v)
            }
        }
        return JsonValue.Obj(entries)
    }

    private fun verifySignedRequest(jwt: String, clientId: String, scheme: String): Pair<JsonValue.Obj, VerifierInfo> {
        val jws = Jws.parse(jwt)
        val claims = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw VpException.InvalidRequest("request object payload must be JSON")

        if (scheme != "x509_san_dns") {
            // redirect_uri / other schemes: no signature to verify here.
            return claims to VerifierInfo(clientId, scheme, null, null, signatureValid = false)
        }

        val x5c = jws.x5c ?: throw VpException.VerifierNotTrusted("x509_san_dns request without x5c")
        val chain = x5c.map { der ->
            CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        }
        val leaf = chain.first()
        val alg = signingAlgorithmFromJwsName((jws.header["alg"] as? JsonValue.Str)?.value ?: "")
            ?: throw VpException.InvalidRequest("unsupported request alg")
        if (!jws.verify(leafKey(leaf), alg)) throw VpException.VerifierNotTrusted("request signature invalid")

        val expectedDns = clientId.substringAfter("x509_san_dns:", clientId)
        if (dnsNames(leaf).none { it.equals(expectedDns, ignoreCase = true) }) {
            throw VpException.VerifierNotTrusted("client_id '$expectedDns' not in certificate SAN dNSName")
        }
        val cn = commonName(leaf)
        return claims to VerifierInfo(clientId, scheme, chain, cn, signatureValid = true)
    }

    private suspend fun fetchRequestObject(url: String): String {
        val resp = http.execute(HttpRequest(HttpMethod.GET, url, listOf("Accept" to "application/oauth-authz-req+jwt")))
        if (resp.status !in 200..299) throw VpException.InvalidRequest("request_uri fetch failed: HTTP ${resp.status}")
        return resp.body.decodeToString().trim()
    }

    private fun clientIdScheme(clientId: String, explicit: String?): String = when {
        explicit != null -> explicit
        clientId.contains(":") -> clientId.substringBefore(":")
        else -> "redirect_uri"
    }

    private fun leafKey(cert: X509Certificate): EcPublicKey {
        val pub = cert.publicKey as? ECPublicKey ?: throw VpException.VerifierNotTrusted("verifier key is not EC")
        val size = (pub.params.curve.field.fieldSize + 7) / 8
        val curve = when (size) {
            32 -> EcCurve.P256; 48 -> EcCurve.P384; 66 -> EcCurve.P521
            else -> throw VpException.VerifierNotTrusted("unsupported curve")
        }
        fun fixed(b: BigInteger): ByteArray {
            val s = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(size - s.size) + s
        }
        return EcPublicKey(curve, fixed(pub.w.affineX), fixed(pub.w.affineY))
    }

    private fun dnsNames(cert: X509Certificate): List<String> =
        cert.subjectAlternativeNames?.filter { it[0] == 2 }?.mapNotNull { it[1] as? String } ?: emptyList()

    private fun commonName(cert: X509Certificate): String? =
        Regex("CN=([^,]+)").find(cert.subjectX500Principal.name)?.groupValues?.get(1)

    private fun parseQuery(uri: String): Map<String, String> {
        val query = uri.substringAfter('?', "")
        if (query.isEmpty()) throw VpException.InvalidRequest("no query parameters in request")
        return query.split('&').filter { it.isNotEmpty() }.associate {
            val k = it.substringBefore('=')
            val v = it.substringAfter('=', "")
            URLDecoder.decode(k, "UTF-8") to URLDecoder.decode(v, "UTF-8")
        }
    }

    private fun JsonValue.Obj.str(name: String): String? = (this[name] as? JsonValue.Str)?.value
}
