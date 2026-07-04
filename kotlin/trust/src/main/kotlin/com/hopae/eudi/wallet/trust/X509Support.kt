package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.Base64

class TrustException(message: String) : Exception(message)

/** JCA-backed X.509 helpers shared by the issuer and verifier trust paths. */
object X509Support {

    private val cf = CertificateFactory.getInstance("X.509")

    fun parse(der: ByteArray): X509Certificate =
        cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    /** Parses a DER X.509 certificate loaded from a resource/anchor file. */
    fun parseAll(ders: List<ByteArray>): List<X509Certificate> = ders.map { parse(it) }

    fun ecPublicKey(cert: X509Certificate): EcPublicKey {
        val pub = cert.publicKey as? ECPublicKey ?: throw TrustException("certificate key is not EC")
        val size = (pub.params.curve.field.fieldSize + 7) / 8
        val curve = when (size) {
            32 -> EcCurve.P256; 48 -> EcCurve.P384; 66 -> EcCurve.P521
            else -> throw TrustException("unsupported curve size $size")
        }
        fun fixed(b: BigInteger): ByteArray {
            val s = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(size - s.size) + s
        }
        return EcPublicKey(curve, fixed(pub.w.affineX), fixed(pub.w.affineY))
    }

    fun signingAlgorithm(cert: X509Certificate): SigningAlgorithm =
        when (val size = (( (cert.publicKey as ECPublicKey).params.curve.field.fieldSize + 7) / 8)) {
            32 -> SigningAlgorithm.ES256; 48 -> SigningAlgorithm.ES384; 66 -> SigningAlgorithm.ES512
            else -> throw TrustException("unsupported curve size $size")
        }

    /** SAN dNSName entries (RFC 5280 §4.2.1.6, type 2). */
    fun dnsNames(cert: X509Certificate): List<String> =
        cert.subjectAlternativeNames?.filter { it[0] == 2 }?.mapNotNull { it[1] as? String } ?: emptyList()

    fun commonName(cert: X509Certificate): String? =
        Regex("CN=([^,]+)").find(cert.subjectX500Principal.name)?.groupValues?.get(1)

    /** base64url(SHA-256(DER)) — the x509_hash client_id value. */
    fun sha256Thumbprint(cert: X509Certificate): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.encoded))
}
