package com.hopae.eudi.wallet.trust

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/** Generates deterministic-ish EC certificate hierarchies with SAN for chain-validation tests. */
object TestCerts {
    init {
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
    }

    class Cert(val certificate: X509Certificate, val keyPair: KeyPair) {
        val der: ByteArray get() = certificate.encoded
    }

    private fun ecKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    fun makeCa(cn: String = "Test CA"): Cert {
        val kp = ecKeyPair()
        val name = X500Name("CN=$cn")
        val now = 1_700_000_000_000L
        val builder = JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(1), Date(now - 86_400_000L), Date(now + 3_650L * 86_400_000L), name, kp.public
        ).addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(kp.private)
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        return Cert(cert, kp)
    }

    fun makeLeaf(
        ca: Cert,
        cn: String,
        dnsName: String? = null,
        notBefore: Long = 1_700_000_000_000L - 86_400_000L,
        notAfter: Long = 1_700_000_000_000L + 3_650L * 86_400_000L,
    ): Cert {
        val kp = ecKeyPair()
        val builder = JcaX509v3CertificateBuilder(
            X500Name(ca.certificate.subjectX500Principal.name), BigInteger.valueOf(System.nanoTime()),
            Date(notBefore), Date(notAfter), X500Name("CN=$cn"), kp.public
        ).addExtension(Extension.basicConstraints, false, BasicConstraints(false))
        if (dnsName != null) {
            builder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, dnsName)))
        }
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(ca.keyPair.private)
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        return Cert(cert, kp)
    }
}
