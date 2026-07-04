package com.hopae.eudi.wallet.testkit

import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.cbor.cose.Ecdsa
import com.hopae.eudi.wallet.spi.AuthorizationHint
import com.hopae.eudi.wallet.spi.HardwarePolicy
import com.hopae.eudi.wallet.spi.KeyAttestation
import com.hopae.eudi.wallet.spi.KeyHandle
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SecureAreaCapabilities
import com.hopae.eudi.wallet.spi.SecureAreaId
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm
import com.hopae.eudi.wallet.spi.curve
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.KeyAgreement

/**
 * In-memory software SecureArea for tests, Linux CI, and desktop/server hosts.
 * No hardware backing, no user auth, no attestation — capabilities say so honestly.
 */
class SoftwareSecureArea(
    override val id: SecureAreaId = SecureAreaId("software"),
) : SecureArea {

    private class Entry(
        val privateKey: PrivateKey,
        val publicKey: EcPublicKey,
        val algorithm: SigningAlgorithm,
    )

    private val keys = ConcurrentHashMap<String, Entry>()
    private val counter = AtomicLong()

    override val capabilities = SecureAreaCapabilities(
        algorithms = setOf(SigningAlgorithm.ES256, SigningAlgorithm.ES384, SigningAlgorithm.ES512),
        hardwareBacked = false,
        userAuthentication = false,
        keyAttestation = false,
        keyAgreement = true,
    )

    override suspend fun createKey(spec: KeySpec): KeyInfo {
        require(spec.hardware != HardwarePolicy.Required) {
            "software secure area cannot satisfy HardwarePolicy.Required"
        }
        val curve = spec.algorithm.curve
        val keyPair = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec(curve.jcaName)) }
            .generateKeyPair()
        val point = (keyPair.public as ECPublicKey).w
        val publicKey = EcPublicKey(
            curve,
            point.affineX.toFixed(curve.coordinateSize),
            point.affineY.toFixed(curve.coordinateSize),
        )
        val alias = "key-${counter.incrementAndGet()}"
        keys[alias] = Entry(keyPair.private, publicKey, spec.algorithm)
        return KeyInfo(KeyHandle(id, alias), spec.algorithm, publicKey)
    }

    override suspend fun publicKey(key: KeyHandle): EcPublicKey = entry(key).publicKey

    override suspend fun sign(
        key: KeyHandle,
        algorithm: SigningAlgorithm,
        data: ByteArray,
        hint: AuthorizationHint?,
    ): ByteArray {
        val entry = entry(key)
        require(algorithm == entry.algorithm) { "key was created for ${entry.algorithm}, not $algorithm" }
        val der = Signature.getInstance(algorithm.coseAlgorithm.jcaName).run {
            initSign(entry.privateKey)
            update(data)
            sign()
        }
        return Der.derSignatureToRaw(der, algorithm.curve.coordinateSize)
    }

    override suspend fun keyAgreement(
        key: KeyHandle,
        peerPublicKey: EcPublicKey,
        hint: AuthorizationHint?,
    ): ByteArray = KeyAgreement.getInstance("ECDH").run {
        init(entry(key).privateKey)
        doPhase(Ecdsa.publicKeyOf(peerPublicKey), true)
        generateSecret()
    }

    override suspend fun attestation(key: KeyHandle, challenge: ByteArray): KeyAttestation? = null

    override suspend fun deleteKey(key: KeyHandle) {
        keys.remove(key.alias)
    }

    private fun entry(key: KeyHandle): Entry {
        require(key.secureArea == id) { "key belongs to ${key.secureArea}, not $id" }
        return keys[key.alias] ?: throw IllegalStateException("unknown or deleted key: ${key.alias}")
    }

    private fun BigInteger.toFixed(size: Int): ByteArray {
        val stripped = toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        require(stripped.size <= size) { "coordinate larger than curve size" }
        return ByteArray(size - stripped.size) + stripped
    }
}
