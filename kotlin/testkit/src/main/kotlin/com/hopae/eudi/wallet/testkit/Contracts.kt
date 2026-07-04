package com.hopae.eudi.wallet.testkit

import com.hopae.eudi.wallet.cbor.cose.Ecdsa
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.spi.coseAlgorithm
import com.hopae.eudi.wallet.spi.curve

/*
 * Port contract test suites (framework-agnostic).
 *
 * "어댑터 자격 = 계약 테스트 통과": the same checks run against SoftwareSecureArea /
 * InMemoryStorageDriver on Linux CI and against real adapters in the device lab.
 * Failures throw IllegalStateException with a descriptive message.
 */

object SecureAreaContract {

    suspend fun verify(area: SecureArea) {
        check(area.capabilities.algorithms.isNotEmpty()) { "capabilities must declare at least one algorithm" }

        for (algorithm in area.capabilities.algorithms) {
            val info = area.createKey(KeySpec(secureArea = area.id, algorithm = algorithm))
            check(info.handle.secureArea == area.id) { "$algorithm: handle must reference this area" }
            check(info.algorithm == algorithm) { "$algorithm: KeyInfo.algorithm mismatch" }

            val fetched = area.publicKey(info.handle)
            check(
                fetched.x.contentEquals(info.publicKey.x) && fetched.y.contentEquals(info.publicKey.y)
            ) { "$algorithm: publicKey(handle) must equal createKey's public key" }

            val data = "port-contract-test".encodeToByteArray()
            val signature = area.sign(info.handle, algorithm, data, null)
            check(signature.size == 2 * algorithm.curve.coordinateSize) {
                "$algorithm: signature must be raw r||s (${2 * algorithm.curve.coordinateSize} bytes), got ${signature.size}"
            }
            check(Ecdsa.verify(info.publicKey, algorithm.coseAlgorithm, data, signature)) {
                "$algorithm: signature must verify against the key's public key"
            }
            check(!Ecdsa.verify(info.publicKey, algorithm.coseAlgorithm, "other-data".encodeToByteArray(), signature)) {
                "$algorithm: signature must not verify for different data"
            }

            if (area.capabilities.keyAttestation) {
                checkNotNull(area.attestation(info.handle, ByteArray(32) { it.toByte() })) {
                    "$algorithm: area declares keyAttestation but returned null"
                }
            }

            area.deleteKey(info.handle)
            check(runCatching { area.sign(info.handle, algorithm, data, null) }.isFailure) {
                "$algorithm: signing with a deleted key must fail"
            }
        }

        if (area.capabilities.keyAgreement) {
            val algorithm = area.capabilities.algorithms.first()
            val a = area.createKey(KeySpec(secureArea = area.id, algorithm = algorithm))
            val b = area.createKey(KeySpec(secureArea = area.id, algorithm = algorithm))
            val s1 = area.keyAgreement(a.handle, b.publicKey, null)
            val s2 = area.keyAgreement(b.handle, a.publicKey, null)
            check(s1.isNotEmpty() && s1.contentEquals(s2)) { "ECDH must be symmetric and non-empty" }
            area.deleteKey(a.handle)
            area.deleteKey(b.handle)
        }
    }
}

object StorageDriverContract {

    suspend fun verify(driver: StorageDriver) {
        val c = "contract-test"

        check(driver.get(c, "missing") == null) { "missing key must read as null" }

        driver.put(c, "k1", byteArrayOf(1, 2, 3))
        check(driver.get(c, "k1")?.contentEquals(byteArrayOf(1, 2, 3)) == true) { "put/get roundtrip" }

        driver.get(c, "k1")!![0] = 99
        check(driver.get(c, "k1")?.get(0) == 1.toByte()) { "returned values must not alias stored state" }

        driver.put(c, "k1", byteArrayOf(9))
        check(driver.get(c, "k1")?.contentEquals(byteArrayOf(9)) == true) { "overwrite must replace value" }

        driver.put(c, "k2", byteArrayOf(2))
        check(driver.keys(c).toSet() == setOf("k1", "k2")) { "keys() must list stored keys" }

        driver.delete(c, "k1")
        check(driver.get(c, "k1") == null) { "delete must remove the value" }

        driver.transaction {
            put(c, "k3", byteArrayOf(3))
            check(get(c, "k2")?.contentEquals(byteArrayOf(2)) == true) { "tx must see pre-existing state" }
            check(get(c, "k3")?.contentEquals(byteArrayOf(3)) == true) { "tx must see its own writes" }
            delete(c, "k2")
        }
        check(driver.get(c, "k3")?.contentEquals(byteArrayOf(3)) == true) { "tx writes must persist" }
        check(driver.get(c, "k2") == null) { "tx deletes must persist" }

        driver.delete(c, "k3")
    }
}
