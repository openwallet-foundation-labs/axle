package com.hopae.eudi.wallet.testkit

import com.hopae.eudi.wallet.cbor.cose.CoseHeaders
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureAreaCoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * M1 완료 기준 E2E: 키 생성 → COSE_Sign1 서명(포트 경유) → 인코드/디코드 → 검증.
 * 프로덕션과 동일 경로 — 개인키는 SecureArea 밖으로 나오지 않는다.
 */
class SecureAreaCoseE2eTest {

    @Test
    fun createSignEncodeDecodeVerify() = runBlocking {
        val area = SoftwareSecureArea()
        val payload = "hello eudi wallet sdk".encodeToByteArray()

        for (algorithm in listOf(SigningAlgorithm.ES256, SigningAlgorithm.ES384, SigningAlgorithm.ES512)) {
            val key = area.createKey(KeySpec(secureArea = area.id, algorithm = algorithm))

            val signed = CoseSign1.sign(
                protected = CoseHeaders.of(algorithm = algorithm.coseAlgorithm),
                payload = payload,
                signer = SecureAreaCoseSigner(area, key.handle, algorithm),
            )

            val decoded = CoseSign1.decode(signed.encode())
            assertTrue(decoded.verify(key.publicKey), "$algorithm: decoded message must verify")

            val tampered = CoseSign1(
                decoded.protectedBytes,
                decoded.unprotected,
                "tampered payload".encodeToByteArray(),
                decoded.signature,
            )
            assertFalse(tampered.verify(key.publicKey), "$algorithm: tampered payload must fail")
        }
    }
}
