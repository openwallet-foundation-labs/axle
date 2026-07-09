package com.hopae.eudi.wallet.proximity

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * ISO 18013-5 §9.1.1.4 / Table 20 session termination: the `status` code round-trips, a status-only
 * frame carries no `data`, and destroying the session keys zeroes them and blocks further use.
 */
class SessionTerminationTest {

    @Test
    fun statusRoundTripsThroughSessionData() {
        val frame = SessionMessages.decodeSessionData(
            SessionMessages.encodeData("ct".encodeToByteArray(), status = SessionMessages.Status.SESSION_TERMINATION)
        )
        assertContentEquals("ct".encodeToByteArray(), frame.data)
        assertEquals(SessionMessages.Status.SESSION_TERMINATION, frame.status)
    }

    @Test
    fun aStatusOnlyFrameHasNoData() {
        val frame = SessionMessages.decodeSessionData(SessionMessages.encodeStatus(SessionMessages.Status.SESSION_TERMINATION))
        assertNull(frame.data)
        assertEquals(20L, frame.status)
        // The data-only accessor rejects it, so callers that expect a response fail loudly.
        assertFailsWith<ProximityException> {
            SessionMessages.decodeData(SessionMessages.encodeStatus(SessionMessages.Status.SESSION_ENCRYPTION_ERROR))
        }
    }

    @Test
    fun aPlainDataFrameHasNoStatus() {
        val frame = SessionMessages.decodeSessionData(SessionMessages.encodeData("x".encodeToByteArray()))
        assertNull(frame.status)
        assertContentEquals("x".encodeToByteArray(), frame.data)
    }

    @Test
    fun destroyZeroesKeysAndBlocksReuse() {
        val eDevice = EphemeralKeyPair.generate()
        val eReader = EphemeralKeyPair.generate()
        val transcript = ProximitySessionTranscript.encode(
            ProximitySessionTranscript.build(DeviceEngagement.qr(eDevice.publicKey), eReader.publicKey)
        )
        val device = SessionEncryption.forMdoc(eDevice, eReader.publicKey, transcript)
        val reader = SessionEncryption.forReader(eReader, eDevice.publicKey, transcript)

        // A message encrypts before destruction…
        val ct = device.encrypt("secret".encodeToByteArray())
        assertContentEquals("secret".encodeToByteArray(), reader.decrypt(ct))

        // …and after destroy() both sides refuse to touch the keys.
        device.destroy()
        reader.destroy()
        assertFailsWith<IllegalStateException> { device.encrypt("again".encodeToByteArray()) }
        assertFailsWith<IllegalStateException> { reader.decrypt(ct) }

        device.destroy() // idempotent
    }
}
