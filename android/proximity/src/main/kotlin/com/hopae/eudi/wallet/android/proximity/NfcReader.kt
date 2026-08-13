package com.hopae.eudi.wallet.android.proximity

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import com.hopae.eudi.wallet.proximity.MdocNfcEngagement
import com.hopae.eudi.wallet.proximity.MdocNfcHandover
import com.hopae.eudi.wallet.proximity.NfcHandover
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The reader side of ISO 18013-5 NFC engagement: puts the phone in NFC reader mode and drives the SDK's
 * [MdocNfcHandover] over the tag's ISO-DEP channel. It auto-detects the mdoc's handover mode — static
 * (reads the Handover Select) or negotiated (runs the TNEP exchange, offering the [Handover Request] built
 * here) — and returns both messages so the caller can bind the SessionTranscript.
 */
object NfcReader {
    /**
     * Suspends until an mdoc tag is tapped, then returns its handover (Select, plus Request iff negotiated).
     *
     * Reader mode stays armed after this returns — the caller **must** [release] it once the whole exchange is
     * over (BLE included), not just the tap. Dropping it at the tap would hand the still-coupled mdoc back to the
     * platform's tag dispatcher, which reads it as an unknown Type-4 tag and throws its "New tag found" activity
     * over the reader (backgrounding it mid-BLE, and tearing the mdoc's presentation down with it). Re-taps while
     * armed are ignored for the same reason: the engagement is already spent.
     */
    suspend fun readHandover(activity: Activity): NfcHandover = suspendCancellableCoroutine { cont ->
        val adapter = NfcAdapter.getDefaultAdapter(activity)
            ?: return@suspendCancellableCoroutine cont.resumeWithException(IllegalStateException("NFC unavailable"))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val engaging = AtomicBoolean(false)
        val callback = NfcAdapter.ReaderCallback { tag ->
            val iso = IsoDep.get(tag) ?: return@ReaderCallback
            if (!engaging.compareAndSet(false, true)) return@ReaderCallback // already engaged (or engaging) — ignore
            scope.launch {
                try {
                    iso.connect()
                    iso.timeout = 5000
                    val result = MdocNfcHandover.read(negotiatedHandoverRequest()) { apdu -> iso.transceive(apdu) }
                    runCatching { iso.close() }
                    if (cont.isActive) cont.resume(result)
                } catch (e: Exception) {
                    engaging.set(false) // a botched tap shouldn't burn the wait — let the next one try
                    if (cont.isActive) cont.resumeWithException(e)
                }
            }
        }
        adapter.enableReaderMode(activity, callback, READER_FLAGS, null)
        cont.invokeOnCancellation {
            armIdle(activity) // back to swallowing taps, not to the platform dispatcher
            scope.cancel()
        }
    }

    /**
     * Holds reader mode with a callback that drops every tag. Keeps the platform's tag dispatcher out of the way
     * for as long as a reader UI is up — otherwise a tap outside an engagement (a stray one, a retry after a lost
     * tag, or the mdoc still coupled after a finished exchange) surfaces as "New tag found" on top of the app.
     * Call on entering/resuming the reader screen and after each engagement; pair with [release] on the way out.
     */
    fun armIdle(activity: Activity) {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return
        runCatching { adapter.enableReaderMode(activity, { /* swallow */ }, READER_FLAGS, null) }
    }

    /**
     * Disarms reader mode. Required before this app emulates a card (reader mode suppresses HCE), so the reader
     * screen must release on the way out — the holder screen would otherwise never answer a tap. Safe to repeat.
     */
    fun release(activity: Activity) {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return
        runCatching { adapter.disableReaderMode(activity) }
    }

    private const val READER_FLAGS = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or
        NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS

    /**
     * The Handover Request to offer if the mdoc uses negotiated handover. Our reader connects as BLE central
     * to the carrier the mdoc names in its Handover Select, so this proposes a peripheral-server BLE carrier
     * with a fresh UUID (the mdoc's own carrier is authoritative); the collision-resolution random is per tap.
     */
    private fun negotiatedHandoverRequest(): ByteArray {
        val uuid = ByteArray(16).also { u ->
            val id = UUID.randomUUID()
            for (i in 0 until 8) u[i] = (id.mostSignificantBits shr (56 - i * 8)).toByte()
            for (i in 0 until 8) u[8 + i] = (id.leastSignificantBits shr (56 - i * 8)).toByte()
        }
        val collisionResolution = ByteArray(2).also { SecureRandom().nextBytes(it) }
        return MdocNfcEngagement.buildHandoverRequest(
            serviceUuid = uuid,
            collisionResolution = collisionResolution,
            peripheralServerMode = true,
            readerEngagement = MdocNfcEngagement.readerEngagement(),
        )
    }
}
