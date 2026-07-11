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
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The reader side of ISO 18013-5 NFC engagement: puts the phone in NFC reader mode and drives the SDK's
 * [MdocNfcHandover] over the tag's ISO-DEP channel. It auto-detects the mdoc's handover mode — static
 * (reads the Handover Select) or negotiated (runs the TNEP exchange, offering the [Handover Request] built
 * here) — and returns both messages so the caller can bind the SessionTranscript.
 */
object NfcReader {
    /** Suspends until an mdoc tag is tapped, then returns its handover (Select, plus Request iff negotiated). */
    suspend fun readHandover(activity: Activity): NfcHandover = suspendCancellableCoroutine { cont ->
        val adapter = NfcAdapter.getDefaultAdapter(activity)
            ?: return@suspendCancellableCoroutine cont.resumeWithException(IllegalStateException("NFC unavailable"))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val callback = NfcAdapter.ReaderCallback { tag ->
            val iso = IsoDep.get(tag) ?: return@ReaderCallback
            scope.launch {
                try {
                    iso.connect()
                    iso.timeout = 5000
                    val result = MdocNfcHandover.read(negotiatedHandoverRequest()) { apdu -> iso.transceive(apdu) }
                    runCatching { iso.close() }
                    runCatching { adapter.disableReaderMode(activity) }
                    if (cont.isActive) cont.resume(result)
                } catch (e: Exception) {
                    if (cont.isActive) cont.resumeWithException(e)
                }
            }
        }
        val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        adapter.enableReaderMode(activity, callback, flags, null)
        cont.invokeOnCancellation {
            runCatching { adapter.disableReaderMode(activity) }
            scope.cancel()
        }
    }

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
