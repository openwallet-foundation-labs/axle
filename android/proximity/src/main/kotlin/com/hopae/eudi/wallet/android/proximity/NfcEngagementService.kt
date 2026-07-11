package com.hopae.eudi.wallet.android.proximity

import android.app.Activity
import android.content.ComponentName
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import com.hopae.eudi.wallet.proximity.NfcEngagementProcessor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * NFC Forum **Type 4 Tag** emulation (Host Card Emulation) that runs the SDK's ISO 18013-5 NFC engagement
 * state machine. The holder arms a [NfcEngagementProcessor] via [processor]; incoming APDUs are handed to it
 * and its responses returned to the reader. The processor decides static vs negotiated handover, so this
 * service is a thin bridge — no protocol logic lives here.
 *
 * Responses are produced asynchronously (`processCommandApdu` returns null, [sendResponseApdu] delivers the
 * result) because the negotiated Handover Select is built by the wallet's presentation flow. APDUs are
 * serialised: the reader is strictly request/response, and the [Mutex] guards the (non-reentrant) processor.
 */
class NfcEngagementService : HostApduService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()

    override fun processCommandApdu(apdu: ByteArray, extras: Bundle?): ByteArray? {
        val active = processor ?: return SW_NOT_FOUND
        scope.launch {
            val response = try {
                mutex.withLock { active.processCommand(apdu) }
            } catch (e: Throwable) {
                SW_ERROR
            }
            sendResponseApdu(response)
        }
        return null // response delivered via sendResponseApdu
    }

    override fun onDeactivated(reason: Int) {
        processor?.reset()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        /**
         * The engagement state machine to serve while presenting; armed by the holder screen (static or
         * negotiated) and cleared when it disarms. Null means no NFC engagement is in progress → tags are refused.
         */
        @Volatile
        var processor: NfcEngagementProcessor? = null

        /**
         * Routes NFC (the shared NDEF Type-4 AID) to *this* service while [activity] is in the foreground,
         * so a tap reaches this wallet even when other NFC/mdoc wallets register the same AID (Android would
         * otherwise show an HCE routing-conflict prompt). Call when the holder begins NFC engagement; pair
         * with [releaseForeground]. Returns false if NFC is unavailable or the preference could not be set.
         */
        fun requestForeground(activity: Activity): Boolean {
            val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return false
            val component = ComponentName(activity, NfcEngagementService::class.java)
            return runCatching { CardEmulation.getInstance(adapter).setPreferredService(activity, component) }.getOrDefault(false)
        }

        /** Releases the foreground routing preference set by [requestForeground]. */
        fun releaseForeground(activity: Activity) {
            val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return
            runCatching { CardEmulation.getInstance(adapter).unsetPreferredService(activity) }
        }

        private val SW_NOT_FOUND = byteArrayOf(0x6A, 0x82.toByte())
        private val SW_ERROR = byteArrayOf(0x6F, 0x00)
    }
}
