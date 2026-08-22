package com.hopae.eudi.demo.ui

import android.content.Context

/**
 * Persisted proximity-sharing preferences: the last-used engagement kind (QR vs NFC, remembered so the next
 * Present-in-person opens on it) plus the advanced transport variants chosen in Settings.
 *
 * Defaults follow one preference, **mdoc central client mode** — the reader advertises and the wallet only
 * scans. §8.3.3.1.1.1 tells a reader to select it when the mdoc supports both, Google Wallet always picks it,
 * and it keeps the wallet from broadcasting a service UUID of its own. So: **negotiated** NFC handover, where
 * the reader offers its carriers and the wallet selects one instead of imposing a role, and **Central** for
 * the QR rows, where a QR engagement can publish only one mode's UUID and has to commit up front.
 */
object ProximityPrefs {
    private const val FILE = "proximity_prefs"
    private const val K_KIND = "kind"       // 0 = QR, 1 = NFC
    private const val K_BLE = "ble_central" // true = central (default), false = peripheral
    private const val K_NFC = "nfc_nego"    // true = negotiated (default), false = static

    const val QR = 0
    const val NFC = 1

    private fun p(ctx: Context) = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /** [QR] or [NFC], remembered across sessions; defaults to QR (works without NFC hardware). */
    fun kind(ctx: Context): Int = p(ctx).getInt(K_KIND, QR)
    fun setKind(ctx: Context, kind: Int) = p(ctx).edit().putInt(K_KIND, kind).apply()

    fun bleCentral(ctx: Context): Boolean = p(ctx).getBoolean(K_BLE, true)
    fun setBleCentral(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean(K_BLE, v).apply()

    fun nfcNegotiated(ctx: Context): Boolean = p(ctx).getBoolean(K_NFC, true)
    fun setNfcNegotiated(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean(K_NFC, v).apply()

    /** The concrete engagement mode: 0 = QR peripheral, 1 = QR central, 2 = NFC static, 3 = NFC negotiated. */
    fun mode(ctx: Context): Int = when (kind(ctx)) {
        NFC -> if (nfcNegotiated(ctx)) 3 else 2
        else -> if (bleCentral(ctx)) 1 else 0
    }
}
