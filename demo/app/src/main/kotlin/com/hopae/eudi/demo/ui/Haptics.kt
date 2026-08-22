package com.hopae.eudi.demo.ui

import android.content.Context
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager

/**
 * Short vibrations for moments the screen cannot confirm on its own.
 *
 * The NFC ones matter most: a tap is over in milliseconds but the handover plus the BLE connection take
 * seconds, so without a buzz the user has no way to tell a registered tap from a missed one and pulls the
 * phones apart mid-exchange. Both roles get it — the reader when it takes the tag, the holder on the first
 * command APDU of the tap.
 *
 * Uses [Vibrator] rather than `View.performHapticFeedback` because these fire from NFC binder threads with no
 * View in reach. `VIBRATE` is a normal permission, granted at install.
 */
object Haptics {
    private fun vibrator(ctx: Context): Vibrator? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ctx.getSystemService(VibratorManager::class.java)?.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            ctx.getSystemService(Vibrator::class.java)
        }

    /** A single firm click — "the tap landed", the exchange is now running. */
    fun tap(ctx: Context) = play(ctx, VibrationEffect.EFFECT_HEAVY_CLICK)

    /** A lighter tick for the end of an exchange. */
    fun done(ctx: Context) = play(ctx, VibrationEffect.EFFECT_CLICK)

    private fun play(ctx: Context, effect: Int) {
        val v = vibrator(ctx)?.takeIf { it.hasVibrator() } ?: return
        runCatching { v.vibrate(VibrationEffect.createPredefined(effect)) }
    }
}
