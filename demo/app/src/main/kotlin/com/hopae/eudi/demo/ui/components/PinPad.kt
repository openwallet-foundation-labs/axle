package com.hopae.eudi.demo.ui.components

import android.view.HapticFeedbackConstants
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Backspace
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hopae.eudi.demo.ui.theme.WalletTheme

/** The 6 (or n) filled/empty PIN dots. Turns red on [error]. */
@Composable
fun PinDots(filled: Int, total: Int = 6, error: Boolean = false) {
    val c = WalletTheme.colors
    val on = if (error) c.danger else c.brand
    val off = if (error) c.dangerBorder else Color(0xFFC9CFDB)
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        repeat(total) { i ->
            val f = i < filled
            Box(
                Modifier.size(14.dp).clip(RoundedCornerShape(99.dp))
                    .background(if (f) on else Color.Transparent)
                    .border(1.5.dp, if (f) on else off, RoundedCornerShape(99.dp)),
            )
        }
    }
}

/**
 * The numeric keypad. Emits digits "0".."9" via [onDigit], backspace via [onDelete]. When [onBiometric] is
 * non-null a fingerprint key takes the bottom-left slot (used on the lock screen); otherwise that slot is blank.
 */
@Composable
fun Keypad(
    onDigit: (String) -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier,
    onBiometric: (() -> Unit)? = null,
) {
    val view = LocalView.current
    fun tap() = view.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
    Column(modifier.widthIn(max = 300.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        listOf(listOf("1", "2", "3"), listOf("4", "5", "6"), listOf("7", "8", "9")).forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                row.forEach { d -> DigitKey(d, Modifier.weight(1f)) { tap(); onDigit(d) } }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            if (onBiometric != null) {
                IconKey(Modifier.weight(1f), { tap(); onBiometric() }) { Icon(Icons.Filled.Fingerprint, null, tint = WalletTheme.colors.brand) }
            } else {
                Box(Modifier.weight(1f).height(56.dp))
            }
            DigitKey("0", Modifier.weight(1f)) { tap(); onDigit("0") }
            IconKey(Modifier.weight(1f), { tap(); onDelete() }) { Icon(Icons.AutoMirrored.Filled.Backspace, null, tint = WalletTheme.colors.inkBody) }
        }
    }
}

@Composable
private fun DigitKey(digit: String, modifier: Modifier, onClick: () -> Unit) {
    Box(
        modifier.height(56.dp).clip(RoundedCornerShape(14.dp)).background(WalletTheme.colors.card)
            .border(1.dp, WalletTheme.colors.cardBorderStrong, RoundedCornerShape(14.dp))
            .clickable { onClick() },
        contentAlignment = Alignment.Center,
    ) {
        Text(digit, color = WalletTheme.colors.ink, fontWeight = FontWeight(700), fontSize = 21.sp)
    }
}

@Composable
private fun IconKey(modifier: Modifier, onClick: () -> Unit, icon: @Composable () -> Unit) {
    Box(
        modifier.height(56.dp).clip(RoundedCornerShape(14.dp)).clickable { onClick() },
        contentAlignment = Alignment.Center,
    ) { icon() }
}
