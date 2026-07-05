package com.hopae.eudi.demo

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * In-app debug log sink — mirrors to logcat (`EudiDemo`), to a StateFlow the Debug Log screen renders,
 * and (once [attach]ed) to a persistent file so logs survive app restarts.
 */
object LogStore {
    private const val TAG = "EudiDemo"
    private const val MAX = 2000
    private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    private val _lines = MutableStateFlow<List<String>>(emptyList())
    val lines: StateFlow<List<String>> = _lines

    @Volatile private var file: File? = null

    /** Point the sink at a persistent file and load any prior lines. */
    fun attach(logFile: File) {
        file = logFile
        runCatching { if (logFile.exists()) _lines.value = logFile.readLines().takeLast(MAX) }
    }

    fun log(message: String) {
        Log.d(TAG, message)
        val line = "${fmt.format(Date())}  $message"
        _lines.update { (it + line).takeLast(MAX) }
        runCatching { file?.appendText(line + "\n") }
    }

    fun clear() {
        _lines.value = emptyList()
        runCatching { file?.writeText("") }
    }

    fun asText(): String = _lines.value.joinToString("\n")
}
