package com.hopae.eudi.wallet.spi

import java.security.SecureRandom
import java.time.Instant

/** Injectable clock — tests pin it for deterministic validity checks. */
fun interface WalletClock {
    fun now(): Instant

    companion object {
        val System: WalletClock = WalletClock { Instant.now() }
    }
}

/** Injectable randomness — tests use fixed seeds for deterministic transcripts. */
fun interface Rng {
    fun nextBytes(size: Int): ByteArray

    companion object {
        private val secureRandom = SecureRandom()
        val Default: Rng = Rng { size -> ByteArray(size).also(secureRandom::nextBytes) }
    }
}

interface WalletLogger {
    enum class Level { Debug, Info, Warn, Error }

    fun log(level: Level, message: String, throwable: Throwable? = null)
}
