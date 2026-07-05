package com.hopae.eudi.demo

import android.content.Context
import com.hopae.eudi.demo.adapters.FileStorageDriver
import com.hopae.eudi.demo.adapters.LogWalletLogger
import com.hopae.eudi.demo.adapters.OkHttpTransport
import com.hopae.eudi.wallet.TransactionLogConfig
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.WalletConfig
import com.hopae.eudi.wallet.WalletPorts
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import java.io.File

/**
 * Assembles the EUDI Wallet SDK with Android debug-grade adapters — one instance per app process.
 *
 * Debug notes:
 *  - [SoftwareSecureArea] holds holder keys in memory (not persisted across process restarts). A
 *    production wallet injects an Android Keystore-backed SecureArea (hardware-bound keys).
 *  - [FileStorageDriver] persists credentials as plain files; production should encrypt at rest.
 *  - The transaction log uses the default in-memory store, so history resets on restart.
 */
object DemoWallet {
    @Volatile private var instance: Wallet? = null

    fun get(context: Context): Wallet = instance ?: synchronized(this) {
        instance ?: Wallet.create(
            // Debug wallet: also log presentations that fail at final submission (opt-in).
            config = WalletConfig(transactionLog = TransactionLogConfig(recordFailures = true)),
            ports = WalletPorts(
                secureAreas = listOf(SoftwareSecureArea()),
                storage = FileStorageDriver(File(context.applicationContext.filesDir, "wallet")),
                http = OkHttpTransport(),
                logger = LogWalletLogger(),
            ),
        ).also {
            instance = it
            LogStore.log("Wallet assembled (SoftwareSecureArea · FileStorageDriver · OkHttp)")
        }
    }
}
