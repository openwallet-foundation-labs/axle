package com.hopae.eudi.demo

import android.content.Context
import android.util.Base64
import com.hopae.eudi.demo.adapters.LogWalletLogger
import com.hopae.eudi.wallet.android.AndroidKeystoreSecureArea
import com.hopae.eudi.wallet.android.FileStorageDriver
import com.hopae.eudi.wallet.android.FileTransactionLogStore
import com.hopae.eudi.wallet.android.OkHttpTransport
import com.hopae.eudi.wallet.IssuanceConfig
import com.hopae.eudi.wallet.TransactionLogConfig
import com.hopae.eudi.wallet.TrustConfig
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.WalletConfig
import com.hopae.eudi.wallet.WalletPorts
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.trustlist.TrustedListClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Assembles the EUDI Wallet SDK with Android debug-grade adapters — one instance per app process.
 *
 * Trust: on first assembly the wallet pulls its CA anchors from the sandbox JAdES **trusted lists** (verified
 * against the pinned Scheme Operator cert) into [TrustConfig], so it can actually verify our issuer (credential
 * DSC / signed metadata), verifier (WRPAC + WRPRC), and registrar (WRPRC status, TS5 registry). Without these
 * anchors the wallet can hold credentials but cannot establish trust — so [get] is `suspend` (one network
 * fetch at startup).
 *
 * Debug notes:
 *  - [AndroidKeystoreSecureArea] holds hardware-bound holder keys that persist across restarts.
 *  - [FileStorageDriver] persists credentials as plain files; production should encrypt at rest.
 */
object DemoWallet {
    /** Base of the sandbox JAdES trusted lists (our Scheme Operator). */
    private const val TL_BASE = "https://trusted-list.vercel.app/tl"

    @Volatile private var instance: Wallet? = null
    private val buildLock = Mutex()

    /** Persistent transaction-log store — exposed so the UI can clear it. */
    lateinit var transactionStore: FileTransactionLogStore
        private set

    /** The assembled wallet, building (and fetching trust anchors) on first call. Cached thereafter. */
    suspend fun get(context: Context): Wallet =
        instance ?: buildLock.withLock {
            // build() does network (trusted lists) + disk I/O on first call → keep it off the main thread.
            instance ?: withContext(Dispatchers.IO) { build(context.applicationContext) }.also { instance = it }
        }

    /** How long a cached trusted-list snapshot is used before a re-fetch is attempted. */
    private const val TRUST_TTL_MS = 24L * 60 * 60 * 1000

    private suspend fun build(context: Context): Wallet {
        val filesDir = context.filesDir
        val logsDir = File(filesDir, "logs").apply { mkdirs() }
        LogStore.attach(File(logsDir, "debug.log"))
        transactionStore = FileTransactionLogStore(File(logsDir, "transactions.log"))
        val logger = LogWalletLogger() // routes SDK + adapter logs into the in-app LogStore
        val http = OkHttpTransport(logger = logger)

        val trust = resolveTrust(http, File(filesDir, "trust"))

        return Wallet.create(
            config = WalletConfig(
                trust = trust,
                // Authorization-code redirect — matches the EUDI reference wallet's scheme.
                issuance = IssuanceConfig(redirectUri = "eu.europa.ec.euidi://authorization"),
                // Debug wallet: also log presentations that fail at final submission (opt-in).
                transactionLog = TransactionLogConfig(recordFailures = true),
            ),
            ports = WalletPorts(
                secureAreas = listOf(AndroidKeystoreSecureArea()),
                storage = FileStorageDriver(File(filesDir, "wallet")),
                http = http,
                logger = logger,
                transactionLogStore = transactionStore,
            ),
        ).also {
            LogStore.log(
                "Wallet assembled — trust anchors: issuer=${trust.issuerAnchorsDer.size} " +
                    "reader=${trust.readerAnchorsDer.size} registrar=${trust.registrarAnchorsDer.size}",
            )
        }
    }

    /**
     * The trust anchors, from disk when a cached snapshot is still fresh ([TRUST_TTL_MS]) — instant + offline —
     * otherwise re-fetched from the trusted lists and re-cached. On a fetch failure we fall back to a stale
     * cache if one exists (so a server outage / no network doesn't strip the wallet of trust). Only the
     * extracted CA DERs are kept (a few small certs), never the list JSON.
     */
    private suspend fun resolveTrust(http: HttpTransport, cacheDir: File): TrustConfig {
        loadCachedTrust(cacheDir)?.let { (cached, ageMs) ->
            if (ageMs < TRUST_TTL_MS) {
                LogStore.log("trusted-list: using cached anchors (age ${ageMs / 1000}s)")
                return cached
            }
        }
        val fetched = fetchTrust(http)
        if (fetched.issuerAnchorsDer.isNotEmpty() || fetched.registrarAnchorsDer.isNotEmpty()) {
            saveCachedTrust(cacheDir, fetched)
            return fetched
        }
        // Fetch yielded nothing (offline / outage): keep using a stale cache if we have one.
        return loadCachedTrust(cacheDir)?.first?.also { LogStore.log("trusted-list: fetch failed, using stale cache") }
            ?: TrustConfig()
    }

    /** Pull the CA anchors from the trusted lists (best-effort per list). */
    private suspend fun fetchTrust(http: HttpTransport): TrustConfig {
        val tl = TrustedListClient(http)
        val soDer = runCatching { pemToDer(fetchText(http, "$TL_BASE/scheme-operator.pem")) }
            .onFailure { LogStore.log("trusted-list: scheme-operator fetch failed (${it.message})") }
            .getOrNull() ?: return TrustConfig()

        suspend fun anchors(slug: String): List<ByteArray> =
            runCatching { tl.fetchCACerts("$TL_BASE/$slug.jades.json", soDer) }
                .onFailure { LogStore.log("trusted-list: '$slug' fetch failed: ${it.message}") }
                .getOrDefault(emptyList())

        // issued credentials chain to the PID + attestation issuer CAs; the verifier's WRPAC (and its WRPRC /
        // status list / TS5 registry) chain to the registrar CA.
        val issuerCAs = anchors("pid-issuers") + anchors("attestation-issuers")
        val registrarCAs = anchors("registrar")
        return TrustConfig(
            issuerAnchorsDer = issuerCAs,
            readerAnchorsDer = registrarCAs,
            registrarAnchorsDer = registrarCAs,
        )
    }

    // --- disk cache: <cacheDir>/{fetchedAt, issuer/*.der, registrar/*.der} ---------------------------------

    private fun loadCachedTrust(cacheDir: File): Pair<TrustConfig, Long>? {
        val stamp = File(cacheDir, "fetchedAt").takeIf { it.exists() }?.readText()?.trim()?.toLongOrNull() ?: return null
        fun ders(sub: String): List<ByteArray> =
            File(cacheDir, sub).listFiles { f -> f.extension == "der" }?.sortedBy { it.name }?.map { it.readBytes() } ?: emptyList()
        val issuer = ders("issuer")
        val registrar = ders("registrar")
        if (issuer.isEmpty() && registrar.isEmpty()) return null
        val trust = TrustConfig(issuerAnchorsDer = issuer, readerAnchorsDer = registrar, registrarAnchorsDer = registrar)
        return trust to (System.currentTimeMillis() - stamp)
    }

    private fun saveCachedTrust(cacheDir: File, trust: TrustConfig) = runCatching {
        fun write(sub: String, ders: List<ByteArray>) {
            val dir = File(cacheDir, sub).apply { deleteRecursively(); mkdirs() }
            ders.forEachIndexed { i, der -> File(dir, "%03d.der".format(i)).writeBytes(der) }
        }
        cacheDir.mkdirs()
        write("issuer", trust.issuerAnchorsDer)
        write("registrar", trust.registrarAnchorsDer) // == readerAnchorsDer
        File(cacheDir, "fetchedAt").writeText(System.currentTimeMillis().toString())
    }.onFailure { LogStore.log("trusted-list: cache write failed: ${it.message}") }

    private suspend fun fetchText(http: HttpTransport, url: String): String {
        val resp = http.execute(HttpRequest(HttpMethod.GET, url, listOf("Accept" to "*/*")))
        if (resp.status !in 200..299) throw IllegalStateException("HTTP ${resp.status} for $url")
        return resp.body.decodeToString()
    }

    private fun pemToDer(pem: String): ByteArray = Base64.decode(
        pem.replace(Regex("-----(BEGIN|END) CERTIFICATE-----"), "").replace(Regex("\\s"), ""),
        Base64.DEFAULT,
    )
}
