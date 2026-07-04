package com.hopae.eudi.wallet.spi

import kotlinx.coroutines.flow.Flow

/** Encrypted blob storage; no domain logic (API-CONTRACT.md §7). */
interface StorageDriver {
    suspend fun put(collection: String, key: String, value: ByteArray)
    suspend fun get(collection: String, key: String): ByteArray?
    suspend fun delete(collection: String, key: String)
    suspend fun keys(collection: String): List<String>
    suspend fun transaction(block: suspend StorageTx.() -> Unit)
}

interface StorageTx {
    suspend fun put(collection: String, key: String, value: ByteArray)
    suspend fun get(collection: String, key: String): ByteArray?
    suspend fun delete(collection: String, key: String)
}

enum class HttpMethod { GET, POST, PUT, PATCH, DELETE }

class HttpRequest(
    val method: HttpMethod,
    val url: String,
    val headers: List<Pair<String, String>> = emptyList(),
    val body: ByteArray? = null,
    /** OpenID flows need redirect interception (e.g. capturing authorization responses). */
    val followRedirects: Boolean = true,
)

class HttpResponse(
    val status: Int,
    val headers: List<Pair<String, String>>,
    val body: ByteArray,
)

interface HttpTransport {
    suspend fun execute(request: HttpRequest): HttpResponse
}

/** ISO 18013-5 transport layer. The session layer (encryption) lives in core on top of this. */
enum class RetrievalMethod { BleServer, BleClient, Nfc }

/** Engagement-derived parameters for opening a channel. Shape is pinned in M5. */
class ChannelSessionInfo(
    val method: RetrievalMethod,
    val parameters: ByteArray? = null,
)

interface DeviceChannelFactory {
    val method: RetrievalMethod
    suspend fun open(session: ChannelSessionInfo): DeviceChannel
}

interface DeviceChannel {
    suspend fun send(data: ByteArray)
    val incoming: Flow<ByteArray>
    suspend fun close()
}

/** Wallet-provider backend port: WUA and key attestations (HAIP wallet attestation). */
interface WalletAttestationProvider {
    suspend fun walletAttestation(keyInfo: KeyInfo): String
    suspend fun keyAttestation(keys: List<KeyInfo>, nonce: String?): String
}
