package com.hopae.eudi.wallet.store

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeyHandle
import com.hopae.eudi.wallet.spi.KeyUse
import com.hopae.eudi.wallet.spi.SecureAreaId
import java.time.Instant

class EnvelopeCodecException(message: String) : Exception(message)

/**
 * CredentialEnvelope <-> deterministic CBOR (integer-keyed maps, version field for migration).
 * Schema v1 — cross-language golden vector pinned in the tests.
 */
object EnvelopeCodec {

    private const val VERSION = 1L

    // top-level keys
    private const val K_VERSION = 0L
    private const val K_ID = 1L
    private const val K_FORMAT_TYPE = 2L      // 0 = mso_mdoc, 1 = dc+sd-jwt
    private const val K_DOCTYPE_OR_VCT = 3L
    private const val K_CREATED_AT = 4L       // epoch millis
    private const val K_LIFECYCLE_TYPE = 5L   // 0 pending, 1 deferred, 2 issued
    private const val K_LIFECYCLE = 6L
    private const val K_METADATA = 7L         // optional issuer/display metadata

    fun encode(envelope: CredentialEnvelope): ByteArray = CborEncoder.encode(toCbor(envelope))

    fun decode(bytes: ByteArray): CredentialEnvelope = fromCbor(CborDecoder.decode(bytes))

    private fun toCbor(e: CredentialEnvelope): Cbor {
        val (formatType, docTypeOrVct) = when (val f = e.format) {
            is CredentialFormat.MsoMdoc -> 0L to f.docType
            is CredentialFormat.SdJwtVc -> 1L to f.vct
        }
        val (lifecycleType, lifecycle) = when (val l = e.lifecycle) {
            is EnvelopeLifecycle.Pending -> 0L to cborMap {
                l.authorizationUrl?.let { put(0L, Cbor.Text(it)) }
                l.resumeContext?.let { put(1L, Cbor.Bytes(it)) }
            }
            is EnvelopeLifecycle.Deferred -> 1L to cborMap {
                put(0L, Cbor.Bytes(l.transactionContext))
                l.retryAfter?.let { put(1L, Cbor.int(it.toEpochMilli())) }
            }
            is EnvelopeLifecycle.Issued -> 2L to cborMap {
                put(
                    0L,
                    cborMap {
                        put(0L, Cbor.int(l.policy.batchSize.toLong()))
                        put(1L, Cbor.int(if (l.policy.use == KeyUse.Rotate) 0L else 1L))
                    }
                )
                put(
                    1L,
                    Cbor.Array(
                        l.instances.map { i ->
                            cborMap {
                                put(0L, Cbor.Text(i.key.secureArea.value))
                                put(1L, Cbor.Text(i.key.alias))
                                put(2L, Cbor.Bytes(i.payload))
                                put(3L, Cbor.int(i.useCount.toLong()))
                            }
                        }
                    )
                )
            }
        }
        return cborMap {
            put(K_VERSION, Cbor.int(VERSION))
            put(K_ID, Cbor.Text(e.id.value))
            put(K_FORMAT_TYPE, Cbor.int(formatType))
            put(K_DOCTYPE_OR_VCT, Cbor.Text(docTypeOrVct))
            put(K_CREATED_AT, Cbor.int(e.createdAt.toEpochMilli()))
            put(K_LIFECYCLE_TYPE, Cbor.int(lifecycleType))
            put(K_LIFECYCLE, lifecycle)
            e.metadata?.let { m ->
                put(K_METADATA, cborMap {
                    put(0L, Cbor.Text(m.issuerUrl))
                    m.issuerDisplayName?.let { put(1L, Cbor.Text(it)) }
                    put(2L, Cbor.Text(m.configurationId))
                    m.displayName?.let { put(3L, Cbor.Text(it)) }
                    m.logoUri?.let { put(4L, Cbor.Text(it)) }
                    m.backgroundColor?.let { put(5L, Cbor.Text(it)) }
                })
            }
        }
    }

    private fun fromCbor(c: Cbor): CredentialEnvelope {
        val root = c.asMap("envelope")
        val version = root.long(K_VERSION)
        if (version != VERSION) throw EnvelopeCodecException("unsupported envelope version $version")

        val format = when (val t = root.long(K_FORMAT_TYPE)) {
            0L -> CredentialFormat.MsoMdoc(root.text(K_DOCTYPE_OR_VCT))
            1L -> CredentialFormat.SdJwtVc(root.text(K_DOCTYPE_OR_VCT))
            else -> throw EnvelopeCodecException("unknown format type $t")
        }
        val lifecycleMap = root.get(K_LIFECYCLE)?.asMap("lifecycle")
            ?: throw EnvelopeCodecException("missing lifecycle")
        val lifecycle = when (val t = root.long(K_LIFECYCLE_TYPE)) {
            0L -> EnvelopeLifecycle.Pending(
                authorizationUrl = lifecycleMap.get(0L)?.let { (it as? Cbor.Text)?.value },
                resumeContext = lifecycleMap.get(1L)?.let { (it as? Cbor.Bytes)?.value },
            )
            1L -> EnvelopeLifecycle.Deferred(
                transactionContext = lifecycleMap.bytes(0L),
                retryAfter = lifecycleMap.get(1L)?.let { Instant.ofEpochMilli(it.longValue("retryAfter")) },
            )
            2L -> {
                val policyMap = lifecycleMap.get(0L)?.asMap("policy")
                    ?: throw EnvelopeCodecException("missing policy")
                val policy = CredentialPolicy(
                    batchSize = policyMap.long(0L).toInt(),
                    use = if (policyMap.long(1L) == 0L) KeyUse.Rotate else KeyUse.OneTime,
                )
                val instances = (lifecycleMap.get(1L) as? Cbor.Array
                    ?: throw EnvelopeCodecException("missing instances")).items.map { item ->
                    val m = item.asMap("instance")
                    CredentialInstance(
                        key = KeyHandle(SecureAreaId(m.text(0L)), m.text(1L)),
                        payload = m.bytes(2L),
                        useCount = m.long(3L).toInt(),
                    )
                }
                EnvelopeLifecycle.Issued(policy, instances)
            }
            else -> throw EnvelopeCodecException("unknown lifecycle type $t")
        }
        val metadata = root.get(K_METADATA)?.asMap("metadata")?.let { m ->
            CredentialMetadata(
                issuerUrl = m.text(0L),
                issuerDisplayName = (m.get(1L) as? Cbor.Text)?.value,
                configurationId = m.text(2L),
                displayName = (m.get(3L) as? Cbor.Text)?.value,
                logoUri = (m.get(4L) as? Cbor.Text)?.value,
                backgroundColor = (m.get(5L) as? Cbor.Text)?.value,
            )
        }
        return CredentialEnvelope(
            id = CredentialId(root.text(K_ID)),
            format = format,
            createdAt = Instant.ofEpochMilli(root.long(K_CREATED_AT)),
            lifecycle = lifecycle,
            metadata = metadata,
        )
    }

    /* ---- small builder/reader helpers ---- */

    private class MapBuilder {
        val entries = mutableListOf<Pair<Cbor, Cbor>>()
        fun put(key: Long, value: Cbor) {
            entries.add(Cbor.int(key) to value)
        }
    }

    private fun cborMap(block: MapBuilder.() -> Unit): Cbor =
        Cbor.CborMap(MapBuilder().apply(block).entries)

    private fun Cbor.asMap(what: String): Cbor.CborMap =
        this as? Cbor.CborMap ?: throw EnvelopeCodecException("$what must be a map")

    private fun Cbor.CborMap.get(key: Long): Cbor? =
        entries.firstOrNull { (k, _) -> (k as? Cbor.UInt)?.value == key.toULong() }?.second

    private fun Cbor.longValue(what: String): Long = when (this) {
        is Cbor.UInt -> value.toLong()
        is Cbor.NInt -> -1L - n.toLong()
        else -> throw EnvelopeCodecException("$what must be an integer")
    }

    private fun Cbor.CborMap.long(key: Long): Long =
        get(key)?.longValue("key $key") ?: throw EnvelopeCodecException("missing key $key")

    private fun Cbor.CborMap.text(key: Long): String =
        (get(key) as? Cbor.Text)?.value ?: throw EnvelopeCodecException("missing text key $key")

    private fun Cbor.CborMap.bytes(key: Long): ByteArray =
        (get(key) as? Cbor.Bytes)?.value ?: throw EnvelopeCodecException("missing bytes key $key")
}
