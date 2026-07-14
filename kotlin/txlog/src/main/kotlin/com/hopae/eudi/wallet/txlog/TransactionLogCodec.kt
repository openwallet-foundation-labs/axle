package com.hopae.eudi.wallet.txlog

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue

/**
 * JSON serialization for [TransactionLogEntry] so a persistent [TransactionLogStore] can store
 * entries as text. Byte fields are base64url; the shape mirrors the Swift codec for a stable,
 * cross-platform on-disk format.
 */
object TransactionLogCodec {

    fun encode(entry: TransactionLogEntry): String = toJson(entry).serialize()

    fun decode(text: String): TransactionLogEntry =
        fromJson(JsonValue.parse(text) as? JsonValue.Obj ?: error("transaction log entry must be a JSON object"))

    fun toJson(e: TransactionLogEntry): JsonValue.Obj = JsonValue.Obj(
        buildList {
            add("id" to JsonValue.Str(e.id))
            add("timestamp" to JsonValue.NumInt(e.timestamp))
            add("type" to JsonValue.Str(e.type.name))
            add("status" to JsonValue.Str(e.status.name))
            e.relyingParty?.let { add("relyingParty" to rpJson(it)) }
            e.issuer?.let { add("issuer" to JsonValue.Str(it)) }
            add("documents" to JsonValue.Arr(e.documents.map { docJson(it) }))
            e.error?.let { add("error" to JsonValue.Str(it)) }
            e.rawRequest?.let { add("rawRequest" to JsonValue.Str(Base64Url.encode(it))) }
            e.rawResponse?.let { add("rawResponse" to JsonValue.Str(Base64Url.encode(it))) }
            e.transport?.let { add("transport" to JsonValue.Str(it.name)) }
            e.issuerName?.let { add("issuerName" to JsonValue.Str(it)) }
            e.issuerRegistered?.let { add("issuerRegistered" to JsonValue.Bool(it)) }
        }
    )

    fun fromJson(o: JsonValue.Obj): TransactionLogEntry = TransactionLogEntry(
        id = o.str("id") ?: error("missing id"),
        timestamp = o.num("timestamp") ?: error("missing timestamp"),
        type = TransactionType.valueOf(o.str("type") ?: error("missing type")),
        status = TransactionStatus.valueOf(o.str("status") ?: error("missing status")),
        relyingParty = (o["relyingParty"] as? JsonValue.Obj)?.let { rpFromJson(it) },
        issuer = o.str("issuer"),
        documents = (o["documents"] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Obj)?.let(::docFromJson) } ?: emptyList(),
        error = o.str("error"),
        rawRequest = o.str("rawRequest")?.let { Base64Url.decode(it) },
        rawResponse = o.str("rawResponse")?.let { Base64Url.decode(it) },
        transport = o.str("transport")?.let { runCatching { TransactionTransport.valueOf(it) }.getOrNull() },
        issuerName = o.str("issuerName"),
        issuerRegistered = (o["issuerRegistered"] as? JsonValue.Bool)?.value,
    )

    private fun rpJson(rp: RelyingParty) = JsonValue.Obj(
        buildList {
            add("id" to JsonValue.Str(rp.id))
            rp.name?.let { add("name" to JsonValue.Str(it)) }
            add("trusted" to JsonValue.Bool(rp.trusted))
            if (rp.certificateChainDer.isNotEmpty()) {
                add("certificateChain" to JsonValue.Arr(rp.certificateChainDer.map { JsonValue.Str(Base64Url.encode(it)) }))
            }
            rp.clientIdScheme?.let { add("clientIdScheme" to JsonValue.Str(it)) }
            rp.subject?.let { add("subject" to JsonValue.Str(it)) }
            if (rp.entitlements.isNotEmpty()) add("entitlements" to JsonValue.Arr(rp.entitlements.map { JsonValue.Str(it) }))
            if (rp.purpose.isNotEmpty()) add("purpose" to JsonValue.Arr(rp.purpose.map { textJson(it) }))
            rp.intermediaryName?.let { add("intermediaryName" to JsonValue.Str(it)) }
            rp.intermediarySub?.let { add("intermediarySub" to JsonValue.Str(it)) }
            rp.attested?.let { add("attested" to JsonValue.Bool(it)) }
            rp.statusValid?.let { add("statusValid" to JsonValue.Bool(it)) }
        }
    )

    private fun rpFromJson(o: JsonValue.Obj) = RelyingParty(
        id = o.str("id") ?: error("relyingParty missing id"),
        name = o.str("name"),
        trusted = (o["trusted"] as? JsonValue.Bool)?.value ?: false,
        certificateChainDer = (o["certificateChain"] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.value?.let(Base64Url::decode) } ?: emptyList(),
        clientIdScheme = o.str("clientIdScheme"),
        subject = o.str("subject"),
        entitlements = (o["entitlements"] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.value } ?: emptyList(),
        purpose = (o["purpose"] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Obj)?.let(::textFromJson) } ?: emptyList(),
        intermediaryName = o.str("intermediaryName"),
        intermediarySub = o.str("intermediarySub"),
        attested = (o["attested"] as? JsonValue.Bool)?.value,
        statusValid = (o["statusValid"] as? JsonValue.Bool)?.value,
    )

    private fun textJson(t: LocalizedText) = JsonValue.Obj(listOf("lang" to JsonValue.Str(t.lang), "value" to JsonValue.Str(t.value)))
    private fun textFromJson(o: JsonValue.Obj) = LocalizedText(o.str("lang") ?: "", o.str("value") ?: "")

    private fun docJson(d: LoggedDocument) = JsonValue.Obj(
        buildList {
            add("format" to JsonValue.Str(d.format))
            d.type?.let { add("type" to JsonValue.Str(it)) }
            d.queryId?.let { add("queryId" to JsonValue.Str(it)) }
            add("claims" to JsonValue.Arr(d.claims.map { claimJson(it) }))
        }
    )

    private fun docFromJson(o: JsonValue.Obj) = LoggedDocument(
        format = o.str("format") ?: error("document missing format"),
        type = o.str("type"),
        queryId = o.str("queryId"),
        claims = (o["claims"] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Obj)?.let(::claimFromJson) } ?: emptyList(),
    )

    private fun claimJson(c: LoggedClaim) = JsonValue.Obj(
        buildList {
            add("path" to JsonValue.Arr(c.path.map { JsonValue.Str(it) }))
            c.value?.let { add("value" to JsonValue.Str(it)) }
        }
    )

    private fun claimFromJson(o: JsonValue.Obj) = LoggedClaim(
        path = (o["path"] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.value } ?: emptyList(),
        value = o.str("value"),
    )

    private fun JsonValue.Obj.str(name: String): String? = (this[name] as? JsonValue.Str)?.value
    private fun JsonValue.Obj.num(name: String): Long? = (this[name] as? JsonValue.NumInt)?.value
}
