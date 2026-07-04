package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseHeaders
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SecureAreaCoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm

/** Builds a signed mdoc `DeviceRequest` (with `readerAuth`) for tests — the reader side. */
object MdocTestReader {

    private const val TAG24: ULong = 24u

    suspend fun deviceRequest(
        area: SecureArea,
        readerKey: KeyInfo,
        docType: String,
        requested: Map<String, List<String>>,
        sessionTranscript: Cbor,
        x5chain: List<ByteArray>,
        intentToRetain: Boolean = false,
    ): ByteArray {
        val nameSpaces = Cbor.CborMap(requested.map { (ns, elems) ->
            Cbor.Text(ns) to Cbor.CborMap(elems.map { Cbor.Text(it) to Cbor.Bool(intentToRetain) })
        })
        val itemsRequest = Cbor.CborMap(listOf(Cbor.Text("docType") to Cbor.Text(docType), Cbor.Text("nameSpaces") to nameSpaces))
        val itemsRequestBytes = Cbor.Tagged(TAG24, Cbor.Bytes(CborEncoder.encode(itemsRequest)))

        val readerAuthentication = Cbor.Array(listOf(Cbor.Text("ReaderAuthentication"), sessionTranscript, itemsRequestBytes))
        val readerAuthBytes = CborEncoder.encode(Cbor.Tagged(TAG24, Cbor.Bytes(CborEncoder.encode(readerAuthentication))))
        val readerAuth = CoseSign1.sign(
            protected = CoseHeaders.of(algorithm = SigningAlgorithm.ES256.coseAlgorithm),
            unprotected = CoseHeaders(Cbor.CborMap(listOf(Cbor.int(33) to Cbor.Array(x5chain.map { Cbor.Bytes(it) })))),
            payload = null,
            detachedPayload = readerAuthBytes,
            signer = SecureAreaCoseSigner(area, readerKey.handle, SigningAlgorithm.ES256),
        )

        val docRequest = Cbor.CborMap(
            listOf(Cbor.Text("itemsRequest") to itemsRequestBytes, Cbor.Text("readerAuth") to readerAuth.toCbor(tagged = false))
        )
        val deviceRequest = Cbor.CborMap(
            listOf(Cbor.Text("version") to Cbor.Text("1.0"), Cbor.Text("docRequests") to Cbor.Array(listOf(docRequest)))
        )
        return CborEncoder.encode(deviceRequest)
    }
}
