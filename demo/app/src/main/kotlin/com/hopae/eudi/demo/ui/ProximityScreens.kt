package com.hopae.eudi.demo.ui

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.Build
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.demo.PortraitCaptureActivity
import android.app.Activity
import com.hopae.eudi.demo.adapters.LogWalletLogger
import com.hopae.eudi.wallet.android.proximity.Ble
import com.hopae.eudi.wallet.android.proximity.BleGattClientTransport
import com.hopae.eudi.wallet.android.proximity.BleGattServerTransport
import com.hopae.eudi.wallet.android.proximity.NfcEngagementService
import com.hopae.eudi.wallet.android.proximity.NfcReader
import com.hopae.eudi.wallet.proximity.MdocNfcEngagement
import com.hopae.eudi.wallet.proximity.NfcEngagementProcessor
import com.hopae.eudi.wallet.proximity.DeviceEngagement
import kotlinx.coroutines.flow.first
import com.hopae.eudi.wallet.spi.ProximityTransport
import java.util.UUID
import com.hopae.eudi.wallet.ProximityRequest
import com.hopae.eudi.wallet.ProximitySelection
import com.hopae.eudi.wallet.ProximitySession
import com.hopae.eudi.wallet.ProximityState
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.RequestedDocument
import com.hopae.eudi.wallet.mdoc.VerifiedDocument
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

private val BLE_PERMISSIONS: Array<String> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
    arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE)
else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

/** What the reader requests — a broad mdoc set; the holder answers with whichever docType it holds. */
private fun readerRequest() = listOf(
    RequestedDocument(
        "eu.europa.ec.eudi.pid.1",
        mapOf("eu.europa.ec.eudi.pid.1" to listOf("family_name", "given_name", "birth_date", "age_over_18", "nationality")),
    ),
    RequestedDocument(
        "org.iso.18013.5.1.mDL",
        mapOf("org.iso.18013.5.1" to listOf("family_name", "given_name", "birth_date", "document_number", "expiry_date")),
    ),
)

// ---------- Holder: present an mdoc over BLE (this device is the wallet) ----------

@Composable
fun ProximityHolderDialog(wallet: Wallet, onClose: () -> Unit) {
    val context = LocalContext.current
    var status by remember { mutableStateOf("Preparing…") }
    var qr by remember { mutableStateOf<Bitmap?>(null) }
    var mode by remember { mutableStateOf(0) } // 0 = QR peripheral, 1 = QR central, 2 = NFC static, 3 = NFC negotiated
    var session by remember { mutableStateOf<ProximitySession?>(null) }
    var pending by remember { mutableStateOf<ProximityRequest?>(null) } // reader's request, awaiting the user's consent
    var granted by remember { mutableStateOf(BLE_PERMISSIONS.all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }) }
    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r -> granted = r.values.all { it } }

    DisposableEffect(granted, mode) {
        if (!granted) {
            status = "Grant Bluetooth permission to present"
            permLauncher.launch(BLE_PERMISSIONS)
            return@DisposableEffect onDispose {}
        }
        qr = null
        pending = null
        val central = mode == 1
        val nfc = mode == 2 || mode == 3
        val negotiated = mode == 3
        // NFC: win the HCE routing conflict while presenting (other wallets register the same NDEF AID).
        if (nfc) (context as? android.app.Activity)?.let { NfcEngagementService.requestForeground(it) }
        val uuid = UUID.randomUUID()
        val uuidBytes = Ble.uuidToBytes(uuid)
        val scope = CoroutineScope(Dispatchers.Main)
        // Peripheral server mode / NFC → we're the GATT server. Central client mode → we're the GATT client (the
        // reader advertises our UUID); scan for it in parallel. NFC delivers the engagement via HCE (no QR).
        val server = if (central) null else BleGattServerTransport(context, uuid, Ble.PERIPHERAL_SERVER, if (nfc) emptyList() else listOf(DeviceEngagement.bleRetrievalMethod(peripheralServerUuid = uuidBytes)), logger = LogWalletLogger())
        val client = if (central) BleGattClientTransport(context, uuid, Ble.CENTRAL_CLIENT, listOf(DeviceEngagement.bleRetrievalMethod(centralClientUuid = uuidBytes)), logger = LogWalletLogger()) else null
        val transport: ProximityTransport = server ?: client!!
        server?.start()
        if (client != null) scope.launch { runCatching { client.connect() } }

        // Drive one presentation session's state → engagement display, consent, and completion UI.
        suspend fun driveSession(s: ProximitySession) {
            session = s
            s.state.collect { st ->
                when (st) {
                    is ProximityState.EngagementReady -> {
                        // Central client mode: arm Ident verification now that the engagement (EDeviceKey) exists.
                        client?.armIdent(DeviceEngagement.eDeviceKeyBytes(st.deviceEngagement))
                        val ndef = st.handoverNdef
                        when {
                            ndef == null -> { qr = encodeQr("mdoc:" + b64(st.deviceEngagement)); status = "Waiting for a reader — show this QR" }
                            !negotiated -> { NfcEngagementService.processor = NfcEngagementProcessor(staticHandoverSelect = ndef); qr = null; status = "Tap your phone to the reader" }
                            else -> { qr = null; status = "Negotiating over NFC…" } // negotiated: the processor is already armed
                        }
                    }
                    is ProximityState.RequestReceived -> {
                        pending = st.request // ask the user before sending (like OpenID4VP consent)
                        status = "Reader connected — review the request"
                        LogStore.log("Proximity: reader requested ${st.request.documents.size} doc(s); awaiting consent")
                    }
                    ProximityState.Submitting -> { pending = null; status = "Sending response…" }
                    ProximityState.Completed -> { pending = null; status = "✅ Presented to the reader" }
                    ProximityState.Declined -> { pending = null; status = "Declined" }
                    is ProximityState.Failed -> { pending = null; status = "❌ ${st.error.message}" }
                    else -> {}
                }
            }
        }

        if (negotiated) {
            // Negotiated handover (§8.2.2.1): the reader runs the TNEP exchange and writes its Handover Request;
            // only then do we start presenting (binding [Hs, Hr]) and hand the Handover Select back over NFC.
            NfcEngagementService.processor = NfcEngagementProcessor(
                negotiatedHandoverSelect = { hr ->
                    val s = wallet.proximity.present(transport, nfc = true, handoverRequestNdef = hr)
                    scope.launch { runCatching { driveSession(s) } }
                    val ready = s.state.first { it is ProximityState.EngagementReady || it is ProximityState.Failed }
                    if (ready is ProximityState.Failed) throw ready.error
                    (ready as ProximityState.EngagementReady).handoverNdef ?: error("no Handover Select produced")
                },
            )
            status = "Tap your phone to the reader (negotiated)"
        } else {
            scope.launch {
                try {
                    driveSession(wallet.proximity.present(transport, nfc = nfc))
                } catch (e: kotlin.coroutines.cancellation.CancellationException) {
                    throw e // normal teardown when the mode changes or the dialog closes — not a failure
                } catch (e: Throwable) {
                    status = "❌ ${e.message}"
                    LogStore.log("❌ Proximity holder: ${e.message}")
                }
            }
        }
        onDispose {
            NfcEngagementService.processor = null
            if (nfc) (context as? android.app.Activity)?.let { NfcEngagementService.releaseForeground(it) }
            scope.cancel(); server?.stop(); client?.stop()
        }
    }

    Dialog(onDismissRequest = onClose) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Present mdoc (BLE / NFC)", style = MaterialTheme.typography.titleLarge)
                val req = pending
                if (req != null) {
                    ProximityConsent(
                        req,
                        onShare = { session?.respond(ProximitySelection.auto(req)); pending = null; status = "Sending response…" },
                        onDecline = { session?.decline(); pending = null; status = "Declined" },
                    )
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            FilterChip(selected = mode == 0, onClick = { mode = 0 }, label = { Text("QR·Periph") })
                            FilterChip(selected = mode == 1, onClick = { mode = 1 }, label = { Text("QR·Central") })
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            FilterChip(selected = mode == 2, onClick = { mode = 2 }, label = { Text("NFC") })
                            FilterChip(selected = mode == 3, onClick = { mode = 3 }, label = { Text("NFC·Nego") })
                        }
                    }
                    qr?.let { Image(it.asImageBitmap(), contentDescription = "engagement QR", modifier = Modifier.size(260.dp)) }
                    Text(status, style = MaterialTheme.typography.bodyLarge)
                    Button(onClick = onClose) { Text("Close") }
                }
            }
        }
    }
}

/** Consent for an in-person reader's proximity request — what it asked for + a Share/Decline choice. */
@Composable
private fun ProximityConsent(req: ProximityRequest, onShare: () -> Unit, onDecline: () -> Unit) {
    InfoBox("Reader") {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(req.reader.commonName ?: "In-person reader", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            TrustBadge(req.reader.trusted)
        }
    }
    InfoBox("Will share") {
        req.documents.forEach { doc ->
            val missing = doc.candidate == null
            Text(doc.docType + if (missing) " — no matching credential" else "", style = MaterialTheme.typography.labelMedium)
            doc.requestedElements.forEach { (ns, elements) ->
                elements.forEach { Text("• $it", style = MaterialTheme.typography.bodyMedium) }
            }
        }
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TextButton(onClick = onDecline, modifier = Modifier.weight(1f)) { Text("Decline") }
        Button(onClick = onShare, enabled = req.satisfiable, modifier = Modifier.weight(1f)) { Text("Share") }
    }
}

// ---------- Reader: scan a wallet's QR and read its mdoc over BLE (this device is the verifier) ----------

@Composable
fun ProximityReaderScreen(wallet: Wallet) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf("Scan a wallet's QR or tap it over NFC to read its mdoc.") }
    var results by remember { mutableStateOf<List<VerifiedDocument>>(emptyList()) }
    var granted by remember { mutableStateOf(BLE_PERMISSIONS.all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }) }
    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r -> granted = r.values.all { it } }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val content = result.contents ?: run { status = "Scan cancelled"; return@rememberLauncherForActivityResult }
        val engagement = decodeEngagement(content) ?: run { status = "❌ Not an mdoc proximity QR"; return@rememberLauncherForActivityResult }
        val ble = DeviceEngagement.parseBle(engagement) ?: run { status = "❌ Engagement carries no BLE method"; return@rememberLauncherForActivityResult }
        results = emptyList()
        status = "Connecting over BLE…"
        scope.launch {
            try {
                // Match the holder's mode: peripheral server → we're the GATT client; central client → we're the GATT server.
                val peripheral = ble.peripheralServerUuid
                val central = ble.centralClientUuid
                val transport: ProximityTransport = when {
                    peripheral != null -> BleGattClientTransport(context, Ble.bytesToUuid(peripheral), Ble.PERIPHERAL_SERVER, logger = LogWalletLogger()).also { it.connect() }
                    // Central client mode: we're the GATT server → expose the Ident characteristic (§8.3.3.1.1.4).
                    central != null -> BleGattServerTransport(context, Ble.bytesToUuid(central), Ble.CENTRAL_CLIENT, identKey = DeviceEngagement.eDeviceKeyBytes(engagement), logger = LogWalletLogger()).also { it.start() }
                    else -> { status = "❌ Engagement carries no BLE UUID"; return@launch }
                }
                status = "Requesting documents…"
                val docs = wallet.reader.read(transport, engagement, readerRequest())
                results = docs
                status = if (docs.isEmpty()) "No documents returned" else "✅ Read ${docs.size} document(s)"
                LogStore.log("Reader read ${docs.size} document(s) over BLE")
            } catch (e: Throwable) {
                status = "❌ ${e.message}"
                LogStore.log("❌ Reader: ${e.message}")
            }
        }
    }

    Column(
        Modifier.fillMaxWidth().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Proximity Reader", style = MaterialTheme.typography.titleLarge)
        Text(
            "Acts as an ISO 18013-5 mdoc reader — scan a wallet's QR or tap it over NFC, then read its mdoc over BLE.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(onClick = {
            if (!granted) { permLauncher.launch(BLE_PERMISSIONS); return@Button }
            scanLauncher.launch(ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt("Scan the wallet's proximity QR")
                setBeepEnabled(false)
                setOrientationLocked(false)
                setCaptureActivity(PortraitCaptureActivity::class.java)
            })
        }) { Text("Scan wallet QR") }
        Button(onClick = {
            if (!granted) { permLauncher.launch(BLE_PERMISSIONS); return@Button }
            results = emptyList()
            status = "Hold near the wallet (NFC)…"
            scope.launch {
                try {
                    val handover = NfcReader.readHandover(context as Activity)
                    val eng = MdocNfcEngagement.parseHandoverSelect(handover.handoverSelect) ?: run { status = "❌ Not an mdoc NFC tag"; return@launch }
                    status = if (handover.negotiated) "Connecting over BLE (negotiated)…" else "Connecting over BLE…"
                    val uuids = if (eng.peripheralServerMode) Ble.PERIPHERAL_SERVER else Ble.CENTRAL_CLIENT
                    val transport = BleGattClientTransport(context, Ble.bytesToUuid(eng.serviceUuid), uuids, logger = LogWalletLogger()).also { it.connect() }
                    status = "Requesting documents…"
                    val docs = wallet.reader.read(transport, eng.deviceEngagement, readerRequest(), handoverNdef = handover.handoverSelect, handoverRequestNdef = handover.handoverRequest)
                    results = docs
                    status = if (docs.isEmpty()) "No documents returned" else "✅ Read ${docs.size} document(s)"
                    LogStore.log("Reader read ${docs.size} document(s) over NFC+BLE")
                } catch (e: Throwable) {
                    status = "❌ ${e.message}"
                    LogStore.log("❌ Reader (NFC): ${e.message}")
                }
            }
        }) { Text("Tap to read (NFC)") }
        Text(status, style = MaterialTheme.typography.bodyLarge)
        results.forEach { doc -> ReaderResultCard(doc) }
    }
}

@Composable
private fun ReaderResultCard(doc: VerifiedDocument) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(doc.docType, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                val (label, color) = if (doc.deviceAuthenticated) "verified" to MaterialTheme.colorScheme.primary else "unverified" to MaterialTheme.colorScheme.error
                AssistChip(onClick = {}, label = { Text(label) }, colors = AssistChipDefaults.assistChipColors(labelColor = color))
            }
            doc.elements.forEach { (_, els) ->
                els.forEach { (k, v) -> Text("$k: ${cborText(v)}", style = MaterialTheme.typography.bodyMedium) }
            }
        }
    }
}

// ---------- helpers ----------

private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

private fun decodeEngagement(content: String): ByteArray? {
    if (!content.startsWith("mdoc:")) return null
    return runCatching { Base64.decode(content.removePrefix("mdoc:").trim(), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP) }.getOrNull()
}

private fun encodeQr(content: String): Bitmap = BarcodeEncoder().encodeBitmap(content, BarcodeFormat.QR_CODE, 600, 600)

private fun cborText(c: Cbor): String = when (c) {
    is Cbor.Text -> c.value
    is Cbor.UInt -> c.value.toString()
    is Cbor.NInt -> "-${c.n + 1uL}"
    is Cbor.Bool -> c.value.toString()
    is Cbor.Bytes -> "0x…(${c.value.size}B)"
    is Cbor.Tagged -> cborText(c.value)
    is Cbor.Array -> c.items.joinToString(", ") { cborText(it) }
    else -> c.toString()
}
