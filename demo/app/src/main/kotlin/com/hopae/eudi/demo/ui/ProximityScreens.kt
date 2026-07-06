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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
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
import com.hopae.eudi.demo.ble.BleHolderTransport
import com.hopae.eudi.demo.ble.BleReaderTransport
import com.hopae.eudi.wallet.ProximitySelection
import com.hopae.eudi.wallet.ProximityState
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.RequestedDocument
import com.hopae.eudi.wallet.mdoc.VerifiedDocument
import com.hopae.eudi.wallet.proximity.DeviceEngagement
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
    var granted by remember { mutableStateOf(BLE_PERMISSIONS.all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }) }
    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r -> granted = r.values.all { it } }

    DisposableEffect(granted) {
        if (!granted) {
            status = "Grant Bluetooth permission to present"
            permLauncher.launch(BLE_PERMISSIONS)
            return@DisposableEffect onDispose {}
        }
        val transport = BleHolderTransport(context)
        val scope = CoroutineScope(Dispatchers.Main)
        scope.launch {
            try {
                transport.start()
                val session = wallet.proximity.present(transport)
                session.state.collect { st ->
                    when (st) {
                        is ProximityState.EngagementReady -> {
                            qr = encodeQr("mdoc:" + b64(st.deviceEngagement))
                            status = "Waiting for a reader — show this QR"
                        }
                        is ProximityState.RequestReceived -> {
                            status = "Reader connected — responding…"
                            LogStore.log("Proximity: reader requested ${st.request.documents.size} doc(s); auto-responding")
                            session.respond(ProximitySelection.auto(st.request))
                        }
                        ProximityState.Submitting -> status = "Sending response…"
                        ProximityState.Completed -> status = "✅ Presented to the reader"
                        ProximityState.Declined -> status = "Declined"
                        is ProximityState.Failed -> status = "❌ ${st.error.message}"
                        else -> {}
                    }
                }
            } catch (e: Throwable) {
                status = "❌ ${e.message}"
                LogStore.log("❌ Proximity holder: ${e.message}")
            }
        }
        onDispose { scope.cancel(); transport.stop() }
    }

    Dialog(onDismissRequest = onClose) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Present via BLE (mdoc)", style = MaterialTheme.typography.titleLarge)
                qr?.let { Image(it.asImageBitmap(), contentDescription = "engagement QR", modifier = Modifier.size(260.dp)) }
                Text(status, style = MaterialTheme.typography.bodyLarge)
                Button(onClick = onClose) { Text("Close") }
            }
        }
    }
}

// ---------- Reader: scan a wallet's QR and read its mdoc over BLE (this device is the verifier) ----------

@Composable
fun ProximityReaderScreen(wallet: Wallet) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf("Tap Scan to read a nearby wallet over BLE.") }
    var results by remember { mutableStateOf<List<VerifiedDocument>>(emptyList()) }
    var granted by remember { mutableStateOf(BLE_PERMISSIONS.all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }) }
    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r -> granted = r.values.all { it } }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val content = result.contents ?: run { status = "Scan cancelled"; return@rememberLauncherForActivityResult }
        val engagement = decodeEngagement(content) ?: run { status = "❌ Not an mdoc proximity QR"; return@rememberLauncherForActivityResult }
        val uuid = DeviceEngagement.parseBleUuid(engagement) ?: run { status = "❌ Engagement carries no BLE method"; return@rememberLauncherForActivityResult }
        results = emptyList()
        status = "Connecting over BLE…"
        scope.launch {
            try {
                val transport = BleReaderTransport(context, BleHolderTransport.bytesToUuid(uuid))
                transport.connect()
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
            "Acts as an ISO 18013-5 mdoc reader: scan another wallet's proximity QR and read its mdoc over BLE.",
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
