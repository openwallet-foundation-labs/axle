package com.hopae.eudi.demo.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.wallet.spi.ProximityTransport
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.util.UUID
import kotlin.math.min

/**
 * ISO/IEC 18013-5 §8.3.3.1.1 BLE **mdoc peripheral server mode** transport — the reader is the GATT
 * central. Scans for the holder's advertised [serviceUuid], connects, subscribes, and exchanges framed
 * messages. Implements [ProximityTransport] so `wallet.reader.read(transport, ...)` drives the exchange.
 */
@SuppressLint("MissingPermission")
class BleReaderTransport(private val context: Context, private val serviceUuid: UUID) : ProximityTransport {
    private val manager = context.getSystemService(BluetoothManager::class.java)
    private var gatt: BluetoothGatt? = null
    private var stateChar: BluetoothGattCharacteristic? = null
    private var c2sChar: BluetoothGattCharacteristic? = null
    private var s2cChar: BluetoothGattCharacteristic? = null
    private var mtu = 23

    private val incoming = Channel<ByteArray>(Channel.UNLIMITED)
    private val assembling = ByteArrayOutputStream()
    private val connectedSignal = CompletableDeferred<Boolean>()
    private var pending: CompletableDeferred<Boolean>? = null

    /** Scans, connects, subscribes to notifications, negotiates MTU, and signals start. Call before [read]. */
    suspend fun connect() {
        val device = scan()
        gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
        withTimeout(15_000) { connectedSignal.await() }
        awaitOp { gatt!!.requestMtu(517) }
        awaitOp { gatt!!.discoverServices() }
        val service = gatt!!.getService(serviceUuid) ?: error("holder service $serviceUuid not found")
        stateChar = service.getCharacteristic(BleHolderTransport.STATE)
        c2sChar = service.getCharacteristic(BleHolderTransport.CLIENT2SERVER)
        s2cChar = service.getCharacteristic(BleHolderTransport.SERVER2CLIENT)
        enableNotify(stateChar!!)
        enableNotify(s2cChar!!)
        writeChar(stateChar!!, byteArrayOf(0x01), BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE) // STATE_START
        LogStore.log("BLE reader connected + subscribed (mtu=$mtu)")
    }

    private suspend fun scan(): BluetoothDevice {
        val found = CompletableDeferred<BluetoothDevice>()
        val scanner = manager.adapter.bluetoothLeScanner ?: error("BLE scanner unavailable (Bluetooth off?)")
        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                if (!found.isCompleted) found.complete(result.device)
            }
            override fun onScanFailed(errorCode: Int) { if (!found.isCompleted) found.completeExceptionally(IllegalStateException("scan failed $errorCode")) }
        }
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(serviceUuid)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        scanner.startScan(listOf(filter), settings, cb)
        LogStore.log("BLE reader scanning for $serviceUuid")
        return try {
            withTimeout(20_000) { found.await() }
        } finally {
            runCatching { scanner.stopScan(cb) }
        }
    }

    override suspend fun send(message: ByteArray) {
        val maxChunk = min(512, mtu - 3) - 1
        var offset = 0
        while (offset < message.size) {
            val size = min(maxChunk, message.size - offset)
            val last = offset + size >= message.size
            val chunk = ByteArray(size + 1)
            chunk[0] = if (last) 0x00 else 0x01
            message.copyInto(chunk, 1, offset, offset + size)
            writeChar(c2sChar!!, chunk, BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE)
            offset += size
        }
        LogStore.log("BLE reader sent ${message.size}B request")
    }

    override suspend fun receive(): ByteArray = incoming.receive()

    override suspend fun close() = stop()

    /** Synchronous teardown, safe to call from a Compose `onDispose`. */
    fun stop() {
        runCatching { gatt?.disconnect() }
        runCatching { gatt?.close() }
        gatt = null
        runCatching { incoming.close() }
    }

    // ---- serial GATT operation plumbing (one op in flight at a time) ----

    private suspend fun awaitOp(start: () -> Boolean) {
        val d = CompletableDeferred<Boolean>()
        pending = d
        check(start()) { "BLE operation failed to start" }
        withTimeout(10_000) { d.await() }
    }

    private suspend fun enableNotify(c: BluetoothGattCharacteristic) {
        gatt!!.setCharacteristicNotification(c, true)
        val cccd = c.getDescriptor(BleHolderTransport.CCCD)
        val enable = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        awaitOp {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                gatt!!.writeDescriptor(cccd, enable) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION") run { cccd.value = enable; gatt!!.writeDescriptor(cccd) }
            }
        }
    }

    private suspend fun writeChar(c: BluetoothGattCharacteristic, value: ByteArray, writeType: Int) {
        awaitOp {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                gatt!!.writeCharacteristic(c, value, writeType) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION") run { c.writeType = writeType; c.value = value; gatt!!.writeCharacteristic(c) }
            }
        }
    }

    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (!connectedSignal.isCompleted) connectedSignal.complete(true)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                if (!connectedSignal.isCompleted) connectedSignal.completeExceptionally(IllegalStateException("disconnected (status $status)"))
            }
        }

        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
            this@BleReaderTransport.mtu = mtu
            pending?.complete(status == BluetoothGatt.GATT_SUCCESS)
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) { pending?.complete(status == BluetoothGatt.GATT_SUCCESS) }
        override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) { pending?.complete(status == BluetoothGatt.GATT_SUCCESS) }
        override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) { pending?.complete(status == BluetoothGatt.GATT_SUCCESS) }

        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray) {
            when (c.uuid) {
                BleHolderTransport.SERVER2CLIENT -> {
                    if (value.isEmpty()) return
                    assembling.write(value, 1, value.size - 1)
                    if (value[0].toInt() == 0x00) { // last chunk
                        incoming.trySend(assembling.toByteArray())
                        assembling.reset()
                    }
                }
                BleHolderTransport.STATE -> if (value.size == 1 && value[0].toInt() == 0x02) { // STATE_END
                    LogStore.log("BLE reader: holder ended session")
                }
            }
        }

        // Pre-Tiramisu delivers the value via the characteristic itself.
        @Deprecated("Deprecated in Java")
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
            @Suppress("DEPRECATION") onCharacteristicChanged(g, c, c.value ?: ByteArray(0))
        }
    }
}
