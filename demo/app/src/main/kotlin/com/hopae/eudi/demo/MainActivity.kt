package com.hopae.eudi.demo

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.lifecycle.lifecycleScope
import com.hopae.eudi.demo.adapters.LogWalletLogger
import com.hopae.eudi.demo.ui.WalletApp
import com.hopae.eudi.wallet.android.dcapi.DcApiBranding
import com.hopae.eudi.wallet.android.dcapi.DcApiRegistrar
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val wallet = DemoWallet.get(this)
        handleIntentLink(intent)
        // Register credentials with the Credential Manager (Digital Credentials API) + keep in sync. Brand the
        // OS selector entries with this wallet's own launcher icon (the library scales it for the selector).
        val branding = DcApiBranding(logoPng = appIconPng())
        val logger = LogWalletLogger()
        lifecycleScope.launch {
            DcApiRegistrar.register(this@MainActivity, wallet, branding, logger = logger)
            wallet.credentials.changes.collect { DcApiRegistrar.register(this@MainActivity, wallet, branding, logger = logger) }
        }
        setContent {
            MaterialTheme {
                Surface { WalletApp(wallet) }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntentLink(intent)
    }

    /**
     * Routes an incoming deep link: the authorization-code redirect resumes the parked issuance session;
     * an offer / presentation link (haip-vci, haip-vp, openid-credential-offer, …) is handed to the UI.
     */
    private fun handleIntentLink(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme == "eu.europa.ec.euidi") PendingAuth.complete(data.toString())
        else IncomingLink.post(data.toString())
    }

    /** This wallet's own launcher icon as PNG bytes — used as the DC API selector branding for its credentials. */
    private fun appIconPng(): ByteArray? = runCatching {
        val d = packageManager.getApplicationIcon(packageName)
        val bmp = Bitmap.createBitmap(d.intrinsicWidth.coerceAtLeast(1), d.intrinsicHeight.coerceAtLeast(1), Bitmap.Config.ARGB_8888)
        Canvas(bmp).also { d.setBounds(0, 0, it.width, it.height); d.draw(it) }
        ByteArrayOutputStream().also { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
    }.getOrNull()
}
