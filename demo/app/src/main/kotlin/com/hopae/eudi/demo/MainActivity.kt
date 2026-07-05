package com.hopae.eudi.demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import com.hopae.eudi.demo.ui.WalletApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val wallet = DemoWallet.get(this)
        setContent {
            MaterialTheme {
                Surface { WalletApp(wallet) }
            }
        }
    }
}
