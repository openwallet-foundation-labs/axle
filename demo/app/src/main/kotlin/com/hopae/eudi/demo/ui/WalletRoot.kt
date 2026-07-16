package com.hopae.eudi.demo.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.hopae.eudi.demo.IncomingLink
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.demo.PendingAuth
import com.hopae.eudi.demo.PortraitCaptureActivity
import com.hopae.eudi.demo.security.AppLock
import com.hopae.eudi.demo.ui.screens.ActivityScreen
import com.hopae.eudi.demo.ui.screens.DebugScreen
import com.hopae.eudi.demo.ui.screens.DocumentDetailScreen
import com.hopae.eudi.demo.ui.screens.DocumentsScreen
import com.hopae.eudi.demo.ui.screens.HomeScreen
import com.hopae.eudi.demo.ui.screens.IssueScreen
import com.hopae.eudi.demo.ui.screens.PresentScreen
import com.hopae.eudi.demo.ui.screens.SettingsScreen
import com.hopae.eudi.demo.ui.screens.TransactionDetailScreen
import com.hopae.eudi.demo.ui.theme.WalletTheme
import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.CredentialOffer
import com.hopae.eudi.wallet.IssuanceSession
import com.hopae.eudi.wallet.PresentationState
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.txlog.TransactionLogEntry
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

private object Routes {
    const val Home = "home"
    const val Documents = "documents"
    const val Activity = "activity"
    const val Settings = "settings"
    const val Debug = "debug"
    const val Reader = "reader"
}

private val MainTabs = setOf(Routes.Home, Routes.Documents, Routes.Activity, Routes.Settings)

@Composable
fun WalletRoot(wallet: Wallet) {
    val nav = rememberNavController()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current

    var refreshKey by remember { mutableStateOf(0) }
    var issuing by remember { mutableStateOf<CredentialOffer?>(null) }
    var consent by remember { mutableStateOf<PendingConsent?>(null) }
    var detail by remember { mutableStateOf<Credential?>(null) }
    var txDetail by remember { mutableStateOf<TransactionLogEntry?>(null) }
    var showProximity by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf<String?>(null) }

    // Standard bottom-nav switch: single instance per tab, saving/restoring each tab's state. Both the bottom
    // bar and the "See all" links go through this so the back stack stays consistent (tapping Home after a
    // "See all" must return Home).
    val navigateTab: (String) -> Unit = { dest ->
        if (dest != nav.currentDestination?.route) {
            nav.navigate(dest) {
                popUpTo(nav.graph.findStartDestination().id) { saveState = true }
                launchSingleTop = true
                restoreState = true
            }
        }
    }

    val openAuth: (String, IssuanceSession) -> Unit = { url, session ->
        PendingAuth.session = session
        LogStore.log("Opening browser for authorization…")
        AppLock.suppressResumeLock() // returning from the browser shouldn't demand a re-unlock
        runCatching {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }.onFailure { LogStore.log("❌ open browser: ${it.message}") }
    }

    // Unified inbound scan router (holder side): route by the scanned/opened URI's scheme.
    fun handleUri(uri: String, source: String) {
        val scheme = uri.substringBefore("://", "").lowercase()
        LogStore.log("$source [$scheme]: ${uri.take(140)}${if (uri.length > 140) "…" else ""}")
        when (scheme) {
            in OFFER_SCHEMES -> scope.launch {
                busy = "Resolving offer…"
                runCatching { issuing = wallet.issuance.resolveOffer(uri) }
                    .onFailure { LogStore.log("❌ resolveOffer: ${it.message}") }
                busy = null
            }
            in VP_SCHEMES -> scope.launch {
                busy = "Resolving request…"
                runCatching {
                    val session = wallet.presentation.start(uri)
                    when (val r = session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed }) {
                        is PresentationState.RequestResolved -> consent = PendingConsent(session, r.request)
                        is PresentationState.Failed -> LogStore.log("❌ ${r.error.message}")
                        else -> {}
                    }
                }.onFailure { LogStore.log("❌ presentation: ${it.message}") }
                busy = null
            }
            else -> LogStore.log("⚠️ Unrecognized scheme '$scheme' (expected an offer or presentation link)")
        }
    }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val uri = result.contents
        if (uri == null) LogStore.log("Scan cancelled") else handleUri(uri, "Scanned")
    }
    fun launchScan() {
        AppLock.suppressResumeLock() // returning from the scanner shouldn't demand a re-unlock
        scanLauncher.launch(
        ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("Scan an issuer offer or a verifier request")
            setBeepEnabled(false)
            setOrientationLocked(false)
            setCaptureActivity(PortraitCaptureActivity::class.java)
        },
        )
    }

    val incoming by IncomingLink.flow.collectAsState()
    LaunchedEffect(incoming) {
        val uri = incoming ?: return@LaunchedEffect
        IncomingLink.consume()
        handleUri(uri, "Opened link")
    }

    val backStack by nav.currentBackStackEntryAsState()
    val route = backStack?.destination?.route

    Scaffold(
        bottomBar = { if (route in MainTabs) WalletBottomBar(navigateTab, route) },
    ) { padding ->
        NavHost(nav, startDestination = Routes.Home, modifier = Modifier.padding(padding).fillMaxSize()) {
            composable(Routes.Home) {
                HomeScreen(
                    wallet = wallet, refreshKey = refreshKey,
                    onScan = { launchScan() },
                    onReadMdl = { nav.navigate(Routes.Reader) },
                    onProximity = { showProximity = true },
                    onOpenDoc = { detail = it },
                    onSeeDocuments = { navigateTab(Routes.Documents) },
                    onSeeActivity = { navigateTab(Routes.Activity) },
                    onOpenActivity = { txDetail = it },
                )
            }
            composable(Routes.Documents) { DocumentsScreen(wallet, refreshKey, onScan = { launchScan() }, onOpenDoc = { detail = it }) }
            composable(Routes.Activity) { ActivityScreen(wallet, refreshKey, onOpenActivity = { txDetail = it }) }
            composable(Routes.Settings) { SettingsScreen(onOpenDebug = { nav.navigate(Routes.Debug) }) }
            composable(Routes.Debug) { DebugScreen(onBack = { nav.popBackStack() }) }
            composable(Routes.Reader) { ReaderRoute(wallet, onBack = { nav.popBackStack() }) }
        }
    }

    // ── overlays ──
    issuing?.let { offer ->
        IssueScreen(
            offer = offer, wallet = wallet, onAuth = openAuth,
            onDone = { issuing = null; refreshKey++ },
            onCancel = { issuing = null; LogStore.log("Issuance cancelled") },
        )
    }
    consent?.let { p ->
        PresentScreen(
            request = p.request,
            session = p.session,
            wallet = wallet,
            onDone = { consent = null; refreshKey++ },
            onCancel = { consent = null; refreshKey++ },
        )
    }
    detail?.let { cred ->
        BackHandler { detail = null }
        DocumentDetailScreen(
            cred = cred,
            onBack = { detail = null },
            onPresentProximity = if (credIsMdoc(cred)) ({ detail = null; showProximity = true }) else null,
            onDelete = {
                detail = null
                scope.launch {
                    runCatching { wallet.credentials.delete(cred.id) }
                        .onSuccess { LogStore.log("Deleted credential ${cred.id.value}") }
                        .onFailure { LogStore.log("❌ delete: ${it.message}") }
                    refreshKey++
                }
            },
        )
    }
    txDetail?.let { entry ->
        BackHandler { txDetail = null }
        TransactionDetailScreen(entry, onBack = { txDetail = null })
    }
    if (showProximity) ProximityHolderDialog(wallet) { showProximity = false }

    busy?.let { message -> BusyOverlay(message) }
}

@Composable
private fun WalletBottomBar(onTab: (String) -> Unit, route: String?) {
    NavigationBar(containerColor = WalletTheme.colors.card) {
        BottomItem(onTab, route, Routes.Home, Icons.Filled.Home, "Home")
        BottomItem(onTab, route, Routes.Documents, Icons.Filled.CreditCard, "Documents")
        BottomItem(onTab, route, Routes.Activity, Icons.Filled.History, "Activity")
        BottomItem(onTab, route, Routes.Settings, Icons.Filled.Settings, "Settings")
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.BottomItem(
    onTab: (String) -> Unit,
    current: String?,
    route: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
) {
    val c = WalletTheme.colors
    NavigationBarItem(
        selected = current == route,
        onClick = { onTab(route) },
        icon = { Icon(icon, null) },
        label = { Text(label) },
        colors = NavigationBarItemDefaults.colors(
            selectedIconColor = c.brand, selectedTextColor = c.brand,
            unselectedIconColor = c.inkFaint, unselectedTextColor = c.inkFaint,
            indicatorColor = c.brandSoftBg,
        ),
    )
}

/** Read-mDL (verifier mode) wrapped with a back top-bar. Its own camera (separate from the holder scanner). */
@Composable
private fun ReaderRoute(wallet: Wallet, onBack: () -> Unit) {
    val c = WalletTheme.colors
    Column(Modifier.fillMaxSize().background(c.screen)) {
        Row(Modifier.fillMaxWidth().padding(12.dp, 16.dp, 12.dp, 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(36.dp).clip(RoundedCornerShape(99.dp)).background(c.card).clickable { onBack() },
                contentAlignment = Alignment.Center,
            ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = c.ink, modifier = Modifier.size(18.dp)) }
            Spacer(Modifier.width(10.dp))
            Text("Reader", style = MaterialTheme.typography.titleMedium, color = c.ink)
        }
        ProximityReaderScreen(wallet)
    }
}

@Composable
private fun BusyOverlay(message: String) {
    Box(
        Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.35f))
            .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) {},
        contentAlignment = Alignment.Center,
    ) {
        Surface(shape = MaterialTheme.shapes.medium, tonalElevation = 6.dp) {
            Row(Modifier.padding(24.dp), verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(28.dp), strokeWidth = 3.dp)
                Spacer(Modifier.width(16.dp))
                Text(message, style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
}
