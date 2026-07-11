plugins {
    id("com.android.library")
}

group = "com.hopae.eudi.android"
version = "0.0.1-SNAPSHOT"

android {
    namespace = "com.hopae.eudi.wallet.android.dcapi"
    compileSdk = 36

    defaultConfig {
        minSdk = 29
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // The wallet facade (Credential/Wallet types + presentation.startDcApi / proximity.respondDcApiMdoc)
    // and the Credential Manager / GMS Identity Credentials APIs this integration is built on.
    api("com.hopae.eudi:wallet:0.0.1-SNAPSHOT")
    api("androidx.credentials:credentials:1.6.0-rc01")
    api("com.google.android.gms:play-services-identity-credentials:16.0.0-alpha08")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
