plugins {
    id("com.android.library")
}

group = "com.hopae.eudi"
version = "0.0.1-SNAPSHOT"

android {
    namespace = "com.hopae.eudi.wallet.android"
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
    // SDK ports these adapters implement (wallet-api transitively exposes cbor for the keystore adapter).
    api("com.hopae.eudi:wallet-api:0.0.1-SNAPSHOT")
    api("com.hopae.eudi:txlog:0.0.1-SNAPSHOT")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
