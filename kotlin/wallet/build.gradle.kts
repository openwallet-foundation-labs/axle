plugins {
    kotlin("jvm")
}

group = "com.hopae.eudi"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // Public API exposes wallet-api (ports + value types) + txlog (wallet.transactions returns its types) + own types.
    api(project(":wallet-api"))
    api(project(":txlog"))
    // Protocol engines are internal wiring — hidden from the public API.
    implementation(project(":credential-store"))
    implementation(project(":sdjwt"))
    // mdoc + proximity are part of the public surface: the reader API (RequestedDocument/VerifiedDocument),
    // the ISO transports (ProximityTransport authors call DeviceEngagement.bleRetrievalMethod), and HPKE.
    api(project(":mdoc"))
    implementation(project(":trust"))
    implementation(project(":statuslist"))
    implementation(project(":openid4vci"))
    implementation(project(":openid4vp"))
    api(project(":proximity"))

    testImplementation(kotlin("test"))
    testImplementation(project(":testkit"))
    testImplementation(testFixtures(project(":mdoc")))
    testImplementation(testFixtures(project(":openid4vci")))
    testImplementation(testFixtures(project(":openid4vp")))
    testImplementation(testFixtures(project(":trust")))
    testImplementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
}
