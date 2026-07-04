plugins {
    kotlin("jvm")
}

group = "com.hopae.eudi"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    api(project(":openid4vp"))
    api(project(":sdjwt"))
    testImplementation(kotlin("test"))
    // test-only: generate certificate hierarchies with SAN for deterministic chain-validation tests
    testImplementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
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
