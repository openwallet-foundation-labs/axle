plugins {
    kotlin("jvm")
}

group = "com.hopae.eudi"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    api(project(":wallet-api"))
    testImplementation(kotlin("test"))
    testImplementation(project(":testkit"))
    testImplementation(project(":mdoc"))
    testImplementation(testFixtures(project(":mdoc")))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
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
