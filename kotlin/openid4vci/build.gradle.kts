plugins {
    kotlin("jvm")
    `java-test-fixtures`
}

group = "com.hopae.eudi"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    api(project(":wallet-api"))
    api(project(":sdjwt"))
    testFixturesImplementation(project(":testkit"))
    testImplementation(kotlin("test"))
    testImplementation(project(":testkit"))
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
