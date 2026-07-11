pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "eudi-wallet-demo"

// Consume the SDK + the Android platform adapters as composite builds so the demo always tracks local
// source (no publishing needed). ../android depends on ../kotlin; both are included here at the root.
includeBuild("../kotlin")
includeBuild("../android")

include(":app")
