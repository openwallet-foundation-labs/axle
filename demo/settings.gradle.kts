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

// Consume the SDK as a composite build so the demo always tracks local source (no publishing needed).
includeBuild("../kotlin")

include(":app")
