plugins {
    kotlin("jvm") version "1.9.24" apply false
    kotlin("plugin.serialization") version "1.9.24" apply false
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
allprojects { group = "com.mrscanner.omega"; version = "2.0.0-omega" }
tasks.register("clean", Delete::class) { delete(rootProject.layout.buildDirectory) }
