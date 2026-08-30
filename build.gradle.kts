plugins {
    kotlin("jvm") version "1.9.24" apply false
    kotlin("plugin.serialization") version "1.9.24" apply false
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
// Keep this in sync with app/build.gradle.kts' versionName — it drove the
// :cli:distZip output filename to a stale "2.0.0-omega" for every release
// from 2.1.0 through 2.4.0 because nobody had to touch this line to bump
// the app version, so nobody did.
allprojects { group = "com.mrscanner.omega"; version = "2.4.0-unbound" }
tasks.register("clean", Delete::class) { delete(rootProject.layout.buildDirectory) }
