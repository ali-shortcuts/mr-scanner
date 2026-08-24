plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "com.mrscanner.omega"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.mrscanner.omega"
        minSdk = 26; targetSdk = 34
        versionCode = 200; versionName = "2.0.0-omega"
        buildConfigField("String", "ENGINE", "\"confidence-v3\"")
        buildConfigField("int", "PLUGIN_CATALOG_SIZE", "41")
    }
    signingConfigs {
        create("release") {
            storeFile = rootProject.file("debug.keystore")
            storePassword = "android"; keyAlias = "androiddebugkey"; keyPassword = "android"
        }
    }
    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = false
        }
        debug {
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = false; buildConfig = true }
    lint { abortOnError = false; checkReleaseBuilds = false }
}
dependencies {
    implementation(project(":core"))
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
