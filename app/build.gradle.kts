plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.mrscanner.omega"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.mrscanner.omega"
        minSdk = 26
        targetSdk = 34
        versionCode = 240
        versionName = "2.4.0-unbound"
        buildConfigField("String", "ENGINE", "\"confidence-v3\"")
        buildConfigField("int", "PLUGIN_CATALOG_SIZE", "41")
        vectorDrawables.useSupportLibrary = true
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a")
        }
    }

    signingConfigs {
        create("release") {
            storeFile = rootProject.file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    // Architecture §12.2 — 32-bit + 64-bit + universal
    splits {
        abi {
            isEnable = true
            reset()
            include("armeabi-v7a", "arm64-v8a")
            isUniversalApk = true
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

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures {
        compose = false
        buildConfig = true
    }
    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            // sqlite-jdbc desktop natives must NEVER ship in the Android APK (crash on load)
            excludes += "**/org/sqlite/native/**"
            excludes += "META-INF/native-image/**"
            excludes += "sqlite-jdbc.properties"
        }
        jniLibs {
            excludes += "**/libsqlitejdbc.so"
        }
    }
}

dependencies {
    implementation(project(":core")) {
        exclude(group = "org.xerial", module = "sqlite-jdbc")
    }
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("androidx.work:work-runtime-ktx:2.9.0")
    implementation("androidx.documentfile:documentfile:1.0.1")
    // Optional Cronet - try resolve; if fails CI still builds without H3 native
    // implementation("org.chromium.net:cronet-embedded:119.6045.31")
    // implementation("com.google.net.cronet:cronet-okhttp:0.1.0")
}
