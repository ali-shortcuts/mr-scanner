plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
}
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin { jvmToolchain(17) }

val jvmOnly by configurations.creating

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // Desktop/CLI only — MUST NOT flow into Android APK
    compileOnly("org.xerial:sqlite-jdbc:3.45.3.0")
    jvmOnly("org.xerial:sqlite-jdbc:3.45.3.0")

    testImplementation("org.xerial:sqlite-jdbc:3.45.3.0")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
tasks.test { useJUnitPlatform() }
tasks.jar {
    archiveBaseName.set("mr-scanner-core")
}
