package com.mrscanner.omega.core.apkanalyzer

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkStaticAnalyzerTest {
    @TempDir lateinit var dir: File

    @Test
    fun analyzesSyntheticZipAsApk() {
        val apk = File(dir, "t.apk")
        ZipOutputStream(apk.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("AndroidManifest.xml"))
            z.write("android.permission.INTERNET debuggable com.example.app".toByteArray())
            z.closeEntry()
            z.putNextEntry(ZipEntry("lib/arm64-v8a/libx.so"))
            z.write(ByteArray(16))
            z.closeEntry()
            z.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
            z.write(ByteArray(8))
            z.closeEntry()
            z.putNextEntry(ZipEntry("classes.dex"))
            z.write("setJavaScriptEnabled Runtime.exec http://evil".toByteArray())
            z.closeEntry()
        }
        val r = ApkStaticAnalyzer.analyze(apk.absolutePath)
        assertTrue(r.abis.contains("arm64-v8a"))
        assertTrue(r.findings.isNotEmpty())
        assertTrue(ApkStaticAnalyzer.format(r).contains("APK:"))
    }
}
