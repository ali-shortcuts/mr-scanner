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
        // Malformed manifest/dex (not real AXML/DEX) must fall back gracefully, not crash.
        assertNull(r.dex)
    }

    /**
     * Real end-to-end check against this project's own built APK (checked
     * into dist/) - not synthetic bytes. This is what caught the false
     * "unsigned" positive during development: a v2/v3-signed APK has zero
     * META-INF *.RSA files, which the old analyzer treated as unsigned.
     */
    @Test
    fun analyzesRealProjectApk() {
        val candidates = listOf(File("dist"), File("../dist"), File("../../dist"))
        val distDir = candidates.firstOrNull { it.isDirectory }
        val apk = distDir?.listFiles { f -> f.name == "MrScannerOmega-2.3.0-final.apk" }?.firstOrNull()
            ?: distDir?.listFiles { f -> f.name.endsWith(".apk") }?.firstOrNull()
        org.junit.jupiter.api.Assumptions.assumeTrue(apk != null && apk.isFile, "no dist/*.apk checked in - skipping real-APK check")
        val r = ApkStaticAnalyzer.analyze(apk!!.absolutePath)

        val m = r.manifest
        assertNotNull(m, "expected a real, parseable binary AndroidManifest.xml")
        assertEquals("com.mrscanner.omega", m!!.packageName)
        assertTrue((m.minSdk ?: 0) >= 21)
        assertTrue(m.components.isNotEmpty())
        assertTrue(m.permissions.any { it.contains("INTERNET") })

        assertNotNull(r.dex, "expected real DEX header stats")
        assertTrue(r.dex!!.totalClasses > 0)
        assertTrue(r.dex!!.totalMethods > 0)

        assertNotNull(r.signature)
        // The project's real release build is v2/v3-signed with no legacy
        // META-INF/*.RSA files - this is exactly the case the old analyzer
        // got wrong. Confirm it's now correctly recognized as signed.
        assertTrue(r.signature!!.signed, "v2/v3-signed APK must not be reported as unsigned")
    }
}
