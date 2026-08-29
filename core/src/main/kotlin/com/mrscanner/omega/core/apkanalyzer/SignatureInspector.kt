package com.mrscanner.omega.core.apkanalyzer

import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Real signature inspection — this fixes a concrete false-positive found
 * while building this feature: the old analyzer only checked for
 * META-INF/*.RSA|DSA|EC files (the legacy v1/jar signing scheme) and
 * reported "no signature found" for any APK that ONLY uses APK Signature
 * Scheme v2/v3 — which is the DEFAULT for any APK built with a current
 * Android Gradle Plugin. Verified against this project's own release
 * build in dist/: it is v2-signed and has zero META-INF/*.RSA files, so
 * the old logic would have wrongly flagged Ali's own signed release APK
 * as unsigned.
 */
object SignatureInspector {

    data class CertInfo(
        val subject: String, val issuer: String, val selfSigned: Boolean,
        val notBefore: Date, val notAfter: Date, val expired: Boolean,
        val serialHex: String, val sigAlgorithm: String, val sha256: String
    )

    data class SignatureReport(
        val v1Certs: List<CertInfo>,
        val v2SchemeMarkerFound: Boolean,
        val v3SchemeMarkerFound: Boolean,
        val signingBlockMagicFound: Boolean
    ) {
        val isSigned: Boolean get() = v1Certs.isNotEmpty() || v2SchemeMarkerFound || v3SchemeMarkerFound || signingBlockMagicFound
    }

    /** [v1SigBlocks] = raw bytes of each META-INF/*.RSA|DSA|EC entry found while walking the zip. */
    fun inspect(apkFile: File, v1SigBlocks: List<ByteArray>): SignatureReport {
        val certs = v1SigBlocks.flatMap { parsePkcs7Certs(it) }
        val (v2, v3, magic) = scanSigningBlockMarkers(apkFile)
        return SignatureReport(certs, v2, v3, magic)
    }

    private fun parsePkcs7Certs(pkcs7: ByteArray): List<CertInfo> = try {
        val cf = CertificateFactory.getInstance("X.509")
        cf.generateCertificates(ByteArrayInputStream(pkcs7)).filterIsInstance<X509Certificate>().map { cert ->
            val subject = cert.subjectX500Principal.name
            val issuer = cert.issuerX500Principal.name
            val now = Date()
            CertInfo(
                subject = subject, issuer = issuer, selfSigned = subject == issuer,
                notBefore = cert.notBefore, notAfter = cert.notAfter, expired = now.after(cert.notAfter),
                serialHex = cert.serialNumber.toString(16),
                sigAlgorithm = cert.sigAlgName,
                sha256 = java.security.MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                    .joinToString("") { "%02x".format(it) }
            )
        }
    } catch (_: Exception) {
        emptyList()
    }

    /**
     * Scans the trailing region of the APK (before the ZIP central directory)
     * for APK Signing Block v2/v3 scheme-ID markers and the block's magic
     * string. A byte-pattern scan rather than exact chunk-offset arithmetic
     * on purpose: it is far more robust to the small structural variations
     * between signer tools, at the cost of not extracting the v2/v3
     * certificate bytes themselves (out of scope here — see class doc).
     */
    private fun scanSigningBlockMarkers(apkFile: File): Triple<Boolean, Boolean, Boolean> {
        return try {
            val len = apkFile.length()
            val windowSize = minOf(len, 4_000_000L).toInt()
            val bytes = ByteArray(windowSize)
            apkFile.inputStream().use { input ->
                if (len > windowSize) input.skip(len - windowSize)
                var read = 0
                while (read < windowSize) {
                    val n = input.read(bytes, read, windowSize - read)
                    if (n < 0) break
                    read += n
                }
            }
            val v2Marker = byteArrayOf(0x1a, 0x87.toByte(), 0x09, 0x71) // 0x7109871a LE
            val v3Marker = byteArrayOf(0xc0.toByte(), 0x68, 0x53, 0xf0.toByte()) // 0xf05368c0 LE
            val magic = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
            Triple(indexOf(bytes, v2Marker) >= 0, indexOf(bytes, v3Marker) >= 0, indexOf(bytes, magic) >= 0)
        } catch (_: Exception) {
            Triple(false, false, false)
        }
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    private val df = SimpleDateFormat("yyyy-MM-dd", Locale.US)
    fun fmtDate(d: Date): String = df.format(d)
}
