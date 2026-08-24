package com.mrscanner.omega.core.apkanalyzer

import java.io.File
import java.util.zip.ZipFile

/**
 * Static APK analyzer - competitive capability for mobile scanners.
 * Works on any .apk without installing it.
 */
object ApkStaticAnalyzer {

    data class Finding(
        val severity: String,
        val id: String,
        val title: String,
        val detail: String
    )

    data class Report(
        val path: String,
        val sizeBytes: Long,
        val fileCount: Int,
        val abis: List<String>,
        val permissions: List<String>,
        val packagesHints: List<String>,
        val findings: List<Finding>,
        val stringsOfInterest: List<String>,
        val metaInf: List<String>
    )

    fun analyze(apkPath: String): Report {
        val file = File(apkPath)
        require(file.isFile) { "APK not found: $apkPath" }
        val permissions = linkedSetOf<String>()
        val abis = linkedSetOf<String>()
        val packages = linkedSetOf<String>()
        val findings = mutableListOf<Finding>()
        val interesting = linkedSetOf<String>()
        val metaInf = mutableListOf<String>()
        var files = 0
        var hasManifest = false
        var debuggable = false
        var cleartext = false
        var usesHttp = false
        var webviewJs = false
        var runtimeExec = false
        var customTrust = false

        ZipFile(file).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                files++
                val name = e.name
                when {
                    name == "AndroidManifest.xml" -> {
                        hasManifest = true
                        val bytes = zip.getInputStream(e).readBytes()
                        val strings = extractPrintableStrings(bytes, minLen = 5)
                        strings.forEach { s ->
                            if (s.startsWith("android.permission.") ||
                                (s.startsWith("com.") && s.contains("permission", true))
                            ) {
                                permissions += s
                            }
                            if (s.matches(Regex("""[a-zA-Z][\w]*(\.[a-zA-Z][\w]*)+"""))) {
                                if (s.contains('.') && !s.startsWith("android.") && s.length < 80) {
                                    packages += s
                                }
                            }
                            if (s.equals("debuggable", true)) debuggable = true
                            if (s.contains("usesCleartextTraffic", true) || s.contains("cleartext", true)) {
                                cleartext = true
                            }
                        }
                        interesting += strings.filter { it.length in 8..60 }.take(40)
                    }
                    name.startsWith("lib/") && name.endsWith(".so") -> {
                        val parts = name.split('/')
                        if (parts.size >= 2) abis += parts[1]
                    }
                    name.startsWith("META-INF/") -> metaInf += name
                    name.endsWith(".js") || name.endsWith(".html") -> {
                        val txt = runCatching {
                            zip.getInputStream(e).bufferedReader().readText()
                        }.getOrDefault("")
                        if (txt.contains("http://")) usesHttp = true
                    }
                    name.endsWith(".dex") || name.matches(Regex("""classes\d*\.dex""")) -> {
                        val bytes = zip.getInputStream(e).readBytes()
                        val strs = extractPrintableStrings(bytes, minLen = 6)
                        strs.forEach { s ->
                            when {
                                s.startsWith("android.permission.") -> permissions += s
                                s.contains("setJavaScriptEnabled") -> webviewJs = true
                                s.contains("Runtime.exec") || s.contains("ProcessBuilder") -> runtimeExec = true
                                s.contains("X509TrustManager") || s.contains("checkServerTrusted") -> customTrust = true
                                s.startsWith("http://") -> usesHttp = true
                                s.contains("BEGIN RSA PRIVATE KEY") ->
                                    findings += Finding(
                                        "CRITICAL",
                                        "embedded-private-key",
                                        "Embedded private key material",
                                        name
                                    )
                            }
                        }
                    }
                }
            }
        }

        if (!hasManifest) {
            findings += Finding("HIGH", "no-manifest", "AndroidManifest.xml missing", apkPath)
        }
        if (debuggable) {
            findings += Finding("HIGH", "debuggable", "Debuggable flag artifacts present", "manifest strings")
        }
        if (cleartext || usesHttp) {
            findings += Finding("MEDIUM", "cleartext-http", "Cleartext HTTP indicators", "manifest/dex/assets")
        }
        if (webviewJs) {
            findings += Finding("MEDIUM", "webview-js", "WebView JavaScript enablement referenced", "dex")
        }
        if (runtimeExec) {
            findings += Finding("HIGH", "runtime-exec", "Runtime.exec / ProcessBuilder referenced", "dex")
        }
        if (customTrust) {
            findings += Finding(
                "HIGH",
                "custom-trust-manager",
                "Custom TrustManager patterns (possible SSL unpin/bypass)",
                "dex"
            )
        }
        if (permissions.any { it.contains("READ_SMS") || it.contains("RECEIVE_SMS") }) {
            findings += Finding(
                "HIGH",
                "sms-permission",
                "SMS-related permission",
                permissions.filter { it.contains("SMS") }.joinToString()
            )
        }
        if (permissions.any { it.contains("RECORD_AUDIO") }) {
            findings += Finding("MEDIUM", "mic-permission", "RECORD_AUDIO permission", "")
        }
        if (permissions.any { it.contains("ACCESS_FINE_LOCATION") }) {
            findings += Finding("MEDIUM", "location-permission", "Fine location permission", "")
        }
        if (abis.isEmpty()) {
            findings += Finding("INFO", "no-native", "No native libraries", "")
        } else {
            findings += Finding("INFO", "native-abis", "Native ABIs present", abis.joinToString())
        }

        val hasSig = metaInf.any {
            it.endsWith(".RSA") || it.endsWith(".DSA") || it.endsWith(".EC") || it.endsWith(".MF")
        }
        if (!hasSig) {
            findings += Finding("HIGH", "unsigned-meta", "No META-INF signature blocks found", "")
        } else {
            findings += Finding(
                "INFO",
                "signed-meta",
                "Signature metadata present",
                metaInf.filter { it.endsWith(".RSA") || it.endsWith(".MF") }.joinToString()
            )
        }

        return Report(
            path = apkPath,
            sizeBytes = file.length(),
            fileCount = files,
            abis = abis.toList().sorted(),
            permissions = permissions.toList().sorted(),
            packagesHints = packages.toList().sorted().take(30),
            findings = findings.sortedBy { severityRank(it.severity) },
            stringsOfInterest = interesting.toList().take(50),
            metaInf = metaInf.take(30)
        )
    }

    private fun severityRank(s: String) = when (s) {
        "CRITICAL" -> 0
        "HIGH" -> 1
        "MEDIUM" -> 2
        "LOW" -> 3
        else -> 4
    }

    fun extractPrintableStrings(data: ByteArray, minLen: Int = 4): List<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        fun flush() {
            if (sb.length >= minLen) out += sb.toString()
            sb.setLength(0)
        }
        for (b in data) {
            val c = b.toInt() and 0xff
            if (c in 32..126) sb.append(c.toChar()) else flush()
        }
        flush()
        return out.distinct()
    }

    fun format(report: Report): String = buildString {
        appendLine("APK: ${report.path}")
        appendLine("size=${report.sizeBytes} files=${report.fileCount}")
        appendLine("abis=${report.abis}")
        appendLine("permissions(${report.permissions.size}):")
        report.permissions.take(40).forEach { appendLine("  - $it") }
        appendLine("findings(${report.findings.size}):")
        report.findings.forEach { f ->
            appendLine("  [${f.severity}] ${f.id}: ${f.title} - ${f.detail}")
        }
        if (report.packagesHints.isNotEmpty()) {
            appendLine("package-hints: ${report.packagesHints.take(15).joinToString()}")
        }
    }
}
