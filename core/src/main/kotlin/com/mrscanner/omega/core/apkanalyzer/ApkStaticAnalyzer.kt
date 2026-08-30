package com.mrscanner.omega.core.apkanalyzer

import java.io.File
import java.util.zip.ZipFile

/**
 * Static APK analyzer.
 *
 * v2 of this analyzer (this file): the v1 version only ever read the APK
 * as a bag of printable-ASCII strings and pattern-matched over them —
 * for AndroidManifest.xml that's guessing, because the manifest is a
 * compiled binary chunk format, not text (see [AxmlParser]'s doc comment
 * for specifics; validated against this project's own built APKs).
 * This version parses the manifest, DEX header, and APK signature for
 * real, and falls back to the old string-heuristic layer only where the
 * structured parse doesn't apply (corrupt/legacy files) or where a
 * heuristic is genuinely the only signal available (asset/dex string
 * scanning for hardcoded secrets, http:// literals, etc - there is no
 * structured alternative to that, so it stays as-is).
 */
object ApkStaticAnalyzer {

    data class Finding(val severity: String, val id: String, val title: String, val detail: String)

    data class ComponentSummary(val kind: String, val name: String, val exported: Boolean, val exportedExplicit: Boolean, val permission: String?, val hasIntentFilter: Boolean)

    data class ManifestSummary(
        val packageName: String?, val versionCode: Int?, val versionName: String?,
        val minSdk: Int?, val targetSdk: Int?, val compileSdk: Int?,
        val debuggable: Boolean?, val allowBackup: Boolean?, val usesCleartextTraffic: Boolean?,
        val networkSecurityConfig: Boolean, val permissions: List<String>, val components: List<ComponentSummary>
    )

    data class DexSummary(val dexFileCount: Int, val totalClasses: Int, val totalMethods: Int, val totalStrings: Int)

    data class SignatureSummary(
        val signed: Boolean, val v1CertSubjects: List<String>, val v1SelfSigned: List<Boolean>,
        val v1Expired: List<Boolean>, val v1Sha256: List<String>, val v2Present: Boolean, val v3Present: Boolean
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
        val metaInf: List<String>,
        val certFingerprints: List<String> = emptyList(),
        val exportedHints: List<String> = emptyList(),
        val manifest: ManifestSummary? = null,
        val dex: DexSummary? = null,
        val signature: SignatureSummary? = null
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
        val certFps = mutableListOf<String>()
        val exportedHints = linkedSetOf<String>()
        val v1SigBlocks = mutableListOf<ByteArray>()
        var files = 0
        var hasManifest = false
        var manifestSummary: ManifestSummary? = null
        var debuggableHeuristic = false
        var cleartext = false
        var usesHttp = false
        var webviewJs = false
        var runtimeExec = false
        var customTrust = false
        var dexFileCount = 0
        var dexClasses = 0; var dexMethods = 0; var dexStrings = 0

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
                        val root = AxmlParser.parse(bytes)
                        if (root != null) {
                            manifestSummary = buildManifestSummary(root)
                        } else {
                            // Not a valid binary manifest (corrupt/synthetic file) - fall back to
                            // the old raw-string heuristic so we still surface *something*.
                            val strings = extractPrintableStrings(bytes, minLen = 5)
                            strings.forEach { s ->
                                if (s.startsWith("android.permission.") || (s.startsWith("com.") && s.contains("permission", true))) permissions += s
                                if (s.equals("debuggable", true)) debuggableHeuristic = true
                                if (s.endsWith("Activity") || s.endsWith("Service") || s.endsWith("Receiver") || s.endsWith("Provider")) {
                                    if (s.contains('.')) exportedHints += s
                                }
                                if (s.contains("usesCleartextTraffic", true) || s.contains("cleartext", true)) cleartext = true
                            }
                            interesting += strings.filter { it.length in 8..60 }.take(40)
                        }
                    }
                    name.startsWith("lib/") && name.endsWith(".so") -> {
                        val parts = name.split('/')
                        if (parts.size >= 2) abis += parts[1]
                    }
                    name.startsWith("META-INF/") -> {
                        metaInf += name
                        if (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC")) {
                            val bytes = zip.getInputStream(e).readBytes()
                            v1SigBlocks += bytes
                            val sha = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
                                .joinToString("") { "%02x".format(it) }
                            certFps += "${name.substringAfterLast('/')}:sha256:$sha"
                        } else if (name.endsWith(".SF")) {
                            val bytes = zip.getInputStream(e).readBytes()
                            val sha = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
                                .joinToString("") { "%02x".format(it) }
                            certFps += "${name.substringAfterLast('/')}:sha256:$sha"
                        }
                    }
                    name.endsWith(".js") || name.endsWith(".html") -> {
                        val txt = runCatching { zip.getInputStream(e).bufferedReader().readText() }.getOrDefault("")
                        if (txt.contains("http://")) usesHttp = true
                    }
                    name.endsWith(".dex") || name.matches(Regex("""classes\d*\.dex""")) -> {
                        val bytes = zip.getInputStream(e).readBytes()
                        DexHeaderReader.read(bytes)?.let { st ->
                            dexFileCount++; dexClasses += st.classDefsCount; dexMethods += st.methodIdsCount; dexStrings += st.stringIdsCount
                        }
                        val strs = extractPrintableStrings(bytes, minLen = 6)
                        strs.forEach { s ->
                            when {
                                s.startsWith("android.permission.") -> permissions += s
                                s.contains("setJavaScriptEnabled") -> webviewJs = true
                                s.contains("Runtime.exec") || s.contains("ProcessBuilder") -> runtimeExec = true
                                s.contains("X509TrustManager") || s.contains("checkServerTrusted") -> customTrust = true
                                s.startsWith("http://") -> usesHttp = true
                                s.contains("BEGIN RSA PRIVATE KEY") ->
                                    findings += Finding("CRITICAL", "embedded-private-key", "Embedded private key material", name)
                            }
                        }
                    }
                }
            }
        }

        val sig = SignatureInspector.inspect(file, v1SigBlocks)
        val sigSummary = SignatureSummary(
            signed = sig.isSigned,
            v1CertSubjects = sig.v1Certs.map { it.subject },
            v1SelfSigned = sig.v1Certs.map { it.selfSigned },
            v1Expired = sig.v1Certs.map { it.expired },
            v1Sha256 = sig.v1Certs.map { it.sha256 },
            v2Present = sig.v2SchemeMarkerFound,
            v3Present = sig.v3SchemeMarkerFound
        )

        val m = manifestSummary
        val debuggable = m?.debuggable ?: debuggableHeuristic
        val cleartextFinal = m?.usesCleartextTraffic ?: cleartext
        if (m != null) permissions += m.permissions
        if (m != null) exportedHints += m.components.filter { it.exported }.map { "${it.kind}:${it.name}" }

        if (!hasManifest) findings += Finding("HIGH", "no-manifest", "AndroidManifest.xml missing", apkPath)
        if (debuggable) findings += Finding("HIGH", "debuggable", "android:debuggable is true - app is debuggable in production builds", if (m != null) "manifest <application> attribute" else "manifest strings (heuristic - could not parse binary manifest)")
        if (cleartextFinal || usesHttp) findings += Finding("MEDIUM", "cleartext-http", "Cleartext HTTP indicators", if (m?.usesCleartextTraffic != null) "manifest usesCleartextTraffic=true" else "string/manifest heuristic")
        if (webviewJs) findings += Finding("MEDIUM", "webview-js", "WebView JavaScript enablement referenced", "dex")
        if (runtimeExec) findings += Finding("HIGH", "runtime-exec", "Runtime.exec / ProcessBuilder referenced", "dex")
        if (customTrust) findings += Finding("HIGH", "custom-trust-manager", "Custom TrustManager patterns (possible SSL unpin/bypass)", "dex")
        if (permissions.any { it.contains("READ_SMS") || it.contains("RECEIVE_SMS") })
            findings += Finding("HIGH", "sms-permission", "SMS-related permission", permissions.filter { it.contains("SMS") }.joinToString())
        if (permissions.any { it.contains("RECORD_AUDIO") }) findings += Finding("MEDIUM", "mic-permission", "RECORD_AUDIO permission", "")
        if (permissions.any { it.contains("ACCESS_FINE_LOCATION") }) findings += Finding("MEDIUM", "location-permission", "Fine location permission", "")
        if (abis.isEmpty()) findings += Finding("INFO", "no-native", "No native libraries", "")
        else findings += Finding("INFO", "native-abis", "Native ABIs present", abis.joinToString())

        if (m?.allowBackup == true) findings += Finding("LOW", "allow-backup", "android:allowBackup is true - app data can be extracted via adb backup on debuggable/rooted devices", "")
        m?.components?.filter { it.exported && it.permission == null && it.kind != "activity" }?.forEach {
            findings += Finding("MEDIUM", "exported-no-permission", "Exported ${it.kind} without a permission requirement", it.name)
        }

        // Signature: replaces the old "any META-INF file => signed" guess with real evidence.
        if (!sig.isSigned) {
            findings += Finding("HIGH", "unsigned", "No v1 (jar), v2, or v3 signature evidence found", "")
        } else {
            val schemes = buildList {
                if (sig.v1Certs.isNotEmpty()) add("v1(${sig.v1Certs.size} cert)")
                if (sig.v2SchemeMarkerFound) add("v2")
                if (sig.v3SchemeMarkerFound) add("v3")
            }
            findings += Finding("INFO", "signed", "Signature evidence found", schemes.joinToString())
            sig.v1Certs.forEach { c ->
                if (c.selfSigned) findings += Finding("INFO", "self-signed-cert", "Self-signed v1 certificate", c.subject)
                if (c.expired) findings += Finding("MEDIUM", "expired-cert", "v1 signing certificate has expired", "${c.subject} (notAfter=${SignatureInspector.fmtDate(c.notAfter)})")
            }
        }

        val minSdkVal = m?.minSdk
        if (minSdkVal != null && minSdkVal < 21) {
            findings += Finding("LOW", "low-minsdk", "minSdkVersion is low ($minSdkVal) - wider legacy TLS/crypto attack surface", "")
        }

        val dexSummary = if (dexFileCount > 0) DexSummary(dexFileCount, dexClasses, dexMethods, dexStrings) else null

        return Report(
            path = apkPath,
            sizeBytes = file.length(),
            fileCount = files,
            abis = abis.toList().sorted(),
            permissions = permissions.toList().sorted(),
            packagesHints = packages.toList().sorted().take(30),
            findings = findings.sortedBy { severityRank(it.severity) },
            stringsOfInterest = interesting.toList().take(50),
            metaInf = metaInf.take(30),
            certFingerprints = certFps.distinct().take(20),
            exportedHints = exportedHints.toList().take(40),
            manifest = m,
            dex = dexSummary,
            signature = sigSummary
        )
    }

    private fun buildManifestSummary(root: AxmlParser.Element): ManifestSummary {
        val pkg = root.attrString("package")
        val versionCode = root.attrInt("versionCode")
        val versionName = root.attrString("versionName")
        val compileSdk = root.attrInt("compileSdkVersion")
        val usesSdk = root.children.firstOrNull { it.name == "uses-sdk" }
        val minSdk = usesSdk?.attrInt("minSdkVersion")
        val targetSdk = usesSdk?.attrInt("targetSdkVersion")
        val perms = root.children.filter { it.name == "uses-permission" || it.name == "uses-permission-sdk-23" }
            .mapNotNull { it.attrString("name") }
        val app = root.children.firstOrNull { it.name == "application" }
        val debuggable = app?.attrBool("debuggable")
        val allowBackup = app?.attrBool("allowBackup")
        val cleartext = app?.attrBool("usesCleartextTraffic")
        val nsc = app?.attr("networkSecurityConfig") != null
        val components = mutableListOf<ComponentSummary>()
        app?.children?.forEach { c ->
            if (c.name in setOf("activity", "activity-alias", "service", "receiver", "provider")) {
                val name = c.attrString("name") ?: "?"
                val hasIntentFilter = c.children.any { it.name == "intent-filter" }
                val explicit = c.attrBool("exported")
                val exported = explicit ?: hasIntentFilter // pre-API31 OS default when unspecified
                val permission = c.attrString("permission")
                components += ComponentSummary(c.name, name, exported, explicit != null, permission, hasIntentFilter)
            }
        }
        return ManifestSummary(pkg, versionCode, versionName, minSdk, targetSdk, compileSdk, debuggable, allowBackup, cleartext, nsc, perms, components)
    }

    private fun severityRank(s: String) = when (s) {
        "CRITICAL" -> 0; "HIGH" -> 1; "MEDIUM" -> 2; "LOW" -> 3; else -> 4
    }

    fun extractPrintableStrings(data: ByteArray, minLen: Int = 4): List<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        fun flush() { if (sb.length >= minLen) out += sb.toString(); sb.setLength(0) }
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
        report.manifest?.let { m ->
            appendLine("package=${m.packageName} version=${m.versionName}(${m.versionCode}) minSdk=${m.minSdk} targetSdk=${m.targetSdk} compileSdk=${m.compileSdk}")
            appendLine("debuggable=${m.debuggable} allowBackup=${m.allowBackup} usesCleartextTraffic=${m.usesCleartextTraffic} networkSecurityConfig=${m.networkSecurityConfig}")
            appendLine("components: ${m.components.size} (exported: ${m.components.count { it.exported }})")
            m.components.filter { it.exported }.take(20).forEach {
                appendLine("  [exported${if (!it.exportedExplicit) ", implicit-from-intent-filter" else ""}] ${it.kind}: ${it.name}${it.permission?.let { p -> "  permission=$p" } ?: ""}")
            }
        }
        report.dex?.let { d ->
            appendLine("dex: files=${d.dexFileCount} classes=${d.totalClasses} methods=${d.totalMethods} strings=${d.totalStrings}")
        }
        report.signature?.let { s ->
            appendLine("signature: signed=${s.signed} v2=${s.v2Present} v3=${s.v3Present} v1Certs=${s.v1CertSubjects.size}")
            s.v1CertSubjects.forEachIndexed { i, subj ->
                appendLine("  cert[$i]: $subj  selfSigned=${s.v1SelfSigned.getOrNull(i)} expired=${s.v1Expired.getOrNull(i)} sha256=${s.v1Sha256.getOrNull(i)?.take(16)}...")
            }
        }
        appendLine("abis=${report.abis}")
        appendLine("permissions(${report.permissions.size}):")
        report.permissions.take(40).forEach { appendLine("  - $it") }
        appendLine("findings(${report.findings.size}):")
        report.findings.forEach { f -> appendLine("  [${f.severity}] ${f.id}: ${f.title} - ${f.detail}") }
        if (report.packagesHints.isNotEmpty()) appendLine("package-hints: ${report.packagesHints.take(15).joinToString()}")
        if (report.certFingerprints.isNotEmpty()) {
            appendLine("cert-meta:")
            report.certFingerprints.forEach { appendLine("  - $it") }
        }
        if (report.exportedHints.isNotEmpty()) appendLine("component-hints: ${report.exportedHints.take(12).joinToString()}")
    }
}
