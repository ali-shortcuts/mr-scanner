package com.mrscanner.omega.core.settings
import java.security.MessageDigest

enum class RedactionLevel { NONE, STANDARD, STRICT }

data class ConsoleSettings(
    // Hard ceiling for concurrency. Not "unlimited" on purpose: past a few
    // thousand simultaneous sockets you hit OS file-descriptor/thread limits
    // before you hit any limit in this app, so raising this further just
    // trades a controlled error for a crash. 4096 is generous headroom over
    // the old 64 cap; CidrRangeEngine.effectiveConcurrency additionally
    // scales this down for ranges too small to use it.
    var concurrency: Int = 8,
    var timeoutMs: Long = 5_000,
    var retries: Int = 1,
    var freeScoreThreshold: Int = 70,
    var precheckTimeoutMs: Long = 800,
    var dedupByIp: Boolean = true,
    var adaptiveTimeout: Boolean = true,
    var postCheckMultiplier: Double = 1.5,
    var dnsRegion: String = "global",
    var customDnsServers: List<String> = emptyList(),
    // Ports probed by tcpconnect/precheck-style plugins. Kept short by design
    // (3-4 entries) per project convention — a long port list doesn't
    // improve zero-rating detection, it just multiplies request volume.
    var scanPorts: List<Int> = listOf(443, 80, 8443),
    var sniSpoofCandidates: List<String> = emptyList(),
    var testFragmentBypass: Boolean = true,
    var testFingerprint: Boolean = false,
    var testEch: Boolean = true,
    var testQuic: Boolean = true,
    var testCdnEdge: Boolean = false,
    var testAlpnMatrix: Boolean = false,
    var testDnsTransport: Boolean = true,
    var testJa3Self: Boolean = true,
    var recordFragmentSplits: List<Int> = listOf(1, 2, 5, 10),
    var budgetProfileOverride: String? = null,
    var checkpointEveryNHosts: Int = 25,
    var exportSchemaVersion: Int = 1,
    var redactionLevel: RedactionLevel = RedactionLevel.STANDARD,
    var updateCheckEnabled: Boolean = true,
    var selfTestOnFirstRun: Boolean = true,
    var deepScan: Boolean = true,
    var operatorHint: String? = "af",
    /** Detected SIM/network operator, "412-20" form (see SimOperatorDetector / AfghanOperators).
     * Drives per-operator DNS resolver ranking in DnsPerformanceStore — null disables it (falls
     * back to the static region list, same as before this existed). */
    var detectedOperatorKey: String? = null,
    var enableActiveInjectionProbes: Boolean = true
) {
    fun configHash(): String {
        val s = "c=$concurrency|t=$timeoutMs|r=$retries|pre=$precheckTimeoutMs|dedup=$dedupByIp|dns=$dnsRegion|frag=$testFragmentBypass|ech=$testEch|quic=$testQuic|cdn=$testCdnEdge|alpn=$testAlpnMatrix|dot=$testDnsTransport|splits=${recordFragmentSplits.joinToString(",")}|deep=$deepScan|customDns=${customDnsServers.sorted().joinToString(",")}|sni=${sniSpoofCandidates.sorted().joinToString(",")}|ports=${scanPorts.joinToString(",")}"
        return MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }.take(16)
    }
    fun setKey(key: String, value: String): Boolean {
        return try {
            when (key.lowercase()) {
                "concurrency" -> concurrency = value.toInt().coerceIn(1, 4096)
                "timeoutms", "timeout" -> timeoutMs = value.toLong().coerceIn(200, 120_000)
                "retries" -> retries = value.toInt().coerceIn(0, 5)
                "dnsregion", "dns_region" -> dnsRegion = value
                "ports", "scanports" -> scanPorts = value.split(",").mapNotNull { it.trim().toIntOrNull() }.take(4)
                "customdns", "customdnsservers" -> customDnsServers = value.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                "operator", "detectedoperatorkey" -> detectedOperatorKey = value.trim().ifEmpty { null }
                "testfragmentbypass", "fragment" -> testFragmentBypass = value.toBooleanStrict()
                "testech", "ech" -> testEch = value.toBooleanStrict()
                "testquic", "quic" -> testQuic = value.toBooleanStrict()
                "testcdnedge", "cdnedge" -> testCdnEdge = value.toBooleanStrict()
                "testalpnmatrix", "alpn" -> testAlpnMatrix = value.toBooleanStrict()
                "testdnstransport", "dnstransport" -> testDnsTransport = value.toBooleanStrict()
                "deepscan", "deep" -> deepScan = value.toBooleanStrict()
                "dedupbyip", "dedup" -> dedupByIp = value.toBooleanStrict()
                "redaction", "redactionlevel" -> redactionLevel = RedactionLevel.valueOf(value.uppercase())
                else -> return false
            }
            true
        } catch (_: Exception) { false }
    }

    fun snapshotLines() = listOf(
        "concurrency=$concurrency", "timeoutMs=$timeoutMs", "retries=$retries", "dnsRegion=$dnsRegion", "scanPorts=$scanPorts",
        "detectedOperatorKey=$detectedOperatorKey",
        "testFragmentBypass=$testFragmentBypass", "testEch=$testEch", "testQuic=$testQuic",
        "testCdnEdge=$testCdnEdge", "testAlpnMatrix=$testAlpnMatrix", "testDnsTransport=$testDnsTransport",
        "deepScan=$deepScan", "dedupByIp=$dedupByIp", "recordFragmentSplits=$recordFragmentSplits",
        "redactionLevel=$redactionLevel", "configHash=${configHash()}"
    )
}
