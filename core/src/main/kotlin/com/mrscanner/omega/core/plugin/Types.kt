package com.mrscanner.omega.core.plugin

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.json.JsonObject
import kotlin.coroutines.coroutineContext

enum class SignalPolarity { SUPPORTS_BYPASS, REFUTES_BYPASS, ABSTAIN }

enum class EvidenceClass(val logOddsWeight: Double) {
    DEFINITIVE(3.0), STRONG(1.5), MODERATE(0.7), WEAK(0.3)
}

data class PluginSignal(
    val pluginId: String,
    val polarity: SignalPolarity,
    val evidenceClass: EvidenceClass,
    val reason: String? = null
)

enum class Verdict { CONFIRMED_CANDIDATE, CONFIRMED_NOT_VULNERABLE, WEAK_SIGNAL_ONLY }

data class ConfidenceReport(
    val confidence: Double,
    val logOdds: Double,
    val verdict: Verdict,
    val contributingSignals: List<PluginSignal>,
    val explanation: String
)

enum class NetworkProfile { CELLULAR_METERED, WIFI_UNMETERED, WIFI_PLUS_VPN, UNKNOWN }

data class PluginCost(val estMs: Long, val estBytes: Long, val estConnections: Int = 1)

data class ScanTarget(
    val host: String,
    val port: Int = 443,
    val sni: String? = null,
    val tags: Map<String, String> = emptyMap()
) { val effectiveSni: String get() = sni ?: host }

class ScanContext(
    val profile: NetworkProfile = NetworkProfile.UNKNOWN,
    val timeoutMs: Long = 5_000,
    val extras: MutableMap<String, Any?> = mutableMapOf()
) {
    fun put(key: String, value: Any?) { extras[key] = value }
    @Suppress("UNCHECKED_CAST")
    fun <T> get(key: String): T? = extras[key] as? T
    suspend fun ensureActive() { coroutineContext.ensureActive() }
}

data class PluginResult(
    val pluginId: String,
    val signal: PluginSignal,
    val summary: String,
    val details: Map<String, String> = emptyMap(),
    val rawExport: JsonObject? = null,
    val durationMs: Long
)

interface ScanPlugin {
    val id: String
    val displayName: String
    val evidenceClass: EvidenceClass?
    val cost: PluginCost
    val dependsOn: Set<String>
    val requiredProfile: Set<NetworkProfile>
    suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult
}

object PluginHelpers {
    fun abstain(pluginId: String, reason: String, t0: Long, evidence: EvidenceClass = EvidenceClass.WEAK) =
        PluginResult(
            pluginId = pluginId,
            signal = PluginSignal(pluginId, SignalPolarity.ABSTAIN, evidence, reason),
            summary = "abstain: $reason",
            details = mapOf("reason" to reason),
            durationMs = (System.currentTimeMillis() - t0).coerceAtLeast(0)
        )

    suspend inline fun safeScan(
        pluginId: String,
        evidence: EvidenceClass,
        t0: Long = System.currentTimeMillis(),
        block: () -> PluginResult
    ): PluginResult = try {
        block()
    } catch (c: CancellationException) {
        throw c
    } catch (e: Exception) {
        abstain(pluginId, e.message ?: e::class.simpleName ?: "error", t0, evidence)
    }
}
