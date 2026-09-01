package com.mrscanner.omega.core.model
import com.mrscanner.omega.core.plugin.ConfidenceReport
import com.mrscanner.omega.core.plugin.PluginResult
import com.mrscanner.omega.core.plugin.Verdict
import kotlinx.serialization.Serializable

@Serializable data class SignalDto(val pluginId: String, val polarity: String, val evidenceClass: String, val reason: String? = null)
@Serializable data class HostResultDto(
    val input: String, val resolved: List<String> = emptyList(),
    val confidence: Double, val logOdds: Double, val verdict: String, val explanation: String,
    val signals: List<SignalDto> = emptyList(), val pluginSummaries: List<String> = emptyList()
)
@Serializable data class ScanExportDto(
    val schemaVersion: Int = 1, val engine: String = "confidence-v3",
    val appVersion: String = "2.4.1-hotfix", val configHash: String, val scanId: String,
    val profile: String, val startedAt: String, val finishedAt: String, val hosts: List<HostResultDto>
)

data class HostScanResult(val host: String, val resolved: List<String>, val report: ConfidenceReport, val pluginResults: List<PluginResult>) {
    fun toDto() = HostResultDto(host, resolved, report.confidence, report.logOdds, report.verdict.name, report.explanation,
        report.contributingSignals.map { SignalDto(it.pluginId, it.polarity.name, it.evidenceClass.name, it.reason) },
        pluginResults.map { "${it.pluginId}: ${it.summary}" })
}

data class HoleRecord(
    val holeId: String, val host: String, val technique: String, var status: String,
    val firstSeenAt: Long, var lastConfirmedAt: Long, var closedAt: Long? = null,
    var closedReason: String? = null, var lastConfidence: Double = 0.0,
    var lastVerdict: String = Verdict.WEAK_SIGNAL_ONLY.name, var lastSeenWeakAt: Long? = null
)

data class CheckpointRecord(
    val scanId: String, val schemaVersion: Int = 1, val configHash: String,
    var cursorIndex: Int, val totalHosts: Int,
    val completedHosts: MutableList<String> = mutableListOf(),
    val createdAt: Long = System.currentTimeMillis(), var updatedAt: Long = System.currentTimeMillis()
)

/**
 * Checkpoint for streaming CIDR scans. Deliberately does NOT keep a
 * completedHosts list like [CheckpointRecord] — for a /8 that list would be
 *16M+ strings. A numeric cursor into the range (position `cursor` of
 * `rangeSpec`) is all that's needed to resume: [com.mrscanner.omega.core.scheduler.CidrRangeEngine.stream]
 * regenerates addresses on demand from that offset.
 */
data class CidrCheckpointRecord(
    val scanId: String, val rangeSpec: String, val configHash: String,
    var cursor: Long, val total: Long, var aliveFound: Long = 0,
    val createdAt: Long = System.currentTimeMillis(), var updatedAt: Long = System.currentTimeMillis()
)
