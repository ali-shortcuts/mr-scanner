package com.mrscanner.omega.core.metrics
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

data class PluginTiming(val pluginId: String, val host: String, val durationMs: Long, val polarity: String, val abstainReason: String?)
data class ScanTiming(val scanId: String, val profile: String, val hostCount: Int, val wallMs: Long, val verdictCounts: Map<String, Int>, val budgetExceededCount: Int)

object LocalMetricsStore {
    private val pluginTimings = CopyOnWriteArrayList<PluginTiming>()
    private val scans = ConcurrentHashMap<String, ScanTiming>()
    fun recordPlugin(t: PluginTiming) { pluginTimings += t; if (pluginTimings.size > 5000) pluginTimings.subList(0, 1000).clear() }
    fun recordScan(t: ScanTiming) { scans[t.scanId] = t }
    fun summary(): List<String> {
        val byPlugin = pluginTimings.groupBy { it.pluginId }
        val lines = mutableListOf("scans=${scans.size} plugin_samples=${pluginTimings.size}")
        byPlugin.entries.sortedByDescending { it.value.size }.take(15).forEach { (id, list) ->
            val sorted = list.map { it.durationMs }.sorted()
            val p50 = sorted.getOrNull(sorted.size / 2) ?: 0
            val p95 = sorted.getOrNull((sorted.size * 0.95).toInt().coerceAtMost(sorted.lastIndex)) ?: 0
            val abstain = list.count { it.polarity == "ABSTAIN" }
            lines += "${id.substringAfterLast('.')}: n=${list.size} p50=${p50}ms p95=${p95}ms abstain=$abstain"
        }
        return lines
    }
}
