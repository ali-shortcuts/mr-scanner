package com.mrscanner.omega.core.network

import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Learns, per detected SIM/network operator, which DNS resolver actually
 * gives usable answers fastest — instead of a static hardcoded list.
 *
 * This is deliberately NOT a hardcoded "operator X's internal DNS server is
 * Y.Y.Y.Y" table: nobody publishes that, and inventing plausible-looking IPs
 * for it would be actively harmful for real field use. What's genuinely
 * knowable in advance is only the operator identity (see [AfghanOperators],
 * sourced from ITU bulletins); which resolver performs best on that
 * operator's network is something that has to be measured, which is exactly
 * what Ali described wanting ("determine, per SIM, which DNS resolves
 * better"). So: every real query already made through [MultiResolverDns]
 * records success/failure/latency here, keyed by operator, and future
 * lookups rank candidate resolvers by that accumulated evidence.
 */
class DnsPerformanceStore(private val persistFile: File? = null) {

    data class Stat(var success: Int = 0, var fail: Int = 0, var rttSumMs: Double = 0.0) {
        val samples get() = success + fail
        /** Unsampled resolvers default to a neutral 0.5 so they still get tried, not buried. */
        val successRate get() = if (samples == 0) 0.5 else success.toDouble() / samples
        val avgRttMs get() = if (success == 0) Double.MAX_VALUE else rttSumMs / success
    }

    // operatorKey -> resolverId -> Stat
    private val data = ConcurrentHashMap<String, ConcurrentHashMap<String, Stat>>()
    private val writesSinceFlush = AtomicInteger(0)

    init { load() }

    fun record(operatorKey: String, resolverId: String, success: Boolean, rttMs: Long) {
        val perOperator = data.getOrPut(operatorKey) { ConcurrentHashMap() }
        val stat = perOperator.getOrPut(resolverId) { Stat() }
        synchronized(stat) {
            if (success) { stat.success++; stat.rttSumMs += rttMs } else stat.fail++
        }
        // Persist periodically rather than on every record — this runs on the
        // hot path of every DNS query during a large scan, and fsync-per-query
        // would undercut the whole point of the unbounded streaming engine.
        if (writesSinceFlush.incrementAndGet() >= 50) { writesSinceFlush.set(0); save() }
    }

    /** [fallback] supplies both the candidate set and the tie-break order for resolvers with no data yet. */
    fun rankedResolvers(operatorKey: String, fallback: List<String>): List<String> {
        val stats = data[operatorKey].orEmpty()
        return fallback.sortedWith(
            compareByDescending<String> { stats[it]?.successRate ?: 0.5 }
                .thenBy { stats[it]?.avgRttMs ?: Double.MAX_VALUE }
        )
    }

    fun summary(operatorKey: String): List<Pair<String, Stat>> =
        data[operatorKey].orEmpty().entries
            .sortedWith(compareByDescending<Map.Entry<String, Stat>> { it.value.successRate }.thenBy { it.value.avgRttMs })
            .map { it.key to it.value }

    fun flush() = save()

    private fun save() {
        val f = persistFile ?: return
        try {
            f.parentFile?.mkdirs()
            f.bufferedWriter().use { w ->
                for ((op, resolvers) in data) for ((rid, s) in resolvers) {
                    w.write("$op\t$rid\t${s.success}\t${s.fail}\t${s.rttSumMs}"); w.newLine()
                }
            }
        } catch (_: Exception) { /* best-effort — ranking degrades to neutral, never crashes a scan */ }
    }

    private fun load() {
        val f = persistFile ?: return
        if (!f.isFile) return
        try {
            f.forEachLine { line ->
                val p = line.split("\t"); if (p.size < 5) return@forEachLine
                val stat = Stat(p[2].toIntOrNull() ?: 0, p[3].toIntOrNull() ?: 0, p[4].toDoubleOrNull() ?: 0.0)
                data.getOrPut(p[0]) { ConcurrentHashMap() }[p[1]] = stat
            }
        } catch (_: Exception) { /* start empty on any corruption */ }
    }
}
