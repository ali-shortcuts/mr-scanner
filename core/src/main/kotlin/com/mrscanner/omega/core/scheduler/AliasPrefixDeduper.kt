package com.mrscanner.omega.core.scheduler

/** Port of Go pkg/scanner/aliased.go — cap alive rate 0.80 in /24. */
object AliasPrefixDeduper {
    fun filter(hostsWithIp: List<Pair<String, String>>, maxAliveRate: Double = 0.80): List<String> {
        val by24 = hostsWithIp.groupBy { (_, ip) ->
            val p = ip.split(".")
            if (p.size == 4) "${p[0]}.${p[1]}.${p[2]}" else ip
        }
        val keep = mutableListOf<String>()
        for ((_, group) in by24) {
            val limit = (group.size * maxAliveRate).toInt().coerceAtLeast(1)
            keep += group.take(limit).map { it.first }
        }
        return keep.distinct()
    }
}
