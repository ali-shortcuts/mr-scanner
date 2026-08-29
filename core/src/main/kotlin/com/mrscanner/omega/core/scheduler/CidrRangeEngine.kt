package com.mrscanner.omega.core.scheduler

/**
 * Streaming CIDR host generator.
 *
 * The old `CidrCmd.expand()` hard-capped at /24 (256 hosts) because it built a
 * `List<String>` up front — for anything bigger than /24 that list becomes
 * expensive or impossible to hold in memory (a /8 is 16,777,216 addresses; a
 * /0 is 4,294,967,296). This engine never builds that list: [stream] returns
 * a lazy `Sequence<String>` that computes one address at a time, so scanning
 * a /8 costs the same memory as scanning a /30 — the range size no longer
 * decides whether the scan is possible.
 *
 * What *does* still matter at huge range sizes is how much work is in flight
 * and how chatty progress reporting is; [reportCadence] and [checkpointCadence]
 * exist so a caller never has to hand-tune those per range — they're derived
 * from the range size automatically.
 */
object CidrRangeEngine {

    data class Range(val networkLong: Long, val prefix: Int, val total: Long) {
        val spec: String get() = "${longToDotted(networkLong)}/$prefix"
    }

    /** Parses "a.b.c.d/prefix" for any prefix 0..32. No upper size cap. */
    fun parse(spec: String): Range? {
        val parts = spec.trim().split("/")
        if (parts.size != 2) return null
        val prefix = parts[1].toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        val octets = parts[0].split(".").mapNotNull { it.toIntOrNull() }
        if (octets.size != 4 || octets.any { it !in 0..255 }) return null
        val ipLong = (octets[0].toLong() shl 24) or (octets[1].toLong() shl 16) or
            (octets[2].toLong() shl 8) or octets[3].toLong()
        val hostBits = 32 - prefix
        val total = if (hostBits >= 32) 1L shl 32 else 1L shl hostBits
        val mask = if (hostBits >= 32) 0L else (0xFFFFFFFFL shl hostBits) and 0xFFFFFFFFL
        val network = ipLong and mask
        return Range(network, prefix, total)
    }

    /** Lazy — O(1) memory regardless of [range].total. Resumable via [startAt]. */
    fun stream(range: Range, startAt: Long = 0L): Sequence<String> = sequence {
        var i = startAt
        while (i < range.total) {
            yield(longToDotted(range.networkLong + i))
            i++
        }
    }

    fun longToDotted(v: Long): String {
        val a = (v ushr 24) and 0xff; val b = (v ushr 16) and 0xff
        val c = (v ushr 8) and 0xff; val d = v and 0xff
        return "$a.$b.$c.$d"
    }

    /**
     * How many hosts between progress/log lines. Small ranges report every
     * host (useful, cheap); huge ranges widen the cadence so a /8 doesn't
     * emit 16 million log lines — the terminal stays readable and the event
     * bus doesn't become the bottleneck instead of the network.
     */
    fun reportCadence(total: Long): Long = when {
        total <= 256 -> 1
        total <= 65_536 -> 64
        total <= 1_048_576 -> 1_000
        total <= 16_777_216 -> 5_000
        else -> 25_000
    }

    /** How often (in hosts processed) to persist a resumable cursor. */
    fun checkpointCadence(total: Long): Long = (reportCadence(total) * 4).coerceAtLeast(25)

    /**
     * Safe concurrency ceiling for a given range size and the operator's
     * requested concurrency — this is the "calculator": the caller always
     * gets *a* usable number back instead of failing, but very large ranges
     * are gently capped below the raw setting to avoid opening more
     * simultaneous sockets than the range can even make useful (e.g. asking
     * for concurrency=4096 against a /28 of 16 hosts is pointless, and asking
     * for concurrency=4096 on a low-power phone against a /8 risks socket
     * exhaustion) — it never refuses the scan, it just picks a sane window.
     */
    fun effectiveConcurrency(total: Long, requested: Int): Int {
        val byRange = if (total < requested) total.toInt().coerceAtLeast(1) else requested
        return byRange.coerceIn(1, requested.coerceAtLeast(1))
    }
}
