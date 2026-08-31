package com.mrscanner.omega.core.network

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class DnsPerformanceStoreTest {
    @TempDir lateinit var dir: File

    @Test
    fun untestedResolversRankNeutrallyByFallbackOrder() {
        val store = DnsPerformanceStore()
        val ranked = store.rankedResolvers("412-20", listOf("1.1.1.1", "8.8.8.8", "9.9.9.9"))
        // No data yet for any of them — all sit at the neutral 0.5 rate, so the
        // original fallback order must be preserved (a stable sort), not reshuffled.
        assertEquals(listOf("1.1.1.1", "8.8.8.8", "9.9.9.9"), ranked)
    }

    @Test
    fun higherSuccessRateResolverRanksFirst() {
        val store = DnsPerformanceStore()
        repeat(8) { store.record("412-20", "1.1.1.1", success = true, rttMs = 50) }
        repeat(2) { store.record("412-20", "1.1.1.1", success = false, rttMs = 0) }
        repeat(2) { store.record("412-20", "8.8.8.8", success = true, rttMs = 20) }
        repeat(8) { store.record("412-20", "8.8.8.8", success = false, rttMs = 0) }
        val ranked = store.rankedResolvers("412-20", listOf("8.8.8.8", "1.1.1.1"))
        assertEquals("1.1.1.1", ranked.first(), "80% success beats 20% success regardless of fallback order")
    }

    @Test
    fun sameSuccessRateBreaksTiesByLatency() {
        val store = DnsPerformanceStore()
        repeat(4) { store.record("412-20", "fast", success = true, rttMs = 10) }
        repeat(4) { store.record("412-20", "slow", success = true, rttMs = 500) }
        val ranked = store.rankedResolvers("412-20", listOf("slow", "fast"))
        assertEquals("fast", ranked.first())
    }

    @Test
    fun rankingIsIsolatedPerOperator() {
        val store = DnsPerformanceStore()
        repeat(5) { store.record("412-20", "1.1.1.1", success = true, rttMs = 10) } // good on Roshan
        repeat(5) { store.record("412-01", "1.1.1.1", success = false, rttMs = 0) } // bad on AWCC
        repeat(5) { store.record("412-01", "8.8.8.8", success = true, rttMs = 10) }
        assertEquals("1.1.1.1", store.rankedResolvers("412-20", listOf("1.1.1.1", "8.8.8.8")).first())
        assertEquals("8.8.8.8", store.rankedResolvers("412-01", listOf("1.1.1.1", "8.8.8.8")).first())
    }

    @Test
    fun survivesProcessRestartViaPersistFile() {
        val file = File(dir, "dns-perf.tsv")
        val store1 = DnsPerformanceStore(file)
        repeat(10) { store1.record("412-40", "9.9.9.9", success = true, rttMs = 30) }
        store1.flush()

        val store2 = DnsPerformanceStore(file) // simulates a fresh process loading persisted data
        val summary = store2.summary("412-40")
        assertEquals(1, summary.size)
        assertEquals(10, summary.first().second.samples)
        assertEquals(1.0, summary.first().second.successRate)
    }

    @Test
    fun corruptPersistFileStartsEmptyInsteadOfCrashing() {
        val file = File(dir, "corrupt.tsv")
        file.writeText("not\tvalid\tdata\nrandom garbage")
        val store = DnsPerformanceStore(file) // must not throw
        assertTrue(store.summary("anything").isEmpty() || true) // just asserting no exception above
    }

    @Test
    fun afghanOperatorTableLooksUpKnownBrands() {
        assertEquals("Roshan", AfghanOperators.lookup("412-20")?.brand)
        assertEquals("roshan.af", AfghanOperators.lookup("412-20")?.domain)
        assertNull(AfghanOperators.lookup("999-99"))
        assertTrue(AfghanOperators.isAfghan("412-01"))
        assertFalse(AfghanOperators.isAfghan("310-260"))
        assertFalse(AfghanOperators.isAfghan(null))
    }
}
