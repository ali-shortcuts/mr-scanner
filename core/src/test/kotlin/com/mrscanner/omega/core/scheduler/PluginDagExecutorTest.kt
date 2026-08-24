package com.mrscanner.omega.core.scheduler
import com.mrscanner.omega.core.plugin.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PluginDagExecutorTest {
    private class P(override val id: String, override val dependsOn: Set<String> = emptySet(), private val alive: Boolean? = null) : ScanPlugin {
        override val displayName = id; override val evidenceClass = EvidenceClass.WEAK
        override val cost = PluginCost(1, 1, 1); override val requiredProfile = emptySet<NetworkProfile>()
        override suspend fun scan(target: ScanTarget, ctx: ScanContext) = PluginResult(id,
            PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK), "ok",
            if (id == "tcpconnect" && alive != null) mapOf("alive" to alive.toString()) else emptyMap(), durationMs = 1)
    }
    @Test fun topo() {
        val e = PluginDagExecutor(listOf(P("b", setOf("a")), P("a"), P("c", setOf("b"))))
        val flat = e.topologicalLayers().flatten().map { it.id }
        assertTrue(flat.indexOf("a") < flat.indexOf("b"))
        assertTrue(flat.indexOf("b") < flat.indexOf("c"))
    }
    @Test fun deadStops() = runBlocking {
        val e = PluginDagExecutor(listOf(P("tcpconnect", alive = false), P("tls", setOf("tcpconnect")), P("https", setOf("tcpconnect"))))
        val r = e.execute(ScanTarget("x"), ScanContext(), BudgetGuard.forProfile(NetworkProfile.UNKNOWN))
        assertEquals(1, r.size); assertEquals("tcpconnect", r.first().pluginId)
    }
}
