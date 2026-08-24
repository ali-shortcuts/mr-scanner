package com.mrscanner.omega.core.scheduler
import com.mrscanner.omega.core.plugin.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

class PluginDagExecutor(private val plugins: List<ScanPlugin>) {
    private val byId = plugins.associateBy { it.id }
    init { topologicalLayers() }

    fun topologicalLayers(): List<List<ScanPlugin>> {
        val remaining = plugins.map { it.id }.toMutableSet()
        val done = mutableSetOf<String>()
        val layers = mutableListOf<List<ScanPlugin>>()
        var guard = 0
        while (remaining.isNotEmpty()) {
            if (guard++ > plugins.size + 2) error("plugin dependency cycle among $remaining")
            val ready = remaining.filter { id ->
                val p = byId.getValue(id)
                p.dependsOn.all { dep -> dep in done || dep !in byId }
            }
            if (ready.isEmpty()) error("unsatisfied deps among $remaining")
            layers += ready.map { byId.getValue(it) }
            done += ready; remaining -= ready.toSet()
        }
        return layers
    }

    suspend fun execute(
        target: ScanTarget, ctx: ScanContext, budget: BudgetGuard,
        pluginFilter: (ScanPlugin) -> Boolean = { true }
    ): List<PluginResult> {
        val results = mutableListOf<PluginResult>()
        for (layer in topologicalLayers()) {
            val runnable = layer.filter { p ->
                if (!pluginFilter(p)) return@filter false
                if (p.requiredProfile.isNotEmpty() && ctx.profile !in p.requiredProfile) return@filter false
                budget.canRun(p.id, p.cost.estConnections, p.cost.estBytes)
            }
            layer.filter { it !in runnable && pluginFilter(it) }.forEach { skipped ->
                val reason = when {
                    skipped.requiredProfile.isNotEmpty() && ctx.profile !in skipped.requiredProfile -> "PROFILE_MISMATCH"
                    skipped.id in budget.skippedPlugins -> "BUDGET_EXCEEDED"
                    else -> "FILTERED"
                }
                results += PluginHelpers.abstain(skipped.id, reason, System.currentTimeMillis(), skipped.evidenceClass ?: EvidenceClass.WEAK)
            }
            if (runnable.isEmpty()) continue
            val layerResults = coroutineScope {
                runnable.map { plugin ->
                    async {
                        val t0 = System.currentTimeMillis()
                        val result = try { plugin.scan(target, ctx) }
                        catch (e: kotlinx.coroutines.CancellationException) { throw e }
                        catch (e: Exception) { PluginHelpers.abstain(plugin.id, e.message ?: "error", t0, plugin.evidenceClass ?: EvidenceClass.WEAK) }
                        budget.record(plugin.cost.estConnections, plugin.cost.estBytes)
                        result
                    }
                }.awaitAll()
            }
            results += layerResults
            val tcp = layerResults.find { it.pluginId == "tcpconnect" }
            if (tcp != null && tcp.details["alive"] == "false") break
        }
        return results
    }
}
