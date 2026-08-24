package com.mrscanner.omega.core.scheduler
import com.mrscanner.omega.core.plugin.NetworkProfile

data class HostBudget(val maxWallTimeMs: Long, val maxConnections: Int, val maxPayloadBytes: Long, val label: String)

class BudgetGuard(val hostBudget: HostBudget) {
    private val t0 = System.currentTimeMillis()
    private var connectionsUsed = 0
    private var bytesUsed = 0L
    private val skipped = mutableListOf<String>()
    val elapsedMs get() = System.currentTimeMillis() - t0
    val skippedPlugins get() = skipped.toList()
    val budget get() = hostBudget

    fun canRun(pluginId: String, estConnections: Int = 1, estBytes: Long = 0): Boolean {
        if (elapsedMs >= hostBudget.maxWallTimeMs) { skipped += pluginId; return false }
        if (connectionsUsed + estConnections > hostBudget.maxConnections) { skipped += pluginId; return false }
        if (bytesUsed + estBytes > hostBudget.maxPayloadBytes) { skipped += pluginId; return false }
        return true
    }
    fun record(c: Int, b: Long) { connectionsUsed += c; bytesUsed += b }

    companion object {
        fun forProfile(profile: NetworkProfile, overrideLabel: String? = null): BudgetGuard {
            val b = when (overrideLabel?.uppercase()) {
                "CIDR_BULK", "BULK" -> HostBudget(3_000, 3, 64L * 1024, "CIDR_BULK")
                "DEEP_SINGLE", "DEEP" -> HostBudget(60_000, 48, 4L * 1024 * 1024, "DEEP_SINGLE")
                else -> when (profile) {
                    NetworkProfile.CELLULAR_METERED -> HostBudget(12_000, 10, 512L * 1024, "CELLULAR_METERED")
                    NetworkProfile.WIFI_PLUS_VPN -> HostBudget(30_000, 24, 1L * 1024 * 1024, "WIFI_PLUS_VPN")
                    NetworkProfile.WIFI_UNMETERED -> HostBudget(60_000, 48, 2L * 1024 * 1024, "WIFI_UNMETERED")
                    NetworkProfile.UNKNOWN -> HostBudget(45_000, 32, 1L * 1024 * 1024, "UNKNOWN")
                }
            }
            return BudgetGuard(b)
        }
    }
}
