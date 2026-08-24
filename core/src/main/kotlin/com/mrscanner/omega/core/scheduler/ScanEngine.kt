package com.mrscanner.omega.core.scheduler
import com.mrscanner.omega.core.db.*
import com.mrscanner.omega.core.db.OmegaDatabase
import com.mrscanner.omega.core.eventbus.*
import com.mrscanner.omega.core.export.ResultJsonCodec
import com.mrscanner.omega.core.intelligence.ConfidenceEngineV3
import com.mrscanner.omega.core.metrics.LocalMetricsStore
import com.mrscanner.omega.core.metrics.PluginTiming
import com.mrscanner.omega.core.metrics.ScanTiming
import com.mrscanner.omega.core.model.*
import com.mrscanner.omega.core.plugin.*
import com.mrscanner.omega.core.settings.ConsoleSettings
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class ScanEngine(
    val settings: ConsoleSettings = ConsoleSettings(),
    val eventBus: EventBus = EventBus(),
    val holeStore: HoleAgeStore = HoleAgeStore(),
    val checkpointStore: CheckpointStore = CheckpointStore(),
    val history: ScanHistoryStore = ScanHistoryStore(),
    var profile: NetworkProfile = NetworkProfile.UNKNOWN,
    val database: OmegaDatabase? = null
) {
    private fun applyHole(host: String, verdict: com.mrscanner.omega.core.plugin.Verdict, conf: Double) {
        if (database != null) database.holes.applyVerdict(host, verdict, conf)
        else holeStore.applyVerdict(host, verdict, conf)
    }
    private fun saveCheckpoint(cp: com.mrscanner.omega.core.model.CheckpointRecord) {
        if (database != null) database.checkpoints.save(cp) else checkpointStore.save(cp)
    }
    private fun loadCheckpoint(id: String) =
        if (database != null) database.checkpoints.get(id) else checkpointStore.get(id)

    suspend fun scanHosts(hosts: List<String>, scanId: String = UUID.randomUUID().toString().take(8), resume: Boolean = false): List<HostScanResult> {
        val t0 = System.currentTimeMillis()
        val startedAt = Instant.now().toString()
        val configHash = settings.configHash()
        var startIndex = 0
        val completed = mutableListOf<String>()
        if (resume) {
            val cp = loadCheckpoint(scanId)
            if (cp != null) {
                if (cp.configHash != configHash) {
                    eventBus.emit(ScanEvent.LogEmitted("ERROR", "config drift — refuse resume"))
                    return emptyList()
                }
                startIndex = cp.cursorIndex; completed += cp.completedHosts
                eventBus.emit(ScanEvent.LogEmitted("SYSTEM", "resuming $scanId @$startIndex"))
            }
        }
        val targets = hosts.drop(startIndex)
        val plugins = PluginRegistry.createAll(settings)
        val dag = PluginDagExecutor(plugins)
        val sem = Semaphore(settings.concurrency.coerceIn(1, 64))
        val results = mutableListOf<HostScanResult>()
        val lock = Any()
        eventBus.emit(ScanEvent.LogEmitted("SYSTEM", "scan=$scanId hosts=${hosts.size} plugins=${plugins.size} profile=$profile budget=${BudgetGuard.forProfile(profile, settings.budgetProfileOverride).budget.label}"))
        eventBus.emit(ScanEvent.LogEmitted("SYSTEM", "configHash=$configHash"))
        var budgetExceeded = 0
        coroutineScope {
            targets.map { host ->
                async(Dispatchers.IO) {
                    sem.withPermit {
                        val result = scanOne(host, dag)
                        synchronized(lock) { results += result; completed += host }
                        applyHole(host, result.report.verdict, result.report.confidence)
                        eventBus.emit(ScanEvent.HostVerdict(host, result.report,
                            result.pluginResults.filter { it.signal.polarity != SignalPolarity.ABSTAIN }
                                .map { "${it.pluginId.substringAfterLast('.')}: ${it.summary}" }))
                        val n = synchronized(lock) { completed.size }
                        eventBus.emit(ScanEvent.Progress(n, hosts.size, host))
                        if (n % settings.checkpointEveryNHosts == 0 || n == hosts.size) {
                            val cp = CheckpointRecord(scanId, configHash = configHash, cursorIndex = completed.size, totalHosts = hosts.size, completedHosts = completed.toMutableList())
                            saveCheckpoint(cp)
                            eventBus.emit(ScanEvent.CheckpointSaved(scanId, cp.cursorIndex))
                        }
                        result
                    }
                }
            }.awaitAll()
        }
        val ordered = hosts.mapNotNull { h -> results.find { it.host == h } }
        history.put(scanId, ordered)
        val wall = System.currentTimeMillis() - t0
        val counts = ordered.groupingBy { it.report.verdict.name }.eachCount()
        LocalMetricsStore.recordScan(ScanTiming(scanId, profile.name, ordered.size, wall, counts, budgetExceeded))
        eventBus.emit(ScanEvent.ScanFinished(scanId, ordered.size, wall))
        eventBus.emit(ScanEvent.LogEmitted("SYSTEM", "finished scan=$scanId hosts=${ordered.size} wallMs=$wall"))
        lastMeta[scanId] = Meta(configHash, profile.name, startedAt, Instant.now().toString())
        return ordered
    }

    suspend fun scanOne(host: String, dag: PluginDagExecutor? = null): HostScanResult {
        val plugins = PluginRegistry.createAll(settings)
        val executor = dag ?: PluginDagExecutor(plugins)
        val ctx = ScanContext(profile = profile, timeoutMs = settings.timeoutMs)
        val budget = BudgetGuard.forProfile(profile, settings.budgetProfileOverride)
        val target = ScanTarget(host = host.trim())
        val pluginResults = executor.execute(target, ctx, budget)
        if (budget.skippedPlugins.isNotEmpty()) eventBus.tryEmit(ScanEvent.BudgetExceeded(host, budget.skippedPlugins))
        pluginResults.forEach { pr ->
            LocalMetricsStore.recordPlugin(PluginTiming(pr.pluginId, host, pr.durationMs, pr.signal.polarity.name, pr.signal.reason))
        }
        val voting = pluginResults.filter { p -> plugins.find { it.id == p.pluginId }?.evidenceClass != null }.map { it.signal }
        val report = ConfidenceEngineV3.compute(voting)
        @Suppress("UNCHECKED_CAST")
        val resolved = ctx.get<List<String>>("resolved.ips").orEmpty()
        return HostScanResult(host, resolved, report, pluginResults)
    }

    fun export(scanId: String): ScanExportDto? {
        val hosts = history.get(scanId) ?: return null
        val m = lastMeta[scanId]
        return ScanExportDto(settings.exportSchemaVersion, configHash = m?.configHash ?: settings.configHash(),
            scanId = scanId, profile = m?.profile ?: profile.name,
            startedAt = m?.startedAt ?: Instant.now().toString(), finishedAt = m?.finishedAt ?: Instant.now().toString(),
            hosts = hosts.map { it.toDto() })
    }
    fun exportJson(scanId: String): String? = export(scanId)?.let { ResultJsonCodec.encode(it, settings.redactionLevel) }

    private data class Meta(val configHash: String, val profile: String, val startedAt: String, val finishedAt: String)
    companion object { private val lastMeta = ConcurrentHashMap<String, Meta>() }
}
