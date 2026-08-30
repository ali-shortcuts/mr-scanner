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
import com.mrscanner.omega.core.network.TcpConnect
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class ScanEngine(
    val settings: ConsoleSettings = ConsoleSettings(),
    val eventBus: EventBus = EventBus(),
    val holeStore: HoleAgeStore = HoleAgeStore(),
    val checkpointStore: CheckpointStore = CheckpointStore(),
    val cidrCheckpointStore: CidrCheckpointStore = CidrCheckpointStore(),
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
        val completedSet = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        if (resume) {
            val cp = loadCheckpoint(scanId)
            if (cp != null) {
                if (cp.configHash != configHash) {
                    eventBus.emit(ScanEvent.LogEmitted("ERROR", "config drift — refuse resume"))
                    return emptyList()
                }
                completedSet.addAll(cp.completedHosts)
                eventBus.emit(ScanEvent.LogEmitted("SYSTEM", "resuming $scanId @${completedSet.size}/${hosts.size}"))
            }
        }
        // Filter by membership rather than the old hosts.drop(startIndex): completion order
        // under concurrent scanning was never guaranteed to match list order, so an index
        // cursor could under- or over-skip on resume. A completed-set is exact either way.
        val targets = hosts.filterNot { it in completedSet }
        val plugins = PluginRegistry.createAll(settings)
        val concurrency = settings.concurrency.coerceIn(1, 4096)
        eventBus.emit(ScanEvent.LogEmitted("SYSTEM", "scan=$scanId hosts=${hosts.size} plugins=${plugins.size} profile=$profile budget=${BudgetGuard.forProfile(profile, settings.budgetProfileOverride).budget.label}"))
        eventBus.emit(ScanEvent.LogEmitted("SYSTEM", "configHash=$configHash"))

        val doneCount = java.util.concurrent.atomic.AtomicInteger(completedSet.size)
        val foundCount = java.util.concurrent.atomic.AtomicInteger(0)
        val results = java.util.concurrent.CopyOnWriteArrayList<HostScanResult>()
        val checkpointEvery = settings.checkpointEveryNHosts.coerceAtLeast(1)

        // Streamed with bounded concurrency (flatMapMerge) instead of the old
        // `targets.map { async { ... } }.awaitAll()`, which launched every host as
        // a coroutine up front regardless of list size — fine for a few hundred
        // hosts, not for a multi-million-line file.
        targets.asFlow()
            .flatMapMerge(concurrency) { host ->
                flow {
                    val dag = PluginDagExecutor(plugins)
                    emit(scanOne(host, dag))
                }
            }
            .collect { result ->
                val host = result.host
                results += result
                completedSet += host
                applyHole(host, result.report.verdict, result.report.confidence)
                if (result.report.verdict == Verdict.CONFIRMED_CANDIDATE) foundCount.incrementAndGet()
                eventBus.emit(ScanEvent.HostVerdict(host, result.report,
                    result.pluginResults.filter { it.signal.polarity != SignalPolarity.ABSTAIN }
                        .map { "${it.pluginId.substringAfterLast('.')}: ${it.summary}" }))
                val n = doneCount.incrementAndGet()
                eventBus.emit(ScanEvent.Progress(n, hosts.size, host, foundCount.get()))
                if (n % checkpointEvery == 0 || n == hosts.size) {
                    val cp = CheckpointRecord(scanId, configHash = configHash, cursorIndex = n, totalHosts = hosts.size, completedHosts = completedSet.toMutableList())
                    saveCheckpoint(cp)
                    eventBus.emit(ScanEvent.CheckpointSaved(scanId, cp.cursorIndex))
                }
            }

        val byHost = results.associateBy { it.host }
        val ordered = hosts.mapNotNull { h -> byHost[h] }
        history.put(scanId, ordered)
        val wall = System.currentTimeMillis() - t0
        val counts = ordered.groupingBy { it.report.verdict.name }.eachCount()
        LocalMetricsStore.recordScan(ScanTiming(scanId, profile.name, ordered.size, wall, counts, 0))
        eventBus.emit(ScanEvent.ScanFinished(scanId, ordered.size, wall))
        eventBus.emit(ScanEvent.LogEmitted("SYSTEM", "finished scan=$scanId hosts=${ordered.size} wallMs=$wall"))
        lastMeta[scanId] = Meta(configHash, profile.name, startedAt, Instant.now().toString())
        return ordered
    }

    data class CidrScanSummary(
        val scanId: String, val rangeSpec: String, val total: Long,
        val scanned: Long, val aliveFound: Long, val hits: List<HostScanResult>, val wallMs: Long
    )

    /**
     * Streams a CIDR range of any size (see [CidrRangeEngine] — no /24-style
     * cap) through the scanner without ever materializing the address list.
     *
     * Two independently-bounded concurrent stages, chained as flows so at
     * most `concurrency` addresses are ever "in flight" at once regardless of
     * how large [range] is:
     *   1. precheck (cheap TCP connect on [ports]) + rolling per-/24 alias
     *      dedupe (same 80%-cap heuristic as [AliasPrefixDeduper], applied
     *      on the fly instead of after materializing a full list)
     *   2. full DAG scan (all plugins) — only for hosts that passed stage 1
     *
     * Progress/checkpoint cadence widen automatically for large ranges via
     * [CidrRangeEngine.reportCadence] / [checkpointCadence] so a /8 doesn't
     * flood the event bus or the checkpoint file with millions of writes.
     * Resuming uses a numeric cursor ([CidrCheckpointRecord]), not a stored
     * host list, so resume cost doesn't grow with range size either.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun scanCidrRange(
        range: CidrRangeEngine.Range,
        scanId: String = UUID.randomUUID().toString().take(8),
        resume: Boolean = false,
        ports: List<Int> = settings.scanPorts.ifEmpty { listOf(443, 80) }
    ): CidrScanSummary {
        val t0 = System.currentTimeMillis()
        val configHash = settings.configHash()
        var startAt = 0L
        var aliveSoFar = 0L
        if (resume) {
            val cp = cidrCheckpointStore.get(scanId)
            if (cp != null) {
                if (cp.configHash != configHash) {
                    eventBus.emit(ScanEvent.LogEmitted("ERROR", "config drift — refuse resume"))
                    return CidrScanSummary(scanId, range.spec, range.total, 0, 0, emptyList(), 0)
                }
                startAt = cp.cursor; aliveSoFar = cp.aliveFound
                eventBus.emit(ScanEvent.LogEmitted("SYSTEM", "resuming cidr=$scanId @$startAt/${range.total}"))
            }
        }
        val concurrency = CidrRangeEngine.effectiveConcurrency(range.total, settings.concurrency)
        val reportEvery = CidrRangeEngine.reportCadence(range.total)
        val checkpointEvery = CidrRangeEngine.checkpointCadence(range.total)
        eventBus.emit(ScanEvent.LogEmitted("SYSTEM",
            "cidr=$scanId range=${range.spec} total=${range.total} concurrency=$concurrency ports=$ports"))

        val plugins = PluginRegistry.createAll(settings)
        val done = AtomicLong(startAt)
        val alive = AtomicLong(aliveSoFar)
        val hits = CopyOnWriteArrayList<HostScanResult>()
        val aliasSeen = ConcurrentHashMap<String, AtomicInteger>()
        val aliasKept = ConcurrentHashMap<String, AtomicInteger>()
        val precheckTimeout = settings.precheckTimeoutMs.toInt().coerceAtLeast(200)

        val candidateHosts: Flow<String> = CidrRangeEngine.stream(range, startAt).asFlow()
            .flatMapMerge(concurrency) { host ->
                flow {
                    val d = done.incrementAndGet()
                    val alivePort = ports.firstOrNull { p -> TcpConnect.isAlive(host, p, precheckTimeout) }
                    if (d % reportEvery == 0L || d == range.total) {
                        eventBus.emit(ScanEvent.RangeProgress(scanId, d, range.total, alive.get(), host))
                    }
                    if (d % checkpointEvery == 0L) {
                        cidrCheckpointStore.save(CidrCheckpointRecord(scanId, range.spec, configHash, d, range.total, alive.get()))
                    }
                    if (alivePort != null) {
                        val prefix24 = host.substringBeforeLast(".")
                        val seen = aliasSeen.getOrPut(prefix24) { AtomicInteger(0) }.incrementAndGet()
                        val kept = aliasKept.getOrPut(prefix24) { AtomicInteger(0) }
                        val cap = (seen * 0.80).toInt().coerceAtLeast(1)
                        if (kept.get() < cap) { kept.incrementAndGet(); emit(host) }
                    }
                }
            }

        candidateHosts
            .flatMapMerge(concurrency) { host ->
                flow {
                    val dag = PluginDagExecutor(plugins)
                    emit(scanOne(host, dag))
                }
            }
            .collect { result ->
                alive.incrementAndGet()
                hits += result
                applyHole(result.host, result.report.verdict, result.report.confidence)
                eventBus.emit(ScanEvent.HostVerdict(result.host, result.report,
                    result.pluginResults.filter { it.signal.polarity != SignalPolarity.ABSTAIN }
                        .map { "${it.pluginId.substringAfterLast('.')}: ${it.summary}" }))
            }

        cidrCheckpointStore.save(CidrCheckpointRecord(scanId, range.spec, configHash, range.total, range.total, alive.get()))
        val wall = System.currentTimeMillis() - t0
        eventBus.emit(ScanEvent.RangeProgress(scanId, range.total, range.total, alive.get(), null))
        eventBus.emit(ScanEvent.ScanFinished(scanId, hits.size, wall))
        eventBus.emit(ScanEvent.LogEmitted("SYSTEM",
            "finished cidr=$scanId scanned=${range.total - startAt} alive=${alive.get()} wallMs=$wall"))
        return CidrScanSummary(scanId, range.spec, range.total, range.total - startAt, alive.get(), hits, wall)
    }

    suspend fun scanOne(host: String, dag: PluginDagExecutor? = null): HostScanResult {
        val plugins = PluginRegistry.createAll(settings)
        val executor = dag ?: PluginDagExecutor(plugins)
        val ctx = ScanContext(profile = profile, timeoutMs = settings.timeoutMs)
        // Prefill temporal hole metadata for timeconsistency plugin
        try {
            val prev = (database?.holes?.list() ?: holeStore.list()).firstOrNull { it.host == host.trim() }
            if (prev != null) {
                ctx.put("hole.lastConfirmedAt", prev.lastConfirmedAt)
                ctx.put("hole.lastVerdict", prev.lastVerdict)
            }
        } catch (_: Exception) {}
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
