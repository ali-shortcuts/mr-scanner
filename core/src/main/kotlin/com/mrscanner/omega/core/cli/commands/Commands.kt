package com.mrscanner.omega.core.cli.commands
import com.mrscanner.omega.core.cli.*
import com.mrscanner.omega.core.eventbus.ScanEvent
import com.mrscanner.omega.core.intelligence.ConfidenceEngineV3
import com.mrscanner.omega.core.metrics.LocalMetricsStore
import com.mrscanner.omega.core.plugin.*
import com.mrscanner.omega.core.scheduler.ScanEngine
import com.mrscanner.omega.core.apkanalyzer.ApkStaticAnalyzer
import com.mrscanner.omega.core.scheduler.CidrRangeEngine
import com.mrscanner.omega.core.update.UpdateChecker
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import java.io.File
import java.util.UUID

object CommandFactory {
    fun defaultRegistry() = CliCommandRegistry(listOf(
        HelpCmd(), FullScanCmd(), HostScanCmd(), FragmentCmd(), SniCmd(), SelfTestCmd(),
        SetCmd(), GetCmd(), ExportCmd(), HolesCmd(), CheckpointCmd(), PluginsCmd(),
        ReverifyCmd(), DiffCmd(), MetricsCmd(), CidrCmd(), ApkScanCmd(), UpdateCmd()
    ))
}

private fun out(t: String) = CliOutputLine(CliOutputLine.Kind.STDOUT, t)
private fun err(t: String) = CliOutputLine(CliOutputLine.Kind.STDERR, t)
private fun sys(t: String) = CliOutputLine(CliOutputLine.Kind.SYSTEM, t)
private fun verd(t: String) = CliOutputLine(CliOutputLine.Kind.VERDICT, t)
private fun mark(v: Verdict) = when (v) {
    Verdict.CONFIRMED_CANDIDATE -> "[+]"; Verdict.CONFIRMED_NOT_VULNERABLE -> "[-]"; else -> "[?]"
}
private fun resolveHosts(args: CliArgs): List<String> {
    val hosts = mutableListOf<String>()
    for (p in args.positionals) {
        val f = File(p)
        if (f.isFile) hosts += f.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        else hosts += p
    }
    return hosts.distinct()
}

class HelpCmd : CliCommand {
    override val name = "help"; override val aliases = listOf("?"); override val usage = "help [cmd]"; override val help = "List commands"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val reg = CommandFactory.defaultRegistry(); val which = args.positionals.firstOrNull()
        if (which == null) { emit(out("Mr Scanner Omega commands:")); reg.all().forEach { emit(out("  ${it.name.padEnd(14)} ${it.usage}")) } }
        else { val c = reg.get(which); if (c == null) emit(err("unknown")) else { emit(out("${c.name} — ${c.help}")); emit(out("usage: ${c.usage}")) } }
    }
}

class FullScanCmd : CliCommand {
    override val name = "fullscan"; override val usage = "fullscan <host|file> [--confidence] [--resume=id] [--profile=WIFI_UNMETERED]"
    override val help = "Full DAG + ConfidenceEngineV3"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = channelFlow {
        val hosts = resolveHosts(args); if (hosts.isEmpty()) { send(err(usage)); return@channelFlow }
        args.flag("profile")?.let { try { engine.profile = NetworkProfile.valueOf(it.uppercase()) } catch (_: Exception) { send(err("bad profile")) } }
        val scanId = args.flag("resume") ?: UUID.randomUUID().toString().take(8)
        session.scanId = scanId
        send(sys("fullscan id=$scanId hosts=${hosts.size} hash=${session.settings.configHash()}"))
        val collector = launch {
            engine.eventBus.events.collect { ev ->
                when (ev) {
                    is ScanEvent.HostVerdict -> {
                        send(verd("${mark(ev.report.verdict)} ${ev.host}  conf=${"%.2f".format(ev.report.confidence)}  ${ev.report.verdict}"))
                        if (args.bool("confidence", true)) send(out("           | ${ev.report.explanation}"))
                    }
                    is ScanEvent.Progress -> {
                        val pct = if (ev.total == 0) 0 else ev.done * 100 / ev.total
                        send(CliOutputLine(CliOutputLine.Kind.PROGRESS, "[$pct%] ${ev.done}/${ev.total} ${ev.host ?: ""}"))
                    }
                    is ScanEvent.CheckpointSaved -> send(sys("checkpoint @${ev.cursor}"))
                    is ScanEvent.LogEmitted -> if (ev.level == "ERROR") send(err(ev.message))
                    is ScanEvent.BudgetExceeded -> send(sys("budget skip ${ev.host}: ${ev.skippedPlugins.take(5).joinToString()}"))
                    is ScanEvent.ScanFinished -> send(sys("done wallMs=${ev.wallMs}"))
                    else -> {}
                }
            }
        }
        try { engine.scanHosts(hosts, scanId, args.flag("resume") != null) } finally { collector.cancel() }
        send(sys("export: export $scanId"))
    }
}

class HostScanCmd : CliCommand {
    override val name = "hostscan"; override val usage = "hostscan <host|file>"; override val help = "Host scan"
    override suspend fun run(a: CliArgs, s: CliSession, e: ScanEngine) = FullScanCmd().run(a, s, e)
}

class FragmentCmd : CliCommand {
    override val name = "fragment"; override val usage = "fragment <host>"; override val help = "tlsfragment + recordfragment"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val host = args.positionals.firstOrNull() ?: run { emit(err(usage)); return@flow }
        session.settings.testFragmentBypass = true
        val r = engine.scanOne(host)
        r.pluginResults.filter { it.pluginId.contains("fragment") }.forEach { emit(out("${it.pluginId}: ${it.summary} [${it.signal.polarity}]")) }
        emit(verd("${mark(r.report.verdict)} conf=${"%.2f".format(r.report.confidence)} ${r.report.verdict}"))
    }
}

class SniCmd : CliCommand {
    override val name = "sni"; override val usage = "sni --target=<host> [--candidates=a,b]"; override val help = "SNI fronting + SAN"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val host = args.flag("target") ?: args.positionals.firstOrNull() ?: run { emit(err(usage)); return@flow }
        args.flag("candidates")?.let { session.settings.sniSpoofCandidates = it.split(",").map { s -> s.trim() }.filter { s -> s.isNotEmpty() } }
        val r = engine.scanOne(host)
        r.pluginResults.filter { it.pluginId.contains("sni") }.forEach { emit(out("${it.pluginId}: ${it.summary}")) }
        emit(verd("${mark(r.report.verdict)} ${r.report.explanation}"))
    }
}

class SelfTestCmd : CliCommand {
    override val name = "selftest"; override val usage = "selftest"; override val help = "Engine self-test"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        var failed = 0
        val t1 = ConfidenceEngineV3.compute(listOf(PluginSignal("x", SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE)))
        val ok1 = t1.verdict == Verdict.CONFIRMED_CANDIDATE; emit(out("${if (ok1) "PASS" else "FAIL"} T1 DEFINITIVE support -> ${t1.verdict}")); if (!ok1) failed++
        val t2 = ConfidenceEngineV3.compute(listOf(PluginSignal("x", SignalPolarity.REFUTES_BYPASS, EvidenceClass.DEFINITIVE)))
        val ok2 = t2.verdict == Verdict.CONFIRMED_NOT_VULNERABLE; emit(out("${if (ok2) "PASS" else "FAIL"} T2 DEFINITIVE refute -> ${t2.verdict}")); if (!ok2) failed++
        val t6 = ConfidenceEngineV3.compute(emptyList())
        val ok6 = t6.verdict == Verdict.WEAK_SIGNAL_ONLY && t6.confidence == 0.5; emit(out("${if (ok6) "PASS" else "FAIL"} empty -> ${t6.verdict} conf=${t6.confidence}")); if (!ok6) failed++
        try {
            val r = engine.scanOne("example.com")
            val tlsOk = r.pluginResults.any { it.pluginId == "tls" && it.details["success"] == "true" }
            emit(out("${if (tlsOk) "PASS" else "WARN"} live tls example.com -> ${r.report.verdict} conf=${"%.2f".format(r.report.confidence)}"))
            emit(out("      snisan: ${r.pluginResults.find { it.pluginId == "plugin.host.snisan" }?.summary ?: "n/a"}"))
        } catch (e: Exception) { emit(out("WARN live: ${e.message}")) }
        try {
            val dead = engine.scanOne("invalid.invalid")
            emit(out("PASS dead-host handled -> plugins=${dead.pluginResults.size} verdict=${dead.report.verdict}"))
        } catch (e: Exception) { emit(out("FAIL dead-host: ${e.message}")); failed++ }
        emit(sys(if (failed == 0) "selftest OK" else "selftest FAILED ($failed)"))
    }
}

class SetCmd : CliCommand {
    override val name = "set"; override val usage = "set <key>=<value>"; override val help = "Update settings"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val raw = args.positionals.joinToString(" "); if (!raw.contains("=")) { emit(err(usage)); return@flow }
        val k = raw.substringBefore("=").trim(); val v = raw.substringAfter("=").trim()
        if (session.settings.setKey(k, v)) emit(out("ok $k=$v hash=${session.settings.configHash()}")) else emit(err("unknown/invalid: $k"))
    }
}

class GetCmd : CliCommand {
    override val name = "get"; override val usage = "get [key]"; override val help = "Show settings"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val key = args.positionals.firstOrNull(); val lines = session.settings.snapshotLines()
        if (key == null) lines.forEach { emit(out(it)) }
        else emit(lines.find { it.substringBefore("=").equals(key, true) }?.let { out(it) } ?: err("no such key"))
    }
}

class ExportCmd : CliCommand {
    override val name = "export"; override val usage = "export <scan-id> [--out=path]"; override val help = "Export JSON v1"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val id = args.positionals.firstOrNull() ?: session.scanId ?: run { emit(err("scan id required")); return@flow }
        val json = engine.exportJson(id) ?: run { emit(err("no scan $id")); return@flow }
        val path = args.flag("out")
        if (path != null) { File(path).writeText(json); emit(out("wrote $path (${json.length} bytes)")) } else emit(out(json))
    }
}

class HolesCmd : CliCommand {
    override val name = "holes"; override val usage = "holes [--open|--closed]"; override val help = "Hole-age list"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val openOnly = when { args.bool("open") -> true; args.bool("closed") -> false; else -> null }
        val list = engine.database?.holes?.list(openOnly) ?: engine.holeStore.list(openOnly)
        if (list.isEmpty()) emit(out("(no holes)"))
        list.forEach { h -> emit(out("${h.status.padEnd(6)} ${h.host.padEnd(40)} conf=${"%.2f".format(h.lastConfidence)} ${h.lastVerdict}")) }
    }
}

class CheckpointCmd : CliCommand {
    override val name = "checkpoint"; override val usage = "checkpoint list|clear <id>"; override val help = "Checkpoints"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        when (args.positionals.firstOrNull()) {
            "list", null -> {
                val all = engine.database?.checkpoints?.list() ?: engine.checkpointStore.list()
                if (all.isEmpty()) emit(out("(none)"))
                all.forEach { emit(out("${it.scanId} cursor=${it.cursorIndex}/${it.totalHosts} hash=${it.configHash}")) }
            }
            "clear" -> {
                val id = args.positionals.getOrNull(1)
                if (id == null) emit(err("id required")) else { (engine.database?.checkpoints ?: engine.checkpointStore).let { /* type mismatch */ }
                    engine.database?.checkpoints?.clear(id) ?: engine.checkpointStore.clear(id); emit(out("cleared $id")) }
            }
            else -> emit(err(usage))
        }
    }
}

class PluginsCmd : CliCommand {
    override val name = "plugins"; override val usage = "plugins"; override val help = "Plugin catalog"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val active = PluginRegistry.createAll(session.settings).map { it.id }.toSet()
        PluginRegistry.catalog().forEach { e ->
            val m = if (e.id in active) "*" else " "
            emit(out("$m ${e.id.padEnd(36)} ${e.group.padEnd(10)} ${e.evidence.padEnd(12)} ${e.name}"))
        }
        emit(sys("* = active (${active.size} loaded) catalog=${PluginRegistry.catalog().size}"))
    }
}

class ReverifyCmd : CliCommand {
    override val name = "reverify"; override val usage = "reverify <scan-id>"; override val help = "Re-run previous scan hosts"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val id = args.positionals.firstOrNull() ?: run { emit(err(usage)); return@flow }
        val prev = engine.history.get(id) ?: run { emit(err("unknown $id")); return@flow }
        val hosts = prev.map { it.host }; emit(sys("reverify ${hosts.size} from $id"))
        FullScanCmd().run(CliArgs(hosts, emptyMap(), hosts), session, engine).collect { emit(it) }
    }
}

class DiffCmd : CliCommand {
    override val name = "diff"; override val usage = "diff <scanA> <scanB>"; override val help = "Diff verdicts"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val a = args.positionals.getOrNull(0); val b = args.positionals.getOrNull(1)
        if (a == null || b == null) { emit(err(usage)); return@flow }
        val ra = engine.history.get(a); val rb = engine.history.get(b)
        if (ra == null || rb == null) { emit(err("missing scan")); return@flow }
        val mb = rb.associateBy { it.host }; var m = 0
        for (ha in ra) {
            val hb = mb[ha.host]
            if (hb == null) { emit(out("ONLY_A ${ha.host} ${ha.report.verdict}")); m++ }
            else if (ha.report.verdict != hb.report.verdict) { emit(out("MISMATCH ${ha.host} ${ha.report.verdict} vs ${hb.report.verdict}")); m++ }
        }
        emit(sys("diff mismatches=$m"))
    }
}

class MetricsCmd : CliCommand {
    override val name = "metrics"; override val usage = "metrics"; override val help = "Local metrics"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        LocalMetricsStore.summary().forEach { emit(out(it)) }
        engine.history.ids().takeLast(5).forEach { id ->
            val hs = engine.history.get(id).orEmpty()
            emit(out("scan $id hosts=${hs.size} ${hs.groupingBy { it.report.verdict }.eachCount()}"))
        }
        val holes = engine.holeStore.list()
        emit(out("holes_open=${holes.count { it.status == "open" }} closed=${holes.count { it.status == "closed" }}"))
    }
}

class CidrCmd : CliCommand {
    override val name = "cidr"
    override val usage = "cidr <a.b.c.0/prefix|file> [<more ranges...>] [--resume=id] [--ports=443,80]"
    override val help = "Stream-scan CIDR range(s) of ANY size (/0-/32) — no host-count cap, streamed not materialized"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = channelFlow {
        // Ranges can come as direct positionals ("1.2.3.0/16") or as a file
        // with one CIDR spec (or plain host, treated as /32) per line.
        val specs = mutableListOf<String>()
        for (p in args.positionals) {
            val f = File(p)
            if (f.isFile) specs += f.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
            else specs += p
        }
        if (specs.isEmpty()) { send(err(usage)); return@channelFlow }

        val ports = args.flag("ports")?.split(",")?.mapNotNull { it.trim().toIntOrNull() } ?: session.settings.scanPorts
        val resumeId = args.flag("resume")

        for (spec in specs) {
            val normalized = if (!spec.contains("/")) "$spec/32" else spec
            val range = CidrRangeEngine.parse(normalized)
            if (range == null) { send(err("bad range: $spec")); continue }
            if (range.prefix < 8) {
                send(sys("warning: /${range.prefix} is ${range.total} hosts — this will take a very long time, proceeding anyway (no hard limit)"))
            }
            val scanId = resumeId ?: UUID.randomUUID().toString().take(8)
            session.scanId = scanId
            send(sys("cidr id=$scanId range=${range.spec} total=${range.total} hash=${session.settings.configHash()}"))
            session.settings.budgetProfileOverride = "CIDR_BULK"
            val collector = launch {
                engine.eventBus.events.collect { ev ->
                    when (ev) {
                        is ScanEvent.HostVerdict -> {
                            send(verd("${mark(ev.report.verdict)} ${ev.host}  conf=${"%.2f".format(ev.report.confidence)}  ${ev.report.verdict}"))
                            if (args.bool("confidence", true)) send(out("           | ${ev.report.explanation}"))
                        }
                        is ScanEvent.RangeProgress -> {
                            val pct = if (ev.total == 0L) 0 else (ev.done * 100 / ev.total)
                            val remaining = ev.total - ev.done
                            send(CliOutputLine(CliOutputLine.Kind.PROGRESS,
                                "[$pct%] scanned=${ev.done}/${ev.total} remaining=$remaining alive=${ev.aliveFound} ${ev.currentHost ?: ""}"))
                        }
                        is ScanEvent.CheckpointSaved -> send(sys("checkpoint @${ev.cursor}"))
                        is ScanEvent.LogEmitted -> if (ev.level == "ERROR") send(err(ev.message)) else send(sys(ev.message))
                        is ScanEvent.BudgetExceeded -> send(sys("budget skip ${ev.host}: ${ev.skippedPlugins.take(5).joinToString()}"))
                        is ScanEvent.ScanFinished -> send(sys("done wallMs=${ev.wallMs}"))
                        else -> {}
                    }
                }
            }
            try {
                val summary = engine.scanCidrRange(range, scanId, resumeId != null, ports)
                send(sys("range done: ${summary.rangeSpec} scanned=${summary.scanned} alive=${summary.aliveFound} wallMs=${summary.wallMs}"))
            } finally {
                collector.cancel()
                session.settings.budgetProfileOverride = null
            }
        }
    }
}


class ApkScanCmd : CliCommand {
    override val name = "apk"; override val usage = "apk <path-to.apk>"; override val help = "Static APK analyzer"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val path = args.positionals.firstOrNull() ?: run { emit(err(usage)); return@flow }
        try {
            val report = ApkStaticAnalyzer.analyze(path)
            ApkStaticAnalyzer.format(report).lines().forEach { emit(out(it)) }
            val crit = report.findings.count { it.severity == "CRITICAL" || it.severity == "HIGH" }
            emit(sys("apk analysis done findings=${report.findings.size} highOrCrit=$crit"))
        } catch (e: Exception) {
            emit(err(e.message ?: "apk fail"))
        }
    }
}

class UpdateCmd : CliCommand {
    override val name = "update"; override val usage = "update [--repo=owner/name]"; override val help = "Check GitHub Releases for updates"
    override suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine) = flow {
        val repo = args.flag("repo") ?: "ali-shortcuts/mr-scanner"
        val checker = UpdateChecker(repo, "2.2.0-omega")
        val info = checker.check()
        if (info == null) emit(out("no update (or check failed)"))
        else {
            emit(out("update available: ${info.tag}"))
            emit(out("download: ${info.downloadUrl ?: "(see releases)"}"))
        }
    }
}

