package com.mrscanner.omega.cli
import com.mrscanner.omega.core.cli.CliInterpreter
import com.mrscanner.omega.core.cli.CliSession
import com.mrscanner.omega.core.cli.commands.CommandFactory
import com.mrscanner.omega.core.db.CheckpointStore
import com.mrscanner.omega.core.db.HoleAgeStore
import com.mrscanner.omega.core.db.OmegaDatabase
import com.mrscanner.omega.core.network.DnsPerformanceStore
import com.mrscanner.omega.core.plugin.NetworkProfile
import com.mrscanner.omega.core.scheduler.ScanEngine
import com.mrscanner.omega.core.settings.ConsoleSettings
import kotlinx.coroutines.runBlocking
import java.io.File

fun main(args: Array<String>) = runBlocking {
    val home = File(System.getProperty("user.home"), ".mr-scanner-omega").apply { mkdirs() }
    val settings = ConsoleSettings()
    val dataDir = File(home, "data")
    val db = OmegaDatabase.open(dataDir)
    val engine = ScanEngine(settings, holeStore = HoleAgeStore(dataDir),
        checkpointStore = CheckpointStore(dataDir), dnsPerf = DnsPerformanceStore(File(dataDir, "dns-performance.tsv")),
        profile = NetworkProfile.WIFI_UNMETERED, database = db)
    val interpreter = CliInterpreter(CommandFactory.defaultRegistry(), engine)
    val session = CliSession(settings)
    println("""
+==================================================+
|  Mr. Scanner Ω  v2.2.0-omega                     |
|  ConfidenceEngineV3 · 41-plugin architecture     |
|  Engine: Confidence v3 (symmetric log-odds)      |
|  Creator: Mr Ali · t.me/Mr_Ali_2025              |
+==================================================+
""".trimIndent())
    if (args.isNotEmpty()) {
        interpreter.execute(args.joinToString(" "), session).collect { println(it.render()) }
        return@runBlocking
    }
    println("Type 'help' for commands, 'exit' to quit.")
    while (true) {
        print("O > "); System.out.flush()
        val line = readLine() ?: break
        if (line.trim() in listOf("exit", "quit")) { println("bye"); break }
        try { interpreter.execute(line, session).collect { println(it.render()) } }
        catch (e: Exception) { System.err.println("! error: ${e.message}") }
    }
}
