package com.mrscanner.omega.core.cli
import com.mrscanner.omega.core.eventbus.EventBus
import com.mrscanner.omega.core.eventbus.ScanEvent
import com.mrscanner.omega.core.scheduler.ScanEngine
import com.mrscanner.omega.core.settings.ConsoleSettings
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

data class CliArgs(val raw: List<String>, val flags: Map<String, String>, val positionals: List<String>) {
    fun flag(name: String) = flags[name]
    fun bool(name: String, default: Boolean = false): Boolean {
        if (!flags.containsKey(name) && raw.none { it == "--$name" || it == "-$name" }) return default
        val v = flags[name] ?: return true
        return v != "false" && v != "0" && v != "no"
    }
    companion object {
        fun parse(tokens: List<String>): CliArgs {
            val flags = linkedMapOf<String, String>(); val pos = mutableListOf<String>(); var i = 0
            while (i < tokens.size) {
                val t = tokens[i]
                when {
                    t.startsWith("--") && t.contains("=") -> flags[t.removePrefix("--").substringBefore("=")] = t.substringAfter("=")
                    t.startsWith("--") -> {
                        val k = t.removePrefix("--"); val n = tokens.getOrNull(i + 1)
                        if (n != null && !n.startsWith("-")) { flags[k] = n; i++ } else flags[k] = "true"
                    }
                    else -> pos += t
                }
                i++
            }
            return CliArgs(tokens, flags, pos)
        }
    }
}

data class CliOutputLine(val kind: Kind, val text: String, val ts: Long = System.currentTimeMillis()) {
    enum class Kind { STDOUT, STDERR, PROGRESS, VERDICT, SYSTEM }
    fun render() = when (kind) {
        Kind.STDERR -> "! $text"; Kind.SYSTEM -> ". $text"; else -> text
    }
}

class CliSession(val settings: ConsoleSettings, var scanId: String? = null, val workingDirLabel: String = "~")

interface CliCommand {
    val name: String
    val aliases: List<String> get() = emptyList()
    val usage: String
    val help: String
    suspend fun run(args: CliArgs, session: CliSession, engine: ScanEngine): Flow<CliOutputLine>
}

class CliCommandRegistry(commands: List<CliCommand>) {
    private val map = commands.flatMap { c -> (listOf(c.name) + c.aliases).map { it.lowercase() to c } }.toMap()
    fun get(name: String) = map[name.lowercase()]
    fun all() = map.values.distinctBy { it.name }.sortedBy { it.name }
}

class CliInterpreter(private val registry: CliCommandRegistry, private val engine: ScanEngine, private val eventBus: EventBus = engine.eventBus) {
    suspend fun execute(raw: String, session: CliSession): Flow<CliOutputLine> = flow {
        val trimmed = raw.trim(); if (trimmed.isEmpty()) return@flow
        if (trimmed == "exit" || trimmed == "quit") { emit(CliOutputLine(CliOutputLine.Kind.SYSTEM, "bye")); return@flow }
        val tokens = tokenize(trimmed)
        val cmd = registry.get(tokens.first())
        if (cmd == null) { emit(CliOutputLine(CliOutputLine.Kind.STDERR, "unknown command: ${tokens.first()} — try 'help'")); return@flow }
        cmd.run(CliArgs.parse(tokens.drop(1)), session, engine).collect { line ->
            emit(line); eventBus.tryEmit(ScanEvent.LogEmitted(line.kind.name, line.text, line.ts))
        }
    }
    companion object {
        fun tokenize(input: String): List<String> {
            val out = mutableListOf<String>(); val cur = StringBuilder(); var sq = false; var dq = false
            for (ch in input) {
                when {
                    ch == '\'' && !dq -> sq = !sq
                    ch == '"' && !sq -> dq = !dq
                    ch.isWhitespace() && !sq && !dq -> { if (cur.isNotEmpty()) { out += cur.toString(); cur.clear() } }
                    else -> cur.append(ch)
                }
            }
            if (cur.isNotEmpty()) out += cur.toString()
            return out
        }
    }
}
