package com.mrscanner.omega
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.isVisible
import com.mrscanner.omega.core.cli.*
import com.mrscanner.omega.core.cli.commands.CommandFactory
import com.mrscanner.omega.core.eventbus.ScanEvent
import com.mrscanner.omega.core.plugin.PluginRegistry
import com.mrscanner.omega.core.plugin.SignalPolarity
import com.mrscanner.omega.core.plugin.Verdict
import com.mrscanner.omega.network.AndroidNetworkProfile
import kotlinx.coroutines.*

class MainActivity : AppCompatActivity() {
    private lateinit var content: FrameLayout
    private var scanJob: Job? = null
    private var termBusy = false
    private val tabButtons = mutableListOf<Button>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        OmegaApp.instance.engine.profile = AndroidNetworkProfile.detect(this)
        content = findViewById(R.id.content)
        val home = findViewById<Button>(R.id.tabHome)
        val scan = findViewById<Button>(R.id.tabScan)
        val term = findViewById<Button>(R.id.tabTerm)
        val about = findViewById<Button>(R.id.tabAbout)
        tabButtons.addAll(listOf(home, scan, term, about))
        home.setOnClickListener { selectTab(0); showHome() }
        scan.setOnClickListener { selectTab(1); showScan() }
        term.setOnClickListener { selectTab(2); showTerminal() }
        about.setOnClickListener { selectTab(3); showAbout() }
        selectTab(0); showHome()
    }
    override fun onDestroy() { super.onDestroy(); scope.cancel() }
    private fun selectTab(i: Int) {
        tabButtons.forEachIndexed { idx, b ->
            b.setBackgroundColor(if (idx == i) Color.parseColor("#5B8CFF") else Color.parseColor("#2A3550"))
        }
    }
    private fun inflate(layout: Int): View {
        content.removeAllViews(); return layoutInflater.inflate(layout, content, true)
    }
    private fun showHome() {
        val root = inflate(R.layout.fragment_home)
        val hostInput = root.findViewById<EditText>(R.id.hostInput)
        val btn = root.findViewById<Button>(R.id.btnScan)
        val progress = root.findViewById<ProgressBar>(R.id.progress)
        val status = root.findViewById<TextView>(R.id.status)
        val verdict = root.findViewById<TextView>(R.id.verdict)
        val conf = root.findViewById<TextView>(R.id.confidence)
        val expl = root.findViewById<TextView>(R.id.explanation)
        root.findViewById<TextView>(R.id.profileLabel).text =
            "profile=${OmegaApp.instance.engine.profile} plugins=${PluginRegistry.createAll(OmegaApp.instance.settings).size}"
        btn.setOnClickListener {
            val host = hostInput.text?.toString()?.trim().orEmpty(); if (host.isEmpty()) return@setOnClickListener
            btn.isEnabled = false; progress.isVisible = true; status.text = "Scanning $host..."
            scope.launch {
                try {
                    val r = OmegaApp.instance.engine.scanOne(host)
                    verdict.text = r.report.verdict.name
                    verdict.setTextColor(colorFor(r.report.verdict))
                    conf.text = "confidence=${"%.2f".format(r.report.confidence)} logOdds=${"%.2f".format(r.report.logOdds)}"
                    val active = r.pluginResults.filter { it.signal.polarity != SignalPolarity.ABSTAIN }
                        .joinToString("\n") { "- ${it.pluginId.substringAfterLast('.')}: ${it.summary}" }
                    expl.text = r.report.explanation + "\n\n" + active
                    status.text = "Done — ${r.pluginResults.size} plugins"
                } catch (e: Exception) { status.text = "Error: ${e.message}" }
                finally { btn.isEnabled = true; progress.isVisible = false }
            }
        }
    }
    private fun showScan() {
        val root = inflate(R.layout.fragment_scan)
        val hostsInput = root.findViewById<EditText>(R.id.hostsInput)
        val btnStart = root.findViewById<Button>(R.id.btnStart)
        val btnStop = root.findViewById<Button>(R.id.btnStop)
        val bar = root.findViewById<ProgressBar>(R.id.scanProgress)
        val status = root.findViewById<TextView>(R.id.scanStatus)
        val results = root.findViewById<TextView>(R.id.results)
        btnStop.setOnClickListener { scanJob?.cancel(); status.text = "Cancelled"; btnStart.isEnabled = true }
        btnStart.setOnClickListener {
            val hosts = hostsInput.text?.toString().orEmpty().lines().map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }.distinct()
            if (hosts.isEmpty()) { status.text = "No hosts"; return@setOnClickListener }
            btnStart.isEnabled = false; results.text = ""; status.text = "Scanning ${hosts.size}..."; bar.progress = 0
            scanJob = scope.launch {
                val engine = OmegaApp.instance.engine
                val collector = launch {
                    engine.eventBus.events.collect { ev ->
                        when (ev) {
                            is ScanEvent.HostVerdict -> results.append("${mark(ev.report.verdict)} ${ev.host} conf=${"%.2f".format(ev.report.confidence)} ${ev.report.verdict}\n")
                            is ScanEvent.Progress -> { bar.progress = if (ev.total == 0) 0 else ev.done * 100 / ev.total; status.text = "${ev.done}/${ev.total} ${ev.host ?: ""}" }
                            is ScanEvent.ScanFinished -> status.text = "Done ${ev.hostCount} hosts ${ev.wallMs}ms id=${ev.scanId}"
                            else -> {}
                        }
                    }
                }
                try { engine.scanHosts(hosts) } catch (e: Exception) { status.text = "Error: ${e.message}" }
                finally { collector.cancel(); btnStart.isEnabled = true }
            }
        }
    }
    private fun showTerminal() {
        val root = inflate(R.layout.fragment_terminal)
        val out = root.findViewById<TextView>(R.id.termOut)
        val input = root.findViewById<EditText>(R.id.termIn)
        val btn = root.findViewById<Button>(R.id.btnRun)
        val scroll = root.findViewById<ScrollView>(R.id.termScroll)
        val session = CliSession(settings = OmegaApp.instance.settings)
        val interpreter = CliInterpreter(CommandFactory.defaultRegistry(), OmegaApp.instance.engine)
        fun append(kind: CliOutputLine.Kind, text: String) {
            val p = when (kind) {
                CliOutputLine.Kind.STDERR -> "! "; CliOutputLine.Kind.SYSTEM -> ". "
                CliOutputLine.Kind.VERDICT -> "* "; else -> ""
            }
            out.append(p + text + "\n"); scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
        }
        fun runCmd(cmd: String) {
            if (cmd.isBlank() || termBusy) return
            termBusy = true; btn.isEnabled = false; append(CliOutputLine.Kind.STDOUT, "> $cmd"); input.setText("")
            scope.launch {
                try { interpreter.execute(cmd, session).collect { append(it.kind, it.text) } }
                catch (e: Exception) { append(CliOutputLine.Kind.STDERR, e.message ?: "error") }
                finally { termBusy = false; btn.isEnabled = true }
            }
        }
        btn.setOnClickListener { runCmd(input.text?.toString().orEmpty()) }
        input.setOnEditorActionListener { _, _, _ -> runCmd(input.text?.toString().orEmpty()); true }
    }
    private fun showAbout() {
        val root = inflate(R.layout.fragment_about)
        val settings = OmegaApp.instance.settings
        val active = PluginRegistry.createAll(settings).size
        root.findViewById<TextView>(R.id.aboutBody).text = buildString {
            appendLine("v${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            appendLine("Engine: ${BuildConfig.ENGINE}")
            appendLine("Catalog: ${BuildConfig.PLUGIN_CATALOG_SIZE} Active: $active")
            appendLine("App ID: ${BuildConfig.APPLICATION_ID}")
            appendLine("configHash: ${settings.configHash()}")
            appendLine("profile: ${OmegaApp.instance.engine.profile}")
            appendLine()
            appendLine("Creator: Mr Ali")
            appendLine("Telegram: t.me/Mr_Ali_2025")
            appendLine("Channel: t.me/Ali_shortcuts")
            appendLine("Email: ali.hekmati2026@gmail.com")
            appendLine()
            appendLine(getString(R.string.engine_info))
        }
    }
    private fun colorFor(v: Verdict) = when (v) {
        Verdict.CONFIRMED_CANDIDATE -> Color.parseColor("#3DDC97")
        Verdict.CONFIRMED_NOT_VULNERABLE -> Color.parseColor("#FF6B6B")
        Verdict.WEAK_SIGNAL_ONLY -> Color.parseColor("#B0B8C8")
    }
    private fun mark(v: Verdict) = when (v) {
        Verdict.CONFIRMED_CANDIDATE -> "[+]"; Verdict.CONFIRMED_NOT_VULNERABLE -> "[-]"; else -> "[?]"
    }
}
