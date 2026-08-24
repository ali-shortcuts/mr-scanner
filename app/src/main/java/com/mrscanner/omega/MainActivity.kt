package com.mrscanner.omega

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import com.mrscanner.omega.core.cli.CliInterpreter
import com.mrscanner.omega.core.cli.CliOutputLine
import com.mrscanner.omega.core.cli.CliSession
import com.mrscanner.omega.core.cli.commands.CommandFactory
import com.mrscanner.omega.core.eventbus.ScanEvent
import com.mrscanner.omega.core.plugin.PluginRegistry
import com.mrscanner.omega.core.plugin.SignalPolarity
import com.mrscanner.omega.core.plugin.Verdict
import com.mrscanner.omega.network.AndroidNetworkProfile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Main shell — branding & About match architecture §9 exactly.
 * Verdict chip colors match architecture §7.4.
 */
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
        selectTab(0)
        showHome()
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    private fun selectTab(i: Int) {
        tabButtons.forEachIndexed { idx, b ->
            b.setBackgroundResource(
                if (idx == i) R.drawable.bg_tab_active else R.drawable.bg_tab_inactive
            )
        }
    }

    private fun inflate(layout: Int): View {
        content.removeAllViews()
        return layoutInflater.inflate(layout, content, true)
    }

    private fun openUrl(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (_: Exception) { /* no browser */ }
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
        val verdictCard = root.findViewById<View>(R.id.verdictCard)
        root.findViewById<TextView>(R.id.profileLabel).text =
            "profile=${OmegaApp.instance.engine.profile} · plugins=${PluginRegistry.createAll(OmegaApp.instance.settings).size}"

        btn.setOnClickListener {
            val host = hostInput.text?.toString()?.trim().orEmpty()
            if (host.isEmpty()) return@setOnClickListener
            btn.isEnabled = false
            progress.isVisible = true
            status.text = "Scanning $host…"
            scope.launch {
                try {
                    val r = OmegaApp.instance.engine.scanOne(host)
                    verdict.text = r.report.verdict.name
                    verdict.setTextColor(colorFor(r.report.verdict))
                    verdictCard?.setBackgroundResource(chipBgFor(r.report.verdict))
                    conf.text =
                        "confidence = ${"%.2f".format(r.report.confidence)}   logOdds = ${"%.2f".format(r.report.logOdds)}"
                    val active = r.pluginResults
                        .filter { it.signal.polarity != SignalPolarity.ABSTAIN }
                        .joinToString("\n") { "• ${it.pluginId.substringAfterLast('.')}: ${it.summary}" }
                    expl.text = r.report.explanation + if (active.isNotEmpty()) "\n\n$active" else ""
                    status.text = "Done — ${r.pluginResults.size} plugin results"
                } catch (e: Exception) {
                    status.text = "Error: ${e.message}"
                } finally {
                    btn.isEnabled = true
                    progress.isVisible = false
                }
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

        btnStop.setOnClickListener {
            scanJob?.cancel()
            status.text = "Cancelled"
            btnStart.isEnabled = true
        }
        btnStart.setOnClickListener {
            val hosts = hostsInput.text?.toString().orEmpty().lines()
                .map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.distinct()
            if (hosts.isEmpty()) {
                status.text = "No hosts"
                return@setOnClickListener
            }
            btnStart.isEnabled = false
            results.text = ""
            status.text = "Scanning ${hosts.size}…"
            bar.progress = 0
            scanJob = scope.launch {
                val engine = OmegaApp.instance.engine
                val collector = launch {
                    engine.eventBus.events.collect { ev ->
                        when (ev) {
                            is ScanEvent.HostVerdict -> {
                                results.append(
                                    "${mark(ev.report.verdict)} ${ev.host}  conf=${"%.2f".format(ev.report.confidence)}  ${ev.report.verdict}\n"
                                )
                            }
                            is ScanEvent.Progress -> {
                                bar.progress = if (ev.total == 0) 0 else ev.done * 100 / ev.total
                                status.text = "${ev.done}/${ev.total} ${ev.host ?: ""}"
                            }
                            is ScanEvent.ScanFinished -> {
                                status.text = "Done ${ev.hostCount} hosts · ${ev.wallMs}ms · id=${ev.scanId}"
                            }
                            else -> {}
                        }
                    }
                }
                try {
                    engine.scanHosts(hosts)
                } catch (e: Exception) {
                    status.text = "Error: ${e.message}"
                } finally {
                    collector.cancel()
                    btnStart.isEnabled = true
                }
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
                CliOutputLine.Kind.STDERR -> "! "
                CliOutputLine.Kind.SYSTEM -> "· "
                CliOutputLine.Kind.VERDICT -> "★ "
                else -> ""
            }
            out.append(p + text + "\n")
            scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
        }

        fun runCmd(cmd: String) {
            if (cmd.isBlank() || termBusy) return
            termBusy = true
            btn.isEnabled = false
            append(CliOutputLine.Kind.STDOUT, "Ω > $cmd")
            input.setText("")
            scope.launch {
                try {
                    interpreter.execute(cmd, session).collect { append(it.kind, it.text) }
                } catch (e: Exception) {
                    append(CliOutputLine.Kind.STDERR, e.message ?: "error")
                } finally {
                    termBusy = false
                    btn.isEnabled = true
                }
            }
        }
        btn.setOnClickListener { runCmd(input.text?.toString().orEmpty()) }
        input.setOnEditorActionListener { _, _, _ ->
            runCmd(input.text?.toString().orEmpty()); true
        }
    }

    /**
     * About screen — architecture §9 fields exactly:
     * Name, App ID, versions, creator, telegram, channel, email, socials, disclaimer,
     * plus App Specs & Engine Info card.
     */
    private fun showAbout() {
        val root = inflate(R.layout.fragment_about)
        val settings = OmegaApp.instance.settings
        val active = PluginRegistry.createAll(settings).size
        val catalog = PluginRegistry.catalog().size

        root.findViewById<TextView>(R.id.aboutVersionLine).text =
            "v${BuildConfig.VERSION_NAME}  ·  versionCode ${BuildConfig.VERSION_CODE}"

        // App Specs & Engine Info — exact lines from §9 after merge
        root.findViewById<TextView>(R.id.aboutSpecsBody).text = buildString {
            appendLine(getString(R.string.engine_info))
            appendLine(getString(R.string.engine_plugins))
            appendLine(getString(R.string.engine_transport))
            appendLine()
            appendLine("Name: Mr. Scanner Ω")
            appendLine("Application ID: ${BuildConfig.APPLICATION_ID}")
            appendLine("versionName: ${BuildConfig.VERSION_NAME}")
            appendLine("versionCode: ${BuildConfig.VERSION_CODE}")
            appendLine("Architecture: Ω-2.0.0-FINAL")
            appendLine("Catalog entries: $catalog")
            appendLine("Active plugins (settings): $active")
            appendLine("configHash: ${settings.configHash()}")
            appendLine("Network profile: ${OmegaApp.instance.engine.profile}")
            appendLine("minSdk 26 · targetSdk 34")
        }

        root.findViewById<Button>(R.id.btnTelegram).setOnClickListener {
            openUrl(getString(R.string.telegram_personal_url))
        }
        root.findViewById<Button>(R.id.btnChannel).setOnClickListener {
            openUrl(getString(R.string.telegram_channel_url))
        }
        root.findViewById<Button>(R.id.btnEmail).setOnClickListener {
            openUrl(getString(R.string.email_mailto))
        }
        root.findViewById<Button>(R.id.btnSocial).setOnClickListener {
            openUrl(getString(R.string.facebook_url))
        }
    }

    /** §7.4 verdict chip colors */
    private fun colorFor(v: Verdict): Int = when (v) {
        Verdict.CONFIRMED_CANDIDATE -> ContextCompat.getColor(this, R.color.verdict_candidate)
        Verdict.CONFIRMED_NOT_VULNERABLE -> ContextCompat.getColor(this, R.color.verdict_not_vuln)
        Verdict.WEAK_SIGNAL_ONLY -> ContextCompat.getColor(this, R.color.verdict_weak)
    }

    private fun chipBgFor(v: Verdict): Int = when (v) {
        Verdict.CONFIRMED_CANDIDATE -> R.drawable.bg_chip_candidate
        Verdict.CONFIRMED_NOT_VULNERABLE -> R.drawable.bg_chip_not_vuln
        Verdict.WEAK_SIGNAL_ONLY -> R.drawable.bg_chip_weak
    }

    private fun mark(v: Verdict): String = when (v) {
        Verdict.CONFIRMED_CANDIDATE -> "[+]"
        Verdict.CONFIRMED_NOT_VULNERABLE -> "[-]"
        Verdict.WEAK_SIGNAL_ONLY -> "[?]"
    }
}
