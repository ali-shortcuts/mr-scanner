package com.mrscanner.omega

import android.content.Intent
import android.app.Activity
import android.provider.OpenableColumns
import android.graphics.Color
import android.net.Uri
import android.widget.Toast
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.FrameLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.SeekBar
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import com.mrscanner.omega.core.cli.CliInterpreter
import com.mrscanner.omega.core.cli.CliOutputLine
import com.mrscanner.omega.core.cli.CliSession
import com.mrscanner.omega.core.cli.commands.CommandFactory
import com.mrscanner.omega.core.eventbus.ScanEvent
import com.mrscanner.omega.core.network.AfghanOperators
import com.mrscanner.omega.core.plugin.PluginRegistry
import com.mrscanner.omega.core.plugin.SignalPolarity
import com.mrscanner.omega.core.plugin.Verdict
import com.mrscanner.omega.core.scheduler.CidrRangeEngine
import com.mrscanner.omega.network.AndroidNetworkProfile
import com.mrscanner.omega.core.update.UpdateChecker
import com.mrscanner.omega.core.apkanalyzer.ApkStaticAnalyzer
import com.mrscanner.omega.network.CellularNetworkBinder
import com.mrscanner.omega.network.SimOperatorDetector
import com.mrscanner.omega.work.ReverifyScheduler
import java.io.File
import java.io.FileOutputStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Main shell — branding & About match architecture §9 exactly.
 * Verdict chip colors match architecture §7.4.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var content: FrameLayout
    private var scanJob: Job? = null
    private var cidrJob: Job? = null
    private var termGlobalCollector: Job? = null
    private var termBusy = false
    private var apkPickPath: String? = null
    private var scanSubMode = 0 // 0 = host, 1 = cidr
    private var pendingHostsField: EditText? = null
    private var pendingCidrField: EditText? = null
    private val reqPickApk = 4401
    private val reqPickHostFile = 4402
    private val reqPickCidrFile = 4403
    private val tabButtons = mutableListOf<Button>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_main)
        } catch (t: Throwable) {
            // Last-resort blank activity rather than instant kill
            android.util.Log.e("MainActivity", "setContentView failed", t)
            finish()
            return
        }
        try {
            OmegaApp.instance.engine.profile = AndroidNetworkProfile.detect(this)
        } catch (_: Throwable) { }

        content = findViewById(R.id.content)

        val home = findViewById<Button>(R.id.tabHome)
        val scan = findViewById<Button>(R.id.tabScan)
        val apk = findViewById<Button>(R.id.tabApk)
        val term = findViewById<Button>(R.id.tabTerm)
        val about = findViewById<Button>(R.id.tabAbout)
        // Null-safe: missing tab should not crash launch
        listOfNotNull(home, scan, apk, term, about).let { tabs ->
            tabButtons.clear()
            tabButtons.addAll(tabs)
        }
        home?.setOnClickListener { selectTab(0); showHome() }
        scan?.setOnClickListener { selectTab(1); showScan() }
        apk?.setOnClickListener { selectTab(2); showApk() }
        term?.setOnClickListener { selectTab(3); showTerminal() }
        about?.setOnClickListener { selectTab(4); showAbout() }
        try {
            val op = SimOperatorDetector.detect(this)
            if (op.mccMnc != null) {
                OmegaApp.instance.settings.operatorHint = op.mccMnc
            }
        } catch (_: Throwable) { }
        // Defer WorkManager: it must never block or crash first frame
        content.post {
            try {
                ReverifyScheduler.schedule(this@MainActivity, 12)
            } catch (t: Throwable) {
                android.util.Log.e("MainActivity", "WorkManager schedule failed", t)
            }
        }
        selectTab(0)
        try {
            showHome()
        } catch (t: Throwable) {
            android.util.Log.e("MainActivity", "showHome failed", t)
            try { showAbout() } catch (_: Throwable) { }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        termGlobalCollector?.cancel()
        cidrJob?.cancel()
        scope.cancel()
    }

    private fun selectTab(i: Int) {
        if (tabButtons.isEmpty()) return
        tabButtons.forEachIndexed { idx, b ->
            try {
                b.setBackgroundResource(
                    if (idx == i) R.drawable.bg_tab_active else R.drawable.bg_tab_inactive
                )
            } catch (_: Throwable) { }
        }
    }

    private fun inflate(layout: Int): View {
        if (layout != R.layout.fragment_terminal) {
            termGlobalCollector?.cancel(); termGlobalCollector = null
        }
        content.removeAllViews()
        return layoutInflater.inflate(layout, content, true)
    }

    private fun openUrl(url: String) {
        try {
            val uri = Uri.parse(url)
            val intent = if (url.startsWith("mailto:", ignoreCase = true)) {
                Intent(Intent.ACTION_SENDTO).apply {
                    data = uri
                }
            } else {
                Intent(Intent.ACTION_VIEW, uri)
            }
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
        } catch (_: Exception) {
            // No handler (browser/mail) installed — fail silently
        }
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

    private fun inflateInto(container: FrameLayout, layout: Int): View {
        container.removeAllViews()
        return layoutInflater.inflate(layout, container, true)
    }

    private fun showScan() {
        val root = inflate(R.layout.fragment_scan_shell)
        val subHost = root.findViewById<Button>(R.id.subTabHost)
        val subCidr = root.findViewById<Button>(R.id.subTabCidr)
        val settingsBtn = root.findViewById<Button>(R.id.btnScanSettings)
        val sub = root.findViewById<FrameLayout>(R.id.scanSubContent)

        fun selectSub(mode: Int) {
            scanSubMode = mode
            subHost.backgroundTintList = ContextCompat.getColorStateList(this, if (mode == 0) R.color.omega_primary else R.color.omega_primary_dim)
            subCidr.backgroundTintList = ContextCompat.getColorStateList(this, if (mode == 1) R.color.omega_primary else R.color.omega_primary_dim)
            if (mode == 0) showScanHost(sub) else showScanCidr(sub)
        }
        subHost.setOnClickListener { selectSub(0) }
        subCidr.setOnClickListener { selectSub(1) }
        settingsBtn.setOnClickListener { showScanSettingsDialog() }
        selectSub(scanSubMode)
    }

    private fun showScanSettingsDialog() {
        val v = layoutInflater.inflate(R.layout.dialog_scan_settings, null)
        val seek = v.findViewById<SeekBar>(R.id.seekConcurrency)
        val label = v.findViewById<TextView>(R.id.labelConcurrency)
        val ports = v.findViewById<EditText>(R.id.inputPorts)
        val timeout = v.findViewById<EditText>(R.id.inputTimeout)
        val dnsRegion = v.findViewById<EditText>(R.id.inputDnsRegion)
        val customDns = v.findViewById<EditText>(R.id.inputCustomDns)
        val operatorLabel = v.findViewById<TextView>(R.id.labelOperator)
        val settings = OmegaApp.instance.settings

        val opKey = settings.detectedOperatorKey
        val opName = AfghanOperators.lookup(opKey)?.brand ?: if (opKey != null) "unknown ($opKey)" else "not detected"
        val ranked = if (opKey != null) OmegaApp.instance.engine.dnsPerf.summary(opKey) else emptyList()
        operatorLabel.text = buildString {
            append("$opName${opKey?.let { " [$it]" } ?: ""}\n")
            if (ranked.isEmpty()) {
                append("no DNS performance data yet — ranking starts after the first scan on this SIM")
            } else {
                append("ranked by measured success (this device, this SIM):\n")
                ranked.take(6).forEach { (id, s) ->
                    val rtt = if (s.avgRttMs == Double.MAX_VALUE) "—" else "${s.avgRttMs.toInt()}ms"
                    append("  $id: ${(s.successRate * 100).toInt()}% ok, $rtt avg (${s.samples} samples)\n")
                }
            }
        }

        fun renderConcurrency(c: Int) { label.text = "concurrency = $c  (ceiling 4096 — higher risks socket/thread exhaustion, not more throughput)" }
        seek.progress = settings.concurrency
        renderConcurrency(settings.concurrency)
        seek.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(sb: SeekBar?, value: Int, fromUser: Boolean) { renderConcurrency(value.coerceAtLeast(1)) }
            override fun onStartTrackingTouch(sb: SeekBar?) {}
            override fun onStopTrackingTouch(sb: SeekBar?) {}
        })
        ports.setText(settings.scanPorts.joinToString(","))
        timeout.setText(settings.precheckTimeoutMs.toString())
        dnsRegion.setText(settings.dnsRegion)
        customDns.setText(settings.customDnsServers.joinToString(","))

        AlertDialog.Builder(this)
            .setTitle("Scan settings")
            .setView(v)
            .setPositiveButton("Save") { _, _ ->
                settings.concurrency = (seek.progress.coerceAtLeast(1))
                settings.setKey("ports", ports.text.toString())
                timeout.text.toString().toLongOrNull()?.let { settings.precheckTimeoutMs = it.coerceIn(200, 60_000) }
                dnsRegion.text.toString().takeIf { it.isNotBlank() }?.let { settings.dnsRegion = it }
                settings.customDnsServers = customDns.text.toString().split(",").map { it.trim() }.filter { it.isNotEmpty() }
                Toast.makeText(this, "Settings saved · configHash=${settings.configHash().take(8)}", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showScanHost(container: FrameLayout) {
        val root = inflateInto(container, R.layout.fragment_scan_host)
        val hostsInput = root.findViewById<EditText>(R.id.hostsInput)
        val loadBtn = root.findViewById<Button>(R.id.btnLoadFile)
        val loadedLabel = root.findViewById<TextView>(R.id.loadedFileLabel)
        val btnStart = root.findViewById<Button>(R.id.btnStart)
        val btnStop = root.findViewById<Button>(R.id.btnStop)
        val bar = root.findViewById<ProgressBar>(R.id.scanProgress)
        val status = root.findViewById<TextView>(R.id.scanStatus)
        val results = root.findViewById<TextView>(R.id.results)

        loadBtn.setOnClickListener {
            pendingHostsField = hostsInput
            openFilePicker(reqPickHostFile)
        }
        loadedLabel.text = ""

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
            OmegaApp.instance.promoteScanService()
            bar.progress = 0
            scanJob = scope.launch {
                val engine = OmegaApp.instance.engine
                // bindToCellular() blocks on a CountDownLatch for up to 4s — never call it
                // on the UI thread (that was freezing/ANR-ing the app on every Start tap).
                val bind = withContext(Dispatchers.IO) { CellularNetworkBinder.bindToCellular(this@MainActivity) }
                if (bind.bound) status.text = "Scanning ${hosts.size}… [${bind.detail}]"
                val collector = launch {
                    engine.eventBus.events.collect { ev ->
                        when (ev) {
                            is ScanEvent.HostVerdict -> {
                                results.append("${mark(ev.report.verdict)} ${ev.host}  conf=${"%.2f".format(ev.report.confidence)}  ${ev.report.verdict}\n")
                            }
                            is ScanEvent.Progress -> {
                                bar.progress = if (ev.total == 0) 0 else ev.done * 100 / ev.total
                                status.text = "scanned ${ev.done}/${ev.total} · found ${ev.foundCount}" + (ev.host?.let { "  → $it" } ?: "")
                            }
                            is ScanEvent.ScanFinished -> {
                                status.text = "Done ${ev.hostCount} hosts · ${ev.wallMs}ms · id=${ev.scanId}"
                            }
                            else -> {}
                        }
                    }
                }
                try {
                    engine.eventBus.subscriberCount.first { it >= 1 }
                    engine.scanHosts(hosts)
                } catch (e: Exception) {
                    status.text = "Error: ${e.message}"
                } finally {
                    collector.cancel()
                    OmegaApp.instance.stopScanService()
                    CellularNetworkBinder.clearBind(this@MainActivity)
                    btnStart.isEnabled = true
                }
            }
        }
    }

    private fun showScanCidr(container: FrameLayout) {
        val root = inflateInto(container, R.layout.fragment_scan_cidr)
        val cidrInput = root.findViewById<EditText>(R.id.cidrInput)
        val loadBtn = root.findViewById<Button>(R.id.btnLoadCidrFile)
        val loadedLabel = root.findViewById<TextView>(R.id.loadedCidrFileLabel)
        val btnStart = root.findViewById<Button>(R.id.btnCidrStart)
        val btnStop = root.findViewById<Button>(R.id.btnCidrStop)
        val bar = root.findViewById<ProgressBar>(R.id.cidrProgress)
        val status = root.findViewById<TextView>(R.id.cidrStatus)
        val results = root.findViewById<TextView>(R.id.cidrResults)

        loadBtn.setOnClickListener {
            pendingCidrField = cidrInput
            openFilePicker(reqPickCidrFile)
        }
        loadedLabel.text = ""

        btnStop.setOnClickListener {
            cidrJob?.cancel()
            status.text = "Cancelled"
            btnStart.isEnabled = true
        }
        btnStart.setOnClickListener {
            val specs = cidrInput.text?.toString().orEmpty().lines()
                .map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.distinct()
            if (specs.isEmpty()) { status.text = "No ranges"; return@setOnClickListener }
            val ranges = specs.mapNotNull { s -> CidrRangeEngine.parse(if (!s.contains("/")) "$s/32" else s) }
            if (ranges.isEmpty()) { status.text = "No valid ranges (a.b.c.d/prefix)"; return@setOnClickListener }
            btnStart.isEnabled = false
            results.text = ""
            val totalAll = ranges.sumOf { it.total }
            status.text = "Scanning ${ranges.size} range(s), $totalAll host(s) total…"
            OmegaApp.instance.promoteScanService()
            bar.progress = 0
            cidrJob = scope.launch {
                val engine = OmegaApp.instance.engine
                val bind = withContext(Dispatchers.IO) { CellularNetworkBinder.bindToCellular(this@MainActivity) }
                val collector = launch {
                    engine.eventBus.events.collect { ev ->
                        when (ev) {
                            is ScanEvent.HostVerdict -> {
                                results.append("${mark(ev.report.verdict)} ${ev.host}  conf=${"%.2f".format(ev.report.confidence)}  ${ev.report.verdict}\n")
                            }
                            is ScanEvent.RangeProgress -> {
                                val pct = if (ev.total == 0L) 0 else (ev.done * 100 / ev.total).toInt()
                                bar.progress = pct
                                status.text = "[$pct%] scanned=${ev.done}/${ev.total} remaining=${ev.total - ev.done} alive=${ev.aliveFound}"
                            }
                            is ScanEvent.ScanFinished -> {
                                status.text = "Done · ${ev.wallMs}ms · id=${ev.scanId}"
                            }
                            else -> {}
                        }
                    }
                }
                try {
                    engine.eventBus.subscriberCount.first { it >= 1 }
                    for (range in ranges) engine.scanCidrRange(range)
                } catch (e: Exception) {
                    status.text = "Error: ${e.message}"
                } finally {
                    collector.cancel()
                    OmegaApp.instance.stopScanService()
                    if (bind.bound) CellularNetworkBinder.clearBind(this@MainActivity)
                    btnStart.isEnabled = true
                }
            }
        }
    }

    private fun openFilePicker(requestCode: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "text/plain"
            putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("text/plain", "text/*", "*/*"))
        }
        try {
            startActivityForResult(intent, requestCode)
        } catch (e: Exception) {
            Toast.makeText(this, "No file picker: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun showTerminal() {
        val root = inflate(R.layout.fragment_terminal)
        val out = root.findViewById<TextView>(R.id.termOut)
        val input = root.findViewById<EditText>(R.id.termIn)
        val btn = root.findViewById<Button>(R.id.btnRun)
        val scroll = root.findViewById<ScrollView>(R.id.termScroll)
        val liveStatus = root.findViewById<TextView>(R.id.termLiveStatus)
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

        // Live global feed: whatever scan is running — from Home, Scan Host,
        // Scan CIDR, or a CLI command typed right here — shows up on this
        // screen while it's open, since all of them emit through the same
        // shared engine.eventBus. Percentage/found/remaining update the
        // compact status line above; verdicts and log lines scroll below.
        termGlobalCollector?.cancel()
        termGlobalCollector = scope.launch {
            OmegaApp.instance.engine.eventBus.events.collect { ev ->
                when (ev) {
                    is ScanEvent.RangeProgress -> {
                        liveStatus.isVisible = true
                        val pct = if (ev.total == 0L) 0 else (ev.done * 100 / ev.total)
                        liveStatus.text = "[${ev.scanId}] ${pct}% · scanned ${ev.done}/${ev.total} · remaining ${ev.total - ev.done} · found ${ev.aliveFound}" +
                            (ev.currentHost?.let { "  → $it" } ?: "")
                    }
                    is ScanEvent.Progress -> {
                        liveStatus.isVisible = true
                        val pct = if (ev.total == 0) 0 else (ev.done * 100 / ev.total)
                        liveStatus.text = "${pct}% · scanned ${ev.done}/${ev.total} · found ${ev.foundCount}" + (ev.host?.let { "  → $it" } ?: "")
                    }
                    is ScanEvent.HostVerdict -> append(CliOutputLine.Kind.VERDICT,
                        "${mark(ev.report.verdict)} ${ev.host}  conf=${"%.2f".format(ev.report.confidence)}  ${ev.report.verdict}")
                    is ScanEvent.CheckpointSaved -> append(CliOutputLine.Kind.SYSTEM, "checkpoint saved @${ev.cursor} (scan ${ev.scanId})")
                    is ScanEvent.BudgetExceeded -> append(CliOutputLine.Kind.SYSTEM, "budget skip ${ev.host}: ${ev.skippedPlugins.take(4).joinToString()}")
                    is ScanEvent.LogEmitted -> append(if (ev.level == "ERROR") CliOutputLine.Kind.STDERR else CliOutputLine.Kind.SYSTEM, ev.message)
                    is ScanEvent.ScanFinished -> {
                        liveStatus.isVisible = false
                        append(CliOutputLine.Kind.SYSTEM, "finished · id=${ev.scanId} · hosts=${ev.hostCount} · ${ev.wallMs}ms")
                    }
                    else -> {}
                }
            }
        }
    }


    private fun showApk() {
        val root = inflate(R.layout.fragment_apk)
        val pathTv = root.findViewById<TextView>(R.id.apkPath)
        val reportTv = root.findViewById<TextView>(R.id.apkReport)
        val btnPick = root.findViewById<Button>(R.id.btnPickApk)
        val btnGo = root.findViewById<Button>(R.id.btnAnalyzeApk)
        apkPickPath?.let {
            pathTv.text = it
            btnGo.isEnabled = true
        }
        btnPick.setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/vnd.android.package-archive"
                putExtra(Intent.EXTRA_MIME_TYPES, arrayOf(
                    "application/vnd.android.package-archive",
                    "application/octet-stream",
                    "*/*"
                ))
            }
            try {
                startActivityForResult(intent, reqPickApk)
            } catch (e: Exception) {
                Toast.makeText(this, "No file picker: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
        btnGo.setOnClickListener {
            val path = apkPickPath ?: return@setOnClickListener
            btnGo.isEnabled = false
            reportTv.text = "Analyzing…"
            scope.launch {
                try {
                    val report = ApkStaticAnalyzer.analyze(path)
                    reportTv.text = ApkStaticAnalyzer.format(report)
                } catch (e: Exception) {
                    reportTv.text = "Error: ${e.message}"
                } finally {
                    btnGo.isEnabled = true
                }
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != Activity.RESULT_OK) return
        val uri = data?.data ?: return
        when (requestCode) {
            reqPickApk -> {
                scope.launch {
                    try {
                        val name = queryDisplayName(uri) ?: "picked.apk"
                        val out = File(cacheDir, "analyze-$name")
                        contentResolver.openInputStream(uri)?.use { input ->
                            FileOutputStream(out).use { output -> input.copyTo(output) }
                        }
                        apkPickPath = out.absolutePath
                        showApk()
                    } catch (e: Exception) {
                        Toast.makeText(this@MainActivity, "Failed to read APK: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
            reqPickHostFile, reqPickCidrFile -> {
                val label = if (requestCode == reqPickHostFile) "host(s)" else "range(s)"
                Toast.makeText(this, "Loading…", Toast.LENGTH_SHORT).show()
                scope.launch {
                    try {
                        // Disk read + line parsing was running synchronously on the UI
                        // thread here — for a large file that's exactly what froze/blacked
                        // out the app. Do it on IO, then hop back to the main thread only
                        // to touch the views.
                        val (lines, name) = withContext(Dispatchers.IO) {
                            val text = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }.orEmpty()
                            val parsed = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toList()
                            parsed to (queryDisplayName(uri) ?: "file")
                        }
                        if (requestCode == reqPickHostFile) pendingHostsField?.setText(lines.joinToString("\n"))
                        else pendingCidrField?.setText(lines.joinToString("\n"))
                        Toast.makeText(this@MainActivity, "Loaded ${lines.size} $label from $name", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(this@MainActivity, "Failed to read file: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private fun queryDisplayName(uri: Uri): String? {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) return c.getString(0)
        }
        return uri.lastPathSegment
    }

    /**
     * About screen — architecture §9 + Creator/Support with official icons.
     * Every icon is fully clickable and opens the exact URL.
     */
    private fun showAbout() {
        val root = inflate(R.layout.fragment_about)
        val settings = OmegaApp.instance.settings
        val active = PluginRegistry.createAll(settings).size
        val catalog = PluginRegistry.catalog().size

        root.findViewById<TextView>(R.id.aboutVersionLine).text =
            "v${BuildConfig.VERSION_NAME}  ·  versionCode ${BuildConfig.VERSION_CODE}"

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
            val opi = SimOperatorDetector.detect(this@MainActivity)
            appendLine("SIM/operator: ${opi.simOperatorName ?: "-"} ${opi.mccMnc ?: ""}")
            appendLine("operatorHint: ${OmegaApp.instance.settings.operatorHint ?: "-"}")
            appendLine("minSdk 26 · targetSdk 34")
            appendLine()
            appendLine("Update channel: ali-shortcuts/mr-scanner")
        }

        bindSocial(root.findViewById(R.id.linkEmail), R.drawable.ic_brand_email,
            R.string.label_email, R.string.handle_email, R.string.url_email)
        bindSocial(root.findViewById(R.id.linkTelegram), R.drawable.ic_brand_telegram,
            R.string.label_telegram, R.string.handle_telegram, R.string.url_telegram)
        bindSocial(root.findViewById(R.id.linkChannel), R.drawable.ic_brand_channel,
            R.string.label_channel, R.string.handle_channel, R.string.url_channel)
        bindSocial(root.findViewById(R.id.linkFacebook), R.drawable.ic_brand_facebook,
            R.string.label_facebook, R.string.handle_facebook, R.string.url_facebook)
        bindSocial(root.findViewById(R.id.linkTiktok), R.drawable.ic_brand_tiktok,
            R.string.label_tiktok, R.string.handle_tiktok, R.string.url_tiktok)
        bindSocial(root.findViewById(R.id.linkInstagram), R.drawable.ic_brand_instagram,
            R.string.label_instagram, R.string.handle_instagram, R.string.url_instagram)
        bindSocial(root.findViewById(R.id.linkYoutube), R.drawable.ic_brand_youtube,
            R.string.label_youtube, R.string.handle_youtube, R.string.url_youtube)
        // Live update check (architecture §12.4)
        scope.launch {
            try {
                val checker = UpdateChecker("ali-shortcuts/mr-scanner", BuildConfig.VERSION_NAME)
                val info = checker.check()
                if (info != null) {
                    val specs = root.findViewById<TextView>(R.id.aboutSpecsBody)
                    specs.append("\n\nUpdate available: ${info.tag}\n${info.downloadUrl ?: ""}")
                }
            } catch (_: Exception) { }
        }
    }

    private fun bindSocial(
        cell: View,
        iconRes: Int,
        titleRes: Int,
        handleRes: Int,
        urlRes: Int
    ) {
        val icon = cell.findViewById<ImageView>(R.id.socialIcon)
        val title = cell.findViewById<TextView>(R.id.socialTitle)
        val handle = cell.findViewById<TextView>(R.id.socialHandle)
        icon.setImageResource(iconRes)
        title.setText(titleRes)
        handle.setText(handleRes)
        val url = getString(urlRes)
        icon.contentDescription = getString(titleRes)
        // Entire cell clickable
        cell.isClickable = true
        cell.isFocusable = true
        cell.setOnClickListener { openUrl(url) }
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
