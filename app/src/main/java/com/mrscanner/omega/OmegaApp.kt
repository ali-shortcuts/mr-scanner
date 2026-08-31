package com.mrscanner.omega

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.appcompat.app.AppCompatDelegate
import com.mrscanner.omega.core.db.CheckpointStore
import com.mrscanner.omega.core.db.HoleAgeStore
import com.mrscanner.omega.core.network.AfghanOperators
import com.mrscanner.omega.core.network.DnsPerformanceStore
import com.mrscanner.omega.core.plugin.NetworkProfile
import com.mrscanner.omega.core.scheduler.ScanEngine
import com.mrscanner.omega.core.settings.ConsoleSettings
import com.mrscanner.omega.network.AndroidNetworkProfile
import com.mrscanner.omega.network.SimOperatorDetector
import com.mrscanner.omega.service.ScanForegroundService
import java.io.File

/**
 * Crash-safe Application.
 *
 * IMPORTANT: Do NOT open JDBC/sqlite-jdbc here. That library ships desktop natives
 * and historically crashed 32/64-bit Android at process start.
 * Android uses file-backed HoleAgeStore/CheckpointStore only.
 */
class OmegaApp : Application() {
    @Volatile lateinit var settings: ConsoleSettings
        private set
    @Volatile lateinit var engine: ScanEngine
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        runCatching { AppCompatDelegate.setCompatVectorFromResourcesEnabled(true) }
        // Step-by-step, each step isolated so one failure never kills the process.
        settings = runCatching { ConsoleSettings() }.getOrElse {
            Log.e(TAG, "ConsoleSettings failed", it)
            ConsoleSettings()
        }
        val dataDir = runCatching {
            File(filesDir, "omega-data").apply { mkdirs() }
        }.getOrElse {
            Log.e(TAG, "filesDir failed", it)
            File(cacheDir, "omega-data").apply { mkdirs() }
        }
        val profile = runCatching { AndroidNetworkProfile.detect(this) }
            .getOrDefault(NetworkProfile.UNKNOWN)
        // Detected once at process start; the resolver ranking that uses this
        // key (DnsPerformanceStore) degrades to the static region list if
        // detection fails or the device has no SIM, so this is never fatal.
        runCatching {
            val op = SimOperatorDetector.detect(this)
            settings.detectedOperatorKey = op.mccMnc
            val known = AfghanOperators.lookup(op.mccMnc)
            Log.i(TAG, "operator=${op.mccMnc} (${known?.brand ?: op.simOperatorName ?: "unknown"})")
        }.onFailure { Log.e(TAG, "SIM operator detection failed", it) }
        val dnsPerf = runCatching { DnsPerformanceStore(File(dataDir, "dns-performance.tsv")) }
            .getOrElse { Log.e(TAG, "DnsPerformanceStore failed, using in-memory only", it); DnsPerformanceStore() }
        engine = runCatching {
            ScanEngine(
                settings = settings,
                holeStore = HoleAgeStore(dataDir),
                checkpointStore = CheckpointStore(dataDir),
                dnsPerf = dnsPerf,
                profile = profile,
                database = null // NEVER JDBC on Android
            )
        }.getOrElse {
            Log.e(TAG, "ScanEngine failed, using bare engine", it)
            ScanEngine(settings = settings, dnsPerf = dnsPerf, profile = profile, database = null)
        }
        runCatching { createScanChannel() }
            .onFailure { Log.e(TAG, "notification channel failed", it) }
    }

    private fun createScanChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val ch = NotificationChannel(
            CHANNEL_SCAN,
            getString(R.string.scan_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = getString(R.string.scan_channel_desc) }
        nm.createNotificationChannel(ch)
    }

    fun promoteScanService() {
        runCatching {
            val i = Intent(this, ScanForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i)
            else startService(i)
        }.onFailure { Log.e(TAG, "FGS start failed", it) }
    }

    fun stopScanService() {
        runCatching { stopService(Intent(this, ScanForegroundService::class.java)) }
    }

    companion object {
        private const val TAG = "OmegaApp"
        const val CHANNEL_SCAN = "scan_progress"
        @JvmStatic lateinit var instance: OmegaApp
            private set
        fun isInitialized(): Boolean = this::instance.isInitialized
    }
}
