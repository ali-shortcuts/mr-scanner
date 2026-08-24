package com.mrscanner.omega

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.os.Build
import android.util.Log
import com.mrscanner.omega.core.db.CheckpointStore
import com.mrscanner.omega.core.db.HoleAgeStore
import com.mrscanner.omega.core.db.OmegaDatabase
import com.mrscanner.omega.core.scheduler.ScanEngine
import com.mrscanner.omega.core.settings.ConsoleSettings
import com.mrscanner.omega.network.AndroidNetworkProfile
import com.mrscanner.omega.service.ScanForegroundService
import java.io.File

class OmegaApp : Application() {
    lateinit var settings: ConsoleSettings
        private set
    lateinit var engine: ScanEngine
        private set
    var database: OmegaDatabase? = null
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        // Never crash the process in Application.onCreate — show UI even if optional services fail.
        settings = try {
            ConsoleSettings()
        } catch (t: Throwable) {
            Log.e(TAG, "settings init failed", t)
            ConsoleSettings()
        }
        val data = try {
            File(filesDir, "omega-data").apply { mkdirs() }
        } catch (t: Throwable) {
            Log.e(TAG, "data dir failed", t)
            File(cacheDir, "omega-data").apply { mkdirs() }
        }
        database = try {
            OmegaDatabase.open(data)
        } catch (t: Throwable) {
            Log.e(TAG, "database open failed — using file stores only", t)
            null
        }
        engine = try {
            ScanEngine(
                settings = settings,
                holeStore = HoleAgeStore(data),
                checkpointStore = CheckpointStore(data),
                profile = try {
                    AndroidNetworkProfile.detect(this)
                } catch (_: Throwable) {
                    com.mrscanner.omega.core.plugin.NetworkProfile.UNKNOWN
                },
                database = database
            )
        } catch (t: Throwable) {
            Log.e(TAG, "engine init failed — minimal engine", t)
            ScanEngine(settings = settings)
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val ch = NotificationChannel(
                    CHANNEL_SCAN,
                    getString(R.string.scan_channel_name),
                    NotificationManager.IMPORTANCE_LOW
                )
                ch.description = getString(R.string.scan_channel_desc)
                getSystemService(NotificationManager::class.java)?.createNotificationChannel(ch)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "notification channel failed", t)
        }
    }

    fun promoteScanService() {
        try {
            val i = Intent(this, ScanForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i)
            else startService(i)
        } catch (t: Throwable) {
            Log.e(TAG, "promote FGS failed", t)
        }
    }

    fun stopScanService() {
        try {
            stopService(Intent(this, ScanForegroundService::class.java))
        } catch (_: Throwable) {
        }
    }

    companion object {
        private const val TAG = "OmegaApp"
        const val CHANNEL_SCAN = "scan_progress"
        lateinit var instance: OmegaApp
            private set
    }
}
