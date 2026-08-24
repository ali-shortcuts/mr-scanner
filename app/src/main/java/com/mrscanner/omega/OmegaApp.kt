package com.mrscanner.omega

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.os.Build
import com.mrscanner.omega.core.db.CheckpointStore
import com.mrscanner.omega.core.db.HoleAgeStore
import com.mrscanner.omega.core.db.OmegaDatabase
import com.mrscanner.omega.core.scheduler.ScanEngine
import com.mrscanner.omega.core.settings.ConsoleSettings
import com.mrscanner.omega.network.AndroidNetworkProfile
import com.mrscanner.omega.service.ScanForegroundService
import java.io.File

class OmegaApp : Application() {
    lateinit var settings: ConsoleSettings; private set
    lateinit var engine: ScanEngine; private set
    lateinit var database: OmegaDatabase; private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        settings = ConsoleSettings()
        val data = File(filesDir, "omega-data").apply { mkdirs() }
        database = OmegaDatabase.open(data)
        engine = ScanEngine(
            settings = settings,
            holeStore = HoleAgeStore(data),
            checkpointStore = CheckpointStore(data),
            profile = AndroidNetworkProfile.detect(this),
            database = database
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL_SCAN,
                getString(R.string.scan_channel_name),
                NotificationManager.IMPORTANCE_LOW
            )
            ch.description = getString(R.string.scan_channel_desc)
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    fun promoteScanService() {
        try {
            val i = Intent(this, ScanForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i)
            else startService(i)
        } catch (_: Exception) { }
    }

    fun stopScanService() {
        try { stopService(Intent(this, ScanForegroundService::class.java)) } catch (_: Exception) { }
    }

    companion object {
        const val CHANNEL_SCAN = "scan_progress"
        lateinit var instance: OmegaApp
            private set
    }
}
