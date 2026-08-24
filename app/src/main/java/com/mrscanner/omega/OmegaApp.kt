package com.mrscanner.omega
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.mrscanner.omega.core.db.CheckpointStore
import com.mrscanner.omega.core.db.HoleAgeStore
import com.mrscanner.omega.core.scheduler.ScanEngine
import com.mrscanner.omega.core.settings.ConsoleSettings
import com.mrscanner.omega.network.AndroidNetworkProfile
import java.io.File

class OmegaApp : Application() {
    lateinit var settings: ConsoleSettings; private set
    lateinit var engine: ScanEngine; private set
    override fun onCreate() {
        super.onCreate(); instance = this; settings = ConsoleSettings()
        val data = File(filesDir, "omega-data").apply { mkdirs() }
        engine = ScanEngine(settings, holeStore = HoleAgeStore(data), checkpointStore = CheckpointStore(data),
            profile = AndroidNetworkProfile.detect(this))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(CHANNEL_SCAN, getString(R.string.scan_channel_name), NotificationManager.IMPORTANCE_LOW)
            ch.description = getString(R.string.scan_channel_desc)
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }
    companion object {
        const val CHANNEL_SCAN = "scan_progress"
        lateinit var instance: OmegaApp; private set
    }
}
