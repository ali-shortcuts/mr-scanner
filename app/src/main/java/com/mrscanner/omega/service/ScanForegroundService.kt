package com.mrscanner.omega.service
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.mrscanner.omega.MainActivity
import com.mrscanner.omega.OmegaApp
import com.mrscanner.omega.R

class ScanForegroundService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val n = NotificationCompat.Builder(this, OmegaApp.CHANNEL_SCAN)
            .setContentTitle(getString(R.string.app_name)).setContentText("Scan in progress")
            .setSmallIcon(R.drawable.ic_stat_scan).setContentIntent(pi).setOngoing(true).build()
        startForeground(42, n)
        return START_STICKY
    }
}
