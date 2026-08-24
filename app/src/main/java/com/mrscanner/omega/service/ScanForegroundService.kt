package com.mrscanner.omega.service

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.mrscanner.omega.MainActivity
import com.mrscanner.omega.OmegaApp
import com.mrscanner.omega.R

class ScanForegroundService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return try {
            val pi = PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val icon = try {
                R.drawable.ic_stat_scan
            } catch (_: Throwable) {
                android.R.drawable.stat_notify_sync
            }
            val n = NotificationCompat.Builder(this, OmegaApp.CHANNEL_SCAN)
                .setContentTitle(getString(R.string.app_name))
                .setContentText("Scan in progress")
                .setSmallIcon(icon)
                .setContentIntent(pi)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build()
            startForeground(42, n)
            START_STICKY
        } catch (t: Throwable) {
            android.util.Log.e("ScanFGS", "startForeground failed", t)
            stopSelf()
            START_NOT_STICKY
        }
    }
}
