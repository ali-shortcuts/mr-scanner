package com.mrscanner.omega.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.mrscanner.omega.OmegaApp

/**
 * Periodic / one-shot re-verify of open holes (architecture timeconsistency).
 */
class ReverifyWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        return try {
            val engine = OmegaApp.instance.engine
            val open = engine.database?.holes?.list(openOnly = true) ?: engine.holeStore.list(openOnly = true)
            val hosts = open.map { it.host }.distinct().take(50)
            if (hosts.isNotEmpty()) {
                engine.scanHosts(hosts, scanId = "reverify-${System.currentTimeMillis() % 100000}")
            }
            Result.success()
        } catch (_: Exception) {
            Result.retry()
        }
    }
}
