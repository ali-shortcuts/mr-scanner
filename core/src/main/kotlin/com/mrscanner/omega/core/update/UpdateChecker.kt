package com.mrscanner.omega.core.update
import com.mrscanner.omega.core.network.SharedOkHttpFactory
import okhttp3.Request
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class UpdateInfo(val tag: String, val downloadUrl: String?, val body: String?)

class UpdateChecker(private val repo: String, private val currentVersionName: String) {
    suspend fun check(): UpdateInfo? = withContext(Dispatchers.IO) {
        try {
            val req = Request.Builder()
                .url("https://api.github.com/repos/$repo/releases/latest")
                .header("Accept", "application/vnd.github+json").get().build()
            SharedOkHttpFactory.get().newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@withContext null
                val body = resp.body?.string() ?: return@withContext null
                val tag = Regex(""""tag_name"\s*:\s*"([^"]+)"""").find(body)?.groupValues?.get(1) ?: return@withContext null
                if (!isNewer(tag.removePrefix("v"), currentVersionName.removePrefix("v"))) return@withContext null
                val url = Regex(""""browser_download_url"\s*:\s*"([^"]+\.apk)"""").find(body)?.groupValues?.get(1)
                UpdateInfo(tag, url, null)
            }
        } catch (_: Exception) { null }
    }
    private fun isNewer(remote: String, local: String): Boolean {
        fun parts(s: String) = s.split(Regex("[^0-9]+")).mapNotNull { it.toIntOrNull() }
        val a = parts(remote); val b = parts(local)
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }; val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }
}
