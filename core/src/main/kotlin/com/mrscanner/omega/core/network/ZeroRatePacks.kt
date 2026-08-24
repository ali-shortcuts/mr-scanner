package com.mrscanner.omega.core.network

import okhttp3.Request
import java.net.HttpURLConnection
import java.net.URL

/**
 * Operator zero-rating heuristic packs.
 * Field-extendable: each pack lists candidate hosts/paths that are often zero-rated
 * or captive-portal adjacent on a given operator. Detection is passive/comparative:
 * reachability + distinctive body markers under cellular profile.
 */
data class ZeroRatePack(
    val id: String,
    val operatorName: String,
    val mccMnc: List<String> = emptyList(), // e.g. 412-01
    val candidates: List<ZeroRateCandidate>
)

data class ZeroRateCandidate(
    val host: String,
    val path: String = "/",
    val https: Boolean = true,
    val bodyMarkers: List<String> = emptyList(),
    val note: String = ""
)

object ZeroRatePacks {
    val ALL: List<ZeroRatePack> = listOf(
        ZeroRatePack(
            id = "af-generic",
            operatorName = "Afghanistan-generic",
            mccMnc = listOf("412-01", "412-20", "412-40", "412-50", "412-55", "412-80", "412-88"),
            candidates = listOf(
                ZeroRateCandidate("facebook.com", "/", true, listOf("facebook", "meta"), "social often zero-rated"),
                ZeroRateCandidate("m.facebook.com", "/", true, listOf("facebook"), "mobile FB"),
                ZeroRateCandidate("www.whatsapp.com", "/", true, listOf("whatsapp"), "messaging"),
                ZeroRateCandidate("www.wikipedia.org", "/", true, listOf("wikipedia"), "edu zero-rate"),
                ZeroRateCandidate("connectivitycheck.gstatic.com", "/generate_204", true, emptyList(), "captive portal probe"),
                ZeroRateCandidate("captive.apple.com", "/hotspot-detect.html", true, listOf("Success", "HTML"), "apple captive"),
                ZeroRateCandidate("www.facebook.com", "/", true, listOf("facebook"), "www FB"),
                ZeroRateCandidate("web.facebook.com", "/", true, listOf("facebook"), "web FB"),
                ZeroRateCandidate("static.xx.fbcdn.net", "/", true, listOf(), "fbcdn"),
                ZeroRateCandidate("www.messenger.com", "/", true, listOf("messenger","facebook"), "messenger"),
                ZeroRateCandidate("telegram.org", "/", true, listOf("telegram"), "telegram"),
                ZeroRateCandidate("www.youtube.com", "/", true, listOf("youtube","ytimg"), "youtube often bundled"),
                ZeroRateCandidate("i.instagram.com", "/", true, listOf("instagram"), "ig api host")
            )
        ),
        ZeroRatePack(
            id = "global-captive",
            operatorName = "global-captive",
            candidates = listOf(
                ZeroRateCandidate("connectivitycheck.gstatic.com", "/generate_204", true),
                ZeroRateCandidate("www.msftconnecttest.com", "/connecttest.txt", true, listOf("Microsoft")),
                ZeroRateCandidate("detectportal.firefox.com", "/success.txt", true, listOf("success"))
            )
        )
    )

    fun forOperator(nameOrMcc: String?): ZeroRatePack {
        if (nameOrMcc.isNullOrBlank()) return ALL.first { it.id == "global-captive" }
        val key = nameOrMcc.lowercase()
        return ALL.firstOrNull { pack ->
            pack.id.contains(key) || pack.operatorName.lowercase().contains(key) ||
                pack.mccMnc.any { it.contains(key) }
        } ?: ALL.first { it.id == "af-generic" }
    }
}

data class ZeroRateHit(
    val candidate: ZeroRateCandidate,
    val ok: Boolean,
    val code: Int?,
    val markerHit: Boolean,
    val bytes: Int,
    val error: String? = null
)

object ZeroRateProbe {
    fun probePack(pack: ZeroRatePack, timeoutMs: Int = 4_000): List<ZeroRateHit> {
        return pack.candidates.map { c -> probeOne(c, timeoutMs) }
    }

    fun probeOne(c: ZeroRateCandidate, timeoutMs: Int): ZeroRateHit {
        val scheme = if (c.https) "https" else "http"
        val url = "$scheme://${c.host}${c.path}"
        return try {
            val u = URL(url)
            val conn = (u.openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                instanceFollowRedirects = true
                requestMethod = "GET"
                setRequestProperty("User-Agent", "MrScannerOmega/2.0")
            }
            conn.connect()
            val code = conn.responseCode
            val body = try {
                (if (code in 200..399) conn.inputStream else conn.errorStream)
                    ?.bufferedReader()?.readText()?.take(2000).orEmpty()
            } catch (_: Exception) { "" }
            val marker = c.bodyMarkers.isEmpty() || c.bodyMarkers.any { body.contains(it, true) }
            val ok = code in 200..399
            ZeroRateHit(c, ok, code, marker && ok, body.length)
        } catch (e: Exception) {
            ZeroRateHit(c, false, null, false, 0, e.message)
        }
    }
}
