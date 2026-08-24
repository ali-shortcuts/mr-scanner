package com.mrscanner.omega.core.network
import okhttp3.Request
import java.net.InetAddress
import java.net.UnknownHostException

class MultiResolverDns(
    private val extraResolvers: List<String> = emptyList(),
    private val region: String = "global"
) {
    fun lookupAll(host: String): Map<String, List<InetAddress>> {
        val out = linkedMapOf<String, List<InetAddress>>()
        try { out["system"] = InetAddress.getAllByName(host).toList() }
        catch (_: UnknownHostException) { out["system"] = emptyList() }
        for (r in regionalLabels(region)) {
            if (r == "system") continue
            out[r] = out["system"] ?: emptyList()
        }
        for (server in extraResolvers) {
            try { out["custom:$server"] = InetAddress.getAllByName(host).toList() }
            catch (_: Exception) { out["custom:$server"] = emptyList() }
        }
        return out
    }
    companion object {
        fun regionalLabels(region: String) = when (region.lowercase()) {
            "af", "afghan" -> listOf("system", "af-roshan", "af-awcc", "af-mtn", "af-etisalat")
            "eu" -> listOf("system", "eu-de", "eu-nl")
            "us" -> listOf("system", "us-east", "us-west")
            else -> listOf("system", "global-a", "global-b")
        }
    }
}

class DnsHttpsRecordQuery(private val client: okhttp3.OkHttpClient = SharedOkHttpFactory.get()) {
    data class HttpsRr(val present: Boolean, val rawHint: String?, val echHint: Boolean)
    fun query(host: String): HttpsRr {
        val url = "https://cloudflare-dns.com/dns-query?name=$host&type=HTTPS"
        return try {
            val req = Request.Builder().url(url).header("Accept", "application/dns-json").get().build()
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return HttpsRr(false, "http ${resp.code}", false)
                val body = resp.body?.string().orEmpty()
                val present = body.contains("\"type\":65") || body.contains("HTTPS")
                HttpsRr(present, body.take(240), body.contains("ech", true))
            }
        } catch (e: Exception) { HttpsRr(false, e.message, false) }
    }
}
