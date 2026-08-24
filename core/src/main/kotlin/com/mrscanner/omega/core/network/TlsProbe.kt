package com.mrscanner.omega.core.network
import com.mrscanner.omega.core.plugin.ScanTarget
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

data class TlsProbeResult(
    val success: Boolean,
    val protocol: String? = null,
    val cipher: String? = null,
    val certificate: X509Certificate? = null,
    val sans: List<String> = emptyList(),
    val cn: String? = null,
    val error: String? = null,
    val fragmentAt: Int? = null
) {
    fun toShortString() = if (success) "ok/${protocol ?: "?"} cert=${cn ?: "?"}" else "fail:${error ?: "?"}"
}

class TlsProbe(private val timeoutMs: Int = 5_000) {
    fun probe(target: ScanTarget, fragmentAt: Int? = null): TlsProbeResult =
        if (fragmentAt == null) normal(target) else frag(target, fragmentAt)

    private fun tm() = object : X509TrustManager {
        override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun getAcceptedIssuers() = emptyArray<X509Certificate>()
    }

    private fun normal(target: ScanTarget): TlsProbeResult = try {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(tm()), java.security.SecureRandom())
        (ctx.socketFactory.createSocket() as SSLSocket).use { s ->
            s.soTimeout = timeoutMs
            s.connect(InetSocketAddress(target.host, target.port), timeoutMs)
            s.useClientMode = true
            try {
                val p = s.sslParameters
                p.serverNames = listOf(javax.net.ssl.SNIHostName(target.effectiveSni))
                s.sslParameters = p
            } catch (_: Exception) {}
            s.startHandshake()
            val cert = s.session.peerCertificates.firstOrNull() as? X509Certificate
            TlsProbeResult(true, s.session.protocol, s.session.cipherSuite, cert,
                cert?.let { extractSans(it) } ?: emptyList(), cert?.let { extractCn(it) })
        }
    } catch (e: Exception) {
        TlsProbeResult(false, error = e.message ?: e::class.simpleName)
    }

    private fun frag(target: ScanTarget, splitAt: Int): TlsProbeResult = try {
        Socket().use { tcp ->
            tcp.soTimeout = timeoutMs; tcp.tcpNoDelay = true
            tcp.connect(InetSocketAddress(target.host, target.port), timeoutMs)
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(tm()), java.security.SecureRandom())
            val ssl = ctx.socketFactory.createSocket(tcp, target.effectiveSni, target.port, true) as SSLSocket
            ssl.soTimeout = timeoutMs
            try {
                val p = ssl.sslParameters
                p.serverNames = listOf(javax.net.ssl.SNIHostName(target.effectiveSni))
                ssl.sslParameters = p
            } catch (_: Exception) {}
            if (splitAt > 0) Thread.sleep(splitAt.coerceAtMost(20).toLong())
            ssl.startHandshake()
            val cert = ssl.session.peerCertificates.firstOrNull() as? X509Certificate
            TlsProbeResult(true, ssl.session.protocol, ssl.session.cipherSuite, cert,
                cert?.let { extractSans(it) } ?: emptyList(), cert?.let { extractCn(it) }, fragmentAt = splitAt)
        }
    } catch (e: Exception) {
        TlsProbeResult(false, error = e.message ?: e::class.simpleName, fragmentAt = splitAt)
    }

    companion object {
        fun extractSans(cert: X509Certificate): List<String> = try {
            (cert.subjectAlternativeNames ?: emptyList()).mapNotNull { e ->
                if (e.size >= 2 && (e[0] as? Int) == 2) e[1]?.toString() else null
            }
        } catch (_: Exception) { emptyList() }

        fun extractCn(cert: X509Certificate): String? = try {
            cert.subjectX500Principal.name.split(",").map { it.trim() }
                .firstOrNull { it.startsWith("CN=", true) }?.substringAfter("=")
        } catch (_: Exception) { null }

        fun matchDnsName(pattern: String, host: String): Boolean {
            val p = pattern.trim().lowercase().trimEnd('.')
            val h = host.trim().lowercase().trimEnd('.')
            if (p == h) return true
            if (!p.startsWith("*.")) return false
            val suffix = p.removePrefix("*")
            if (!h.endsWith(suffix)) return false
            val left = h.removeSuffix(suffix)
            return left.isNotEmpty() && !left.contains('.')
        }
        fun sanContains(sans: List<String>, host: String) = sans.any { matchDnsName(it, host) }
        fun cnEqualsOrWildcard(cn: String?, host: String) = cn != null && matchDnsName(cn, host)
    }
}

object TcpConnect {
    fun isAlive(host: String, port: Int, timeoutMs: Int): Boolean = try {
        Socket().use { it.connect(InetSocketAddress(host, port), timeoutMs); true }
    } catch (_: Exception) { false }
}
