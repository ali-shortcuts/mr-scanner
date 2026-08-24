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
    val fragmentAt: Int? = null,
    val clientHello: ByteArray = ByteArray(0),
    val ja3: String? = null,
    val mode: String = "ssl"
) {
    fun toShortString() = if (success) "ok/${protocol ?: "?"} mode=$mode cert=${cn ?: "?"}" else "fail:${error ?: "?"}"
}

/**
 * TLS probe facade.
 * Preferred path: FragmentingSocket (real ClientHello record fragmentation).
 * Fallback: classic SSLSocket for environments that block raw handshake crafting.
 */
class TlsProbe(private val timeoutMs: Int = 5_000) {

    fun probe(target: ScanTarget, fragmentAt: Int? = null): TlsProbeResult {
        val frag = FragmentingSocket.probe(
            host = target.host,
            port = target.port,
            sni = target.effectiveSni,
            timeoutMs = timeoutMs,
            fragmentAt = fragmentAt
        )
        if (frag.success || fragmentAt != null) {
            return TlsProbeResult(
                success = frag.success,
                protocol = frag.protocolHint,
                certificate = frag.certificate,
                sans = frag.sans,
                cn = frag.cn,
                error = frag.error,
                fragmentAt = fragmentAt,
                clientHello = frag.clientHello,
                ja3 = frag.ja3,
                mode = frag.mode
            )
        }
        return normalSsl(target)
    }

    fun probeMulti(target: ScanTarget, splits: IntArray): TlsProbeResult {
        val frag = FragmentingSocket.probe(
            host = target.host,
            port = target.port,
            sni = target.effectiveSni,
            timeoutMs = timeoutMs,
            multiSplit = splits
        )
        return TlsProbeResult(
            success = frag.success,
            protocol = frag.protocolHint,
            certificate = frag.certificate,
            sans = frag.sans,
            cn = frag.cn,
            error = frag.error,
            fragmentAt = splits.firstOrNull(),
            clientHello = frag.clientHello,
            ja3 = frag.ja3,
            mode = frag.mode
        )
    }

    private fun normalSsl(target: ScanTarget): TlsProbeResult = try {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(trustAll()), java.security.SecureRandom())
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
            TlsProbeResult(
                success = true,
                protocol = s.session.protocol,
                cipher = s.session.cipherSuite,
                certificate = cert,
                sans = cert?.let { extractSans(it) } ?: emptyList(),
                cn = cert?.let { extractCn(it) },
                mode = "ssl-socket"
            )
        }
    } catch (e: Exception) {
        TlsProbeResult(success = false, error = e.message ?: e::class.simpleName, mode = "ssl-socket")
    }

    private fun trustAll() = object : X509TrustManager {
        override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
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
