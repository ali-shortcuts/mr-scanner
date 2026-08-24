package com.mrscanner.omega.core.network

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * Real DNS-over-TLS (RFC 7858) — TCP/853 + TLS, length-prefixed DNS messages.
 */
object DoTClient {

    data class Answer(
        val resolver: String,
        val addresses: List<String>,
        val rttMs: Long,
        val error: String? = null
    )

    fun queryA(
        host: String,
        resolver: String = "1.1.1.1",
        port: Int = 853,
        timeoutMs: Int = 3_000,
        serverName: String = resolver
    ): Answer {
        val t0 = System.currentTimeMillis()
        return try {
            val tm = object : X509TrustManager {
                override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
                override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(tm), java.security.SecureRandom())
            (ctx.socketFactory.createSocket() as SSLSocket).use { ssl ->
                ssl.soTimeout = timeoutMs
                ssl.connect(InetSocketAddress(resolver, port), timeoutMs)
                try {
                    val p = ssl.sslParameters
                    p.serverNames = listOf(SNIHostName(serverName))
                    ssl.sslParameters = p
                } catch (_: Exception) {}
                ssl.startHandshake()
                val query = DnsUdpClient.buildQuery(host, type = 1)
                val out = DataOutputStream(ssl.outputStream)
                out.writeShort(query.size)
                out.write(query)
                out.flush()
                val input = DataInputStream(ssl.inputStream)
                val len = input.readUnsignedShort()
                val resp = ByteArray(len)
                input.readFully(resp)
                val ips = DnsUdpClient.parseAAnswers(resp, resp.size)
                Answer(resolver, ips, System.currentTimeMillis() - t0)
            }
        } catch (e: Exception) {
            Answer(resolver, emptyList(), System.currentTimeMillis() - t0, e.message)
        }
    }

    fun probeMatrix(host: String, timeoutMs: Int = 3_000): List<Answer> {
        val resolvers = listOf(
            "1.1.1.1" to "cloudflare-dns.com",
            "8.8.8.8" to "dns.google",
            "9.9.9.9" to "dns.quad9.net"
        )
        return resolvers.map { (ip, sni) -> queryA(host, ip, 853, timeoutMs, sni) }
    }
}
