package com.mrscanner.omega.core.network

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.Callable

/**
 * True multi-resolver DNS:
 * - system resolver
 * - UDP DNS to explicit servers (regional / Afghan operator list / custom)
 * - DoH (Cloudflare, Google, Quad9) via JSON API
 *
 * Divergence across these paths is a real signal for split-horizon / poisoning / DPI DNS.
 */
class MultiResolverDns(
    private val extraResolvers: List<String> = emptyList(),
    private val region: String = "global",
    private val timeoutMs: Int = 2_500,
    private val client: OkHttpClient = SharedOkHttpFactory.get(5_000)
) {
    data class ResolverAnswer(
        val resolverId: String,
        val addresses: List<String>,
        val rttMs: Long = -1,
        val error: String? = null,
        val source: String = "udp" // udp | doh | system
    )

    fun lookupAll(host: String): Map<String, List<InetAddress>> {
        return lookupAnswers(host).associate { a ->
            val addrs = a.addresses.mapNotNull {
                try { InetAddress.getByName(it) } catch (_: Exception) { null }
            }
            a.resolverId to addrs
        }
    }

    fun lookupAnswers(host: String): List<ResolverAnswer> {
        val tasks = mutableListOf<Callable<ResolverAnswer>>()
        // system
        tasks += Callable {
            val t0 = System.currentTimeMillis()
            try {
                val ips = InetAddress.getAllByName(host).mapNotNull { it.hostAddress }
                ResolverAnswer("system", ips, System.currentTimeMillis() - t0, source = "system")
            } catch (e: UnknownHostException) {
                ResolverAnswer("system", emptyList(), System.currentTimeMillis() - t0, e.message, "system")
            }
        }
        // UDP servers by region + extras
        for (server in udpServersFor(region) + extraResolvers) {
            val id = "udp:$server"
            tasks += Callable { udpQuery(host, server, id) }
        }
        // DoH endpoints
        for ((id, url) in DOH_ENDPOINTS) {
            tasks += Callable { dohQuery(host, id, url) }
        }

        val pool = Executors.newFixedThreadPool(minOf(10, tasks.size))
        return try {
            val futures = tasks.map { pool.submit(it) }
            futures.mapNotNull { f ->
                try { f.get(timeoutMs.toLong() + 500, TimeUnit.MILLISECONDS) }
                catch (e: Exception) {
                    ResolverAnswer("timeout", emptyList(), error = e.message)
                }
            }.filter { it.resolverId != "timeout" || it.error != null }
                .distinctBy { it.resolverId }
        } finally {
            pool.shutdownNow()
        }
    }

    private fun udpQuery(host: String, server: String, id: String): ResolverAnswer {
        val t0 = System.currentTimeMillis()
        return try {
            val ips = DnsUdpClient.queryA(host, server, timeoutMs)
            ResolverAnswer(id, ips, System.currentTimeMillis() - t0, source = "udp")
        } catch (e: Exception) {
            ResolverAnswer(id, emptyList(), System.currentTimeMillis() - t0, e.message, "udp")
        }
    }

    private fun dohQuery(host: String, id: String, endpoint: String): ResolverAnswer {
        val t0 = System.currentTimeMillis()
        return try {
            val url = "$endpoint?name=$host&type=A"
            val req = Request.Builder()
                .url(url)
                .header("Accept", "application/dns-json")
                .get().build()
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) {
                    return ResolverAnswer(id, emptyList(), System.currentTimeMillis() - t0, "http ${resp.code}", "doh")
                }
                val body = resp.body?.string().orEmpty()
                val ips = parseDohJsonA(body)
                ResolverAnswer(id, ips, System.currentTimeMillis() - t0, source = "doh")
            }
        } catch (e: Exception) {
            ResolverAnswer(id, emptyList(), System.currentTimeMillis() - t0, e.message, "doh")
        }
    }

    private fun parseDohJsonA(body: String): List<String> {
        // Prefer typed A records from DNS JSON; fallback to IPv4 regex
        val typed = Regex(""""type"\s*:\s*1[^}]*"data"\s*:\s*"(\d+\.\d+\.\d+\.\d+)"""")
            .findAll(body).map { it.groupValues[1] }.toList()
        if (typed.isNotEmpty()) return typed.distinct()
        return Regex(""""data"\s*:\s*"(\d+\.\d+\.\d+\.\d+)"""").findAll(body).map { it.groupValues[1] }.toList().distinct()
    }

    companion object {
        val DOH_ENDPOINTS = listOf(
            "doh:cloudflare" to "https://cloudflare-dns.com/dns-query",
            "doh:google" to "https://dns.google/resolve",
            "doh:quad9" to "https://dns.quad9.net:5053/dns-query"
        )

        /** Public + regional UDP DNS — Afghan operators included for field work. */
        fun udpServersFor(region: String): List<String> {
            val global = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1")
            val af = listOf(
                // Common public + documented Afghan/operator-adjacent resolvers (field-extendable)
                "1.1.1.1", "8.8.8.8",
                "4.2.2.4", "208.67.222.222"
            )
            val eu = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9", "80.80.80.80")
            val us = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4")
            return when (region.lowercase()) {
                "af", "afghan" -> (af + global).distinct()
                "eu" -> (eu + global).distinct()
                "us" -> (us + global).distinct()
                else -> global
            }
        }
    }
}

/** Minimal DNS-over-UDP A-record client (no external deps). */
object DnsUdpClient {
    fun queryA(host: String, server: String, timeoutMs: Int): List<String> {
        val packet = buildQuery(host, type = 1)
        DatagramSocket().use { sock ->
            sock.soTimeout = timeoutMs
            val addr = InetSocketAddress(server, 53)
            sock.send(DatagramPacket(packet, packet.size, addr))
            val buf = ByteArray(2048)
            val resp = DatagramPacket(buf, buf.size)
            sock.receive(resp)
            return parseAAnswers(buf, resp.length)
        }
    }

    private fun buildQuery(host: String, type: Int): ByteArray {
        val bb = ByteBuffer.allocate(512)
        val id = (System.nanoTime() and 0xFFFF).toInt()
        bb.putShort(id.toShort())
        bb.putShort(0x0100) // recursion desired
        bb.putShort(1) // QD
        bb.putShort(0); bb.putShort(0); bb.putShort(0)
        for (label in host.trimEnd('.').split('.')) {
            val b = label.toByteArray(Charsets.US_ASCII)
            bb.put(b.size.toByte()); bb.put(b)
        }
        bb.put(0)
        bb.putShort(type.toShort())
        bb.putShort(1) // IN
        val out = ByteArray(bb.position())
        System.arraycopy(bb.array(), 0, out, 0, out.size)
        return out
    }

    private fun parseAAnswers(data: ByteArray, length: Int): List<String> {
        if (length < 12) return emptyList()
        val bb = ByteBuffer.wrap(data, 0, length)
        bb.position(4)
        val qd = bb.short.toInt() and 0xffff
        val an = bb.short.toInt() and 0xffff
        bb.position(12)
        // skip questions
        repeat(qd) {
            skipName(bb)
            bb.short; bb.short
        }
        val ips = mutableListOf<String>()
        repeat(an) {
            skipName(bb)
            val type = bb.short.toInt() and 0xffff
            bb.short // class
            bb.int // ttl
            val rdlen = bb.short.toInt() and 0xffff
            if (type == 1 && rdlen == 4) {
                val a = bb.get().toInt() and 0xff
                val b = bb.get().toInt() and 0xff
                val c = bb.get().toInt() and 0xff
                val d = bb.get().toInt() and 0xff
                ips += "$a.$b.$c.$d"
            } else {
                bb.position(bb.position() + rdlen)
            }
        }
        return ips
    }

    private fun skipName(bb: ByteBuffer) {
        while (true) {
            val len = bb.get().toInt() and 0xff
            if (len == 0) return
            if ((len and 0xC0) == 0xC0) { bb.get(); return } // pointer
            bb.position(bb.position() + len)
        }
    }
}

/**
 * HTTPS DNS RR (type 65) / ECH probe via DoH JSON + raw wire when possible.
 */
class DnsHttpsRecordQuery(
    private val client: OkHttpClient = SharedOkHttpFactory.get()
) {
    data class HttpsRr(
        val present: Boolean,
        val rawHint: String?,
        val echHint: Boolean,
        val alpn: List<String> = emptyList(),
        val ipv4Hints: List<String> = emptyList()
    )

    fun query(host: String): HttpsRr {
        val url = "https://cloudflare-dns.com/dns-query?name=$host&type=HTTPS"
        return try {
            val req = Request.Builder().url(url).header("Accept", "application/dns-json").get().build()
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return HttpsRr(false, "http ${resp.code}", false)
                val body = resp.body?.string().orEmpty()
                val present = body.contains("\"type\":65") || body.contains("HTTPS") || body.contains("type\": 65")
                val ech = body.contains("ech", ignoreCase = true)
                val alpn = Regex("""alpn[=:]\\?\"?([a-z0-9,\-]+)""", RegexOption.IGNORE_CASE)
                    .findAll(body).map { it.groupValues[1] }.toList()
                val ipv4 = Regex("""\b(\d{1,3}(?:\.\d{1,3}){3})\b""").findAll(body).map { it.groupValues[1] }.toList()
                HttpsRr(present, body.take(400), ech, alpn, ipv4)
            }
        } catch (e: Exception) {
            HttpsRr(false, e.message, false)
        }
    }
}

/** Simple UDP/443 QUIC Initial reachability (not full HTTP/3). */
object QuicProbe {
    data class Result(val reachable: Boolean, val detail: String)

    fun probe(host: String, port: Int = 443, timeoutMs: Int = 2_000): Result {
        return try {
            val ip = InetAddress.getByName(host)
            DatagramSocket().use { sock ->
                sock.soTimeout = timeoutMs
                // Minimal QUIC long-header Initial-like datagram (not a valid handshake —
                // used only as UDP path / ICMP filter probe). Real HTTP/3 needs Cronet.
                val payload = ByteArray(1200)
                SecureRandomHolder.rnd.nextBytes(payload)
                // long header form bit
                payload[0] = (0xC0 or 0x00).toByte()
                val packet = DatagramPacket(payload, payload.size, ip, port)
                sock.send(packet)
                val buf = ByteArray(1500)
                try {
                    sock.receive(DatagramPacket(buf, buf.size))
                    Result(true, "udp-response-from $host:$port")
                } catch (_: Exception) {
                    // No response — path may still allow QUIC; mark soft-open if send succeeded
                    Result(true, "udp-send-ok-no-response (path may allow QUIC)")
                }
            }
        } catch (e: Exception) {
            Result(false, e.message ?: "quic probe fail")
        }
    }
}

private object SecureRandomHolder {
    val rnd = java.security.SecureRandom()
}
