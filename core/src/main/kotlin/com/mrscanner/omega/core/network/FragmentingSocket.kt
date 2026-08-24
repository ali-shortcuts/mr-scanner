package com.mrscanner.omega.core.network

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * Real TLS ClientHello record fragmentation (DPI bypass technique).
 *
 * Builds a TLS 1.2 ClientHello, wraps it as one or more TLS records, and can
 * split the *record payload* across multiple TCP writes at configurable offsets
 * — unlike a simple sleep-before-handshake approximation.
 *
 * Also captures raw ClientHello bytes for JA3/JA4 self-reporting.
 */
object FragmentingSocket {

    data class FragResult(
        val success: Boolean,
        val splitAt: Int?,
        val protocolHint: String? = null,
        val serverHelloOk: Boolean = false,
        val certificate: X509Certificate? = null,
        val sans: List<String> = emptyList(),
        val cn: String? = null,
        val clientHello: ByteArray = ByteArray(0),
        val ja3: String? = null,
        val error: String? = null,
        val mode: String = "record-fragment"
    )

    /**
     * @param fragmentAt null = single TLS record write; Int = split ClientHello
     *        plaintext across two TLS records after N bytes (record fragmentation).
     *        Additional multi-point splits use [multiSplit].
     */
    fun probe(
        host: String,
        port: Int = 443,
        sni: String = host,
        timeoutMs: Int = 5_000,
        fragmentAt: Int? = null,
        multiSplit: IntArray = intArrayOf()
    ): FragResult {
        val hello = ClientHelloBuilder.build(sni)
        val ja3 = Ja3Calculator.fromClientHello(hello)
        return try {
            Socket().use { tcp ->
                tcp.tcpNoDelay = true
                tcp.soTimeout = timeoutMs
                tcp.connect(InetSocketAddress(host, port), timeoutMs)
                val out = tcp.getOutputStream()
                val input = tcp.getInputStream()

                when {
                    multiSplit.isNotEmpty() -> writeMultiRecordFragmented(out, hello, multiSplit)
                    fragmentAt != null && fragmentAt > 0 -> writeRecordFragmented(out, hello, fragmentAt)
                    else -> writeSingleRecord(out, hello)
                }
                out.flush()

                // Read ServerHello / Certificate flight (best-effort parse)
                val flight = readTlsFlight(input, timeoutMs)
                if (!flight.gotServerHello) {
                    // Fallback: some middleboxes need full SSLSocket after partial — try layered
                    return fallbackSsl(host, port, sni, timeoutMs, hello, ja3, fragmentAt)
                }
                FragResult(
                    success = true,
                    splitAt = fragmentAt,
                    protocolHint = flight.versionHint,
                    serverHelloOk = true,
                    certificate = flight.cert,
                    sans = flight.cert?.let { TlsProbe.extractSans(it) } ?: emptyList(),
                    cn = flight.cert?.let { TlsProbe.extractCn(it) },
                    clientHello = hello,
                    ja3 = ja3,
                    mode = if (fragmentAt != null) "record-fragment" else "single-record"
                )
            }
        } catch (e: Exception) {
            // Last resort: standard SSLSocket for connectivity baseline
            fallbackSsl(host, port, sni, timeoutMs, hello, ja3, fragmentAt, e.message)
        }
    }

    private fun fallbackSsl(
        host: String,
        port: Int,
        sni: String,
        timeoutMs: Int,
        hello: ByteArray,
        ja3: String?,
        fragmentAt: Int?,
        priorError: String? = null
    ): FragResult {
        return try {
            val tm = trustAll()
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(tm), SecureRandom())
            (ctx.socketFactory.createSocket() as SSLSocket).use { s ->
                s.soTimeout = timeoutMs
                s.connect(InetSocketAddress(host, port), timeoutMs)
                try {
                    val p = s.sslParameters
                    p.serverNames = listOf(SNIHostName(sni))
                    s.sslParameters = p
                } catch (_: Exception) {}
                s.startHandshake()
                val cert = s.session.peerCertificates.firstOrNull() as? X509Certificate
                FragResult(
                    success = true,
                    splitAt = fragmentAt,
                    protocolHint = s.session.protocol,
                    serverHelloOk = true,
                    certificate = cert,
                    sans = cert?.let { TlsProbe.extractSans(it) } ?: emptyList(),
                    cn = cert?.let { TlsProbe.extractCn(it) },
                    clientHello = hello,
                    ja3 = ja3,
                    mode = "ssl-fallback",
                    error = priorError
                )
            }
        } catch (e: Exception) {
            FragResult(
                success = false,
                splitAt = fragmentAt,
                clientHello = hello,
                ja3 = ja3,
                error = listOfNotNull(priorError, e.message).joinToString(" | "),
                mode = "failed"
            )
        }
    }

    private fun writeSingleRecord(out: OutputStream, handshakeBody: ByteArray) {
        // handshake type already inside body; wrap as handshake record
        out.write(tlsRecord(0x16, handshakeBody))
    }

    /**
     * Record fragmentation: split handshake message into multiple TLS records
     * at [splitAt] bytes of the handshake payload (including handshake header).
     */
    private fun writeRecordFragmented(out: OutputStream, handshakeBody: ByteArray, splitAt: Int) {
        val at = splitAt.coerceIn(1, handshakeBody.size - 1)
        val a = handshakeBody.copyOfRange(0, at)
        val b = handshakeBody.copyOfRange(at, handshakeBody.size)
        out.write(tlsRecord(0x16, a))
        out.flush()
        // tiny pacing helps some DPI paths without faking the crypto
        Thread.sleep(2)
        out.write(tlsRecord(0x16, b))
    }

    private fun writeMultiRecordFragmented(out: OutputStream, handshakeBody: ByteArray, points: IntArray) {
        val cuts = (points.toList() + handshakeBody.size).map { it.coerceIn(1, handshakeBody.size) }.distinct().sorted()
        var prev = 0
        for (c in cuts) {
            if (c <= prev) continue
            out.write(tlsRecord(0x16, handshakeBody.copyOfRange(prev, c)))
            out.flush()
            Thread.sleep(1)
            prev = c
        }
        if (prev < handshakeBody.size) {
            out.write(tlsRecord(0x16, handshakeBody.copyOfRange(prev, handshakeBody.size)))
        }
    }

    private fun tlsRecord(type: Int, payload: ByteArray): ByteArray {
        // TLS 1.0 record version for max middlebox compatibility on ClientHello
        val bb = ByteBuffer.allocate(5 + payload.size)
        bb.put(type.toByte())
        bb.putShort(0x0301) // TLS 1.0
        bb.putShort(payload.size.toShort())
        bb.put(payload)
        return bb.array()
    }

    private data class Flight(
        val gotServerHello: Boolean,
        val versionHint: String?,
        val cert: X509Certificate?
    )

    private fun readTlsFlight(input: InputStream, timeoutMs: Int): Flight {
        val buf = ByteArray(8192)
        var total = ByteArray(0)
        val deadline = System.currentTimeMillis() + timeoutMs
        var gotSH = false
        var cert: X509Certificate? = null
        var ver: String? = null
        while (System.currentTimeMillis() < deadline) {
            val available = try { input.available() } catch (_: Exception) { 0 }
            if (available <= 0) {
                // blocking read one byte to wait
                val n = try {
                    input.read(buf, 0, 1)
                } catch (_: Exception) { -1 }
                if (n <= 0) break
                total += buf.copyOf(n)
            } else {
                val n = input.read(buf, 0, minOf(buf.size, available))
                if (n <= 0) break
                total += buf.copyOf(n)
            }
            // parse records
            var off = 0
            while (off + 5 <= total.size) {
                val typ = total[off].toInt() and 0xff
                val len = ((total[off + 3].toInt() and 0xff) shl 8) or (total[off + 4].toInt() and 0xff)
                if (off + 5 + len > total.size) break
                val payload = total.copyOfRange(off + 5, off + 5 + len)
                if (typ == 0x16 && payload.isNotEmpty()) {
                    // may contain multiple handshake messages
                    var p = 0
                    while (p + 4 <= payload.size) {
                        val hsType = payload[p].toInt() and 0xff
                        val hsLen = ((payload[p + 1].toInt() and 0xff) shl 16) or
                            ((payload[p + 2].toInt() and 0xff) shl 8) or
                            (payload[p + 3].toInt() and 0xff)
                        if (p + 4 + hsLen > payload.size) break
                        val body = payload.copyOfRange(p + 4, p + 4 + hsLen)
                        when (hsType) {
                            2 -> { // ServerHello
                                gotSH = true
                                if (body.size >= 2) {
                                    val major = body[0].toInt() and 0xff
                                    val minor = body[1].toInt() and 0xff
                                    ver = "TLS $major.$minor"
                                }
                            }
                            11 -> { // Certificate
                                cert = parseFirstCert(body) ?: cert
                            }
                        }
                        p += 4 + hsLen
                    }
                }
                off += 5 + len
            }
            if (gotSH && cert != null) break
            if (gotSH && total.size > 400) break
        }
        return Flight(gotSH, ver, cert)
    }

    private fun parseFirstCert(certMsg: ByteArray): X509Certificate? {
        return try {
            if (certMsg.size < 3) return null
            // certs length 3 bytes
            var o = 3
            if (o + 3 > certMsg.size) return null
            val certLen = ((certMsg[o].toInt() and 0xff) shl 16) or
                ((certMsg[o + 1].toInt() and 0xff) shl 8) or
                (certMsg[o + 2].toInt() and 0xff)
            o += 3
            if (o + certLen > certMsg.size) return null
            val der = certMsg.copyOfRange(o, o + certLen)
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCertificate(der.inputStream()) as X509Certificate
        } catch (_: Exception) {
            null
        }
    }

    private fun trustAll() = object : X509TrustManager {
        override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private operator fun ByteArray.plus(other: ByteArray): ByteArray {
        val o = ByteArray(size + other.size)
        System.arraycopy(this, 0, o, 0, size)
        System.arraycopy(other, 0, o, size, other.size)
        return o
    }
}

/** Minimal TLS 1.2 ClientHello with SNI + common cipher suites. */
object ClientHelloBuilder {
    private val rnd = SecureRandom()

    fun build(sniHost: String): ByteArray {
        val body = ByteArrayOutputStream()
        // client_version TLS 1.2
        body.write(byteArrayOf(0x03, 0x03))
        // random 32
        val random = ByteArray(32).also { rnd.nextBytes(it) }
        body.write(random)
        // session id empty
        body.write(0)
        // cipher suites
        val ciphers = intArrayOf(
            0xC02F, // ECDHE_RSA_AES_128_GCM_SHA256
            0xC030, // ECDHE_RSA_AES_256_GCM_SHA384
            0xC02B, // ECDHE_ECDSA_AES_128_GCM_SHA256
            0xC02C, // ECDHE_ECDSA_AES_256_GCM_SHA384
            0xCCA8, // ECDHE_RSA_CHACHA20
            0xCCA9, // ECDHE_ECDSA_CHACHA20
            0x009C, // RSA_AES_128_GCM
            0x002F, // RSA_AES_128_CBC_SHA
            0x0035  // RSA_AES_256_CBC_SHA
        )
        body.writeShort(ciphers.size * 2)
        ciphers.forEach { body.writeShort(it) }
        // compression null
        body.write(1)
        body.write(0)
        // extensions
        val exts = ByteArrayOutputStream()
        // SNI
        val sniBytes = sniHost.toByteArray(Charsets.US_ASCII)
        val sniList = ByteArrayOutputStream()
        sniList.write(0) // host_name type
        sniList.writeShort(sniBytes.size)
        sniList.write(sniBytes)
        val sniListBytes = sniList.toByteArray()
        exts.writeShort(0x0000) // server_name
        exts.writeShort(sniListBytes.size + 2)
        exts.writeShort(sniListBytes.size)
        exts.write(sniListBytes)
        // supported_groups
        val groups = intArrayOf(0x001d, 0x0017, 0x0018) // x25519, secp256r1, secp384r1
        exts.writeShort(0x000a)
        exts.writeShort(2 + groups.size * 2)
        exts.writeShort(groups.size * 2)
        groups.forEach { exts.writeShort(it) }
        // ec_point_formats
        exts.writeShort(0x000b)
        exts.writeShort(2)
        exts.write(1)
        exts.write(0)
        // signature_algorithms
        val sigs = intArrayOf(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601)
        exts.writeShort(0x000d)
        exts.writeShort(2 + sigs.size * 2)
        exts.writeShort(sigs.size * 2)
        sigs.forEach { exts.writeShort(it) }
        // renegotiation info empty
        exts.writeShort(0xff01)
        exts.writeShort(1)
        exts.write(0)

        val extBytes = exts.toByteArray()
        body.writeShort(extBytes.size)
        body.write(extBytes)

        val ch = body.toByteArray()
        // Handshake header: type=1 ClientHello, length 3 bytes
        val hs = ByteArrayOutputStream()
        hs.write(1)
        hs.write((ch.size shr 16) and 0xff)
        hs.write((ch.size shr 8) and 0xff)
        hs.write(ch.size and 0xff)
        hs.write(ch)
        return hs.toByteArray()
    }

    private fun ByteArrayOutputStream.writeShort(v: Int) {
        write((v shr 8) and 0xff)
        write(v and 0xff)
    }
}

/** JA3 fingerprint from ClientHello handshake bytes (type+len+body). */
object Ja3Calculator {
    fun fromClientHello(handshakeMsg: ByteArray): String {
        // handshakeMsg starts with type(1) len(3) then body
        if (handshakeMsg.size < 40 || handshakeMsg[0].toInt() != 1) return "unknown"
        val body = handshakeMsg.copyOfRange(4, handshakeMsg.size)
        var o = 0
        if (body.size < 34) return "unknown"
        val ver = ((body[0].toInt() and 0xff) shl 8) or (body[1].toInt() and 0xff)
        o = 2 + 32 // version + random
        val sidLen = body[o].toInt() and 0xff; o += 1 + sidLen
        if (o + 2 > body.size) return "unknown"
        val csLen = ((body[o].toInt() and 0xff) shl 8) or (body[o + 1].toInt() and 0xff); o += 2
        val ciphers = mutableListOf<Int>()
        val csEnd = o + csLen
        while (o + 2 <= csEnd && o + 2 <= body.size) {
            ciphers += ((body[o].toInt() and 0xff) shl 8) or (body[o + 1].toInt() and 0xff)
            o += 2
        }
        if (o >= body.size) return "unknown"
        val compLen = body[o].toInt() and 0xff; o += 1 + compLen
        val extTypes = mutableListOf<Int>()
        var groups = listOf<Int>()
        var points = listOf<Int>()
        if (o + 2 <= body.size) {
            val extLen = ((body[o].toInt() and 0xff) shl 8) or (body[o + 1].toInt() and 0xff); o += 2
            val extEnd = o + extLen
            while (o + 4 <= extEnd && o + 4 <= body.size) {
                val et = ((body[o].toInt() and 0xff) shl 8) or (body[o + 1].toInt() and 0xff)
                val el = ((body[o + 2].toInt() and 0xff) shl 8) or (body[o + 3].toInt() and 0xff)
                o += 4
                val eb = if (o + el <= body.size) body.copyOfRange(o, o + el) else ByteArray(0)
                o += el
                if (et != 0x0015) extTypes += et // skip padding
                if (et == 0x000a && eb.size >= 2) { // supported_groups
                    var i = 2
                    val g = mutableListOf<Int>()
                    while (i + 2 <= eb.size) {
                        g += ((eb[i].toInt() and 0xff) shl 8) or (eb[i + 1].toInt() and 0xff); i += 2
                    }
                    groups = g
                }
                if (et == 0x000b && eb.isNotEmpty()) {
                    val n = eb[0].toInt() and 0xff
                    points = eb.drop(1).take(n).map { it.toInt() and 0xff }
                }
            }
        }
        val ja3Str = listOf(
            ver.toString(),
            ciphers.joinToString("-"),
            extTypes.joinToString("-"),
            groups.joinToString("-"),
            points.joinToString("-")
        ).joinToString(",")
        return md5Hex(ja3Str) + "|" + ja3Str.take(80)
    }

    private fun md5Hex(s: String): String {
        val md = java.security.MessageDigest.getInstance("MD5")
        return md.digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
