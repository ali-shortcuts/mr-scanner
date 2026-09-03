package com.mrscanner.omega.core.fingerprint

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import kotlin.random.Random

/**
 * Real JARM (Active TLS Server Fingerprinting), ported from the official
 * salesforce/jarm Python implementation (BSD-3-Clause, John Althouse /
 * Andrew Smart / RJ Nunaly / Mike Brady, Python port by Caleb Yu —
 * https://github.com/salesforce/jarm/blob/master/jarm.py).
 *
 * This replaces the old JarmLite placeholder, which was just
 * `"$protocol|$cipher".hashCode()` — not a TLS fingerprint at all, just
 * a hash of whatever one plugin happened to already know.
 *
 * Validation approach, since this environment can't make arbitrary
 * outbound network connections to test against a live reference: the
 * packet-building and response-parsing logic (everything except the
 * raw socket I/O itself) was cross-checked offline against the actual
 * Python source — fixed cipher-list ordering, the fuzzy-hash algorithm,
 * and response parsing were all run through the unmodified reference
 * functions with synthetic inputs and compared byte-for-byte against
 * this Kotlin port (see JarmProbeTest). The socket I/O itself
 * (connect/write/read) has no algorithmic ambiguity to get wrong, and
 * mirrors the same pattern already used elsewhere in this codebase
 * (TlsProbe.kt / FragmentingSocket.kt).
 */
object JarmProbe {

    // ---- Probe configuration (mirrors main()'s ten fixed probe tuples) ----
    private data class ProbeSpec(
        val version: String, val cipherList: String, val cipherOrder: String,
        val grease: Boolean, val rareAlpn: Boolean, val versionSupport: String, val extOrder: String
    )

    private val PROBES = listOf(
        ProbeSpec("TLS_1.2", "ALL", "FORWARD", false, false, "1.2_SUPPORT", "REVERSE"),
        ProbeSpec("TLS_1.2", "ALL", "REVERSE", false, false, "1.2_SUPPORT", "FORWARD"),
        ProbeSpec("TLS_1.2", "ALL", "TOP_HALF", false, false, "NO_SUPPORT", "FORWARD"),
        ProbeSpec("TLS_1.2", "ALL", "BOTTOM_HALF", false, true, "NO_SUPPORT", "FORWARD"),
        ProbeSpec("TLS_1.2", "ALL", "MIDDLE_OUT", true, true, "NO_SUPPORT", "REVERSE"),
        ProbeSpec("TLS_1.1", "ALL", "FORWARD", false, false, "NO_SUPPORT", "FORWARD"),
        ProbeSpec("TLS_1.3", "ALL", "FORWARD", false, false, "1.3_SUPPORT", "REVERSE"),
        ProbeSpec("TLS_1.3", "ALL", "REVERSE", false, false, "1.3_SUPPORT", "FORWARD"),
        ProbeSpec("TLS_1.3", "NO1.3", "FORWARD", false, false, "1.3_SUPPORT", "FORWARD"),
        ProbeSpec("TLS_1.3", "ALL", "MIDDLE_OUT", true, false, "1.3_SUPPORT", "REVERSE")
    )

    data class ProbeOutcome(val raw: String, val timedOut: Boolean, val socketError: Boolean)

    /** Runs all 10 probes against [host]:[port] over real sockets and returns the final 62-char hash. */
    fun compute(host: String, port: Int = 443, timeoutMs: Int = 6_000): String {
        val results = PROBES.map { spec -> runOneProbe(host, port, spec, timeoutMs) }
        if (results.any { it.timedOut }) {
            // Matches the reference: any single timeout blanks the whole scan (a partial JARM is misleading).
            return jarmHash(List(10) { "|||" }.joinToString(","))
        }
        return jarmHash(results.joinToString(",") { it.raw })
    }

    private fun runOneProbe(host: String, port: Int, spec: ProbeSpec, timeoutMs: Int): ProbeOutcome {
        return try {
            val payload = buildClientHello(host, spec)
            Socket().use { sock ->
                sock.connect(InetSocketAddress(host, port), timeoutMs)
                sock.soTimeout = timeoutMs
                sock.getOutputStream().write(payload)
                sock.getOutputStream().flush()
                val buf = ByteArray(1484)
                val n = try { sock.getInputStream().read(buf) } catch (_: IOException) { -1 }
                if (n <= 0) ProbeOutcome("|||", timedOut = false, socketError = true)
                else ProbeOutcome(readPacket(buf.copyOf(n)), timedOut = false, socketError = false)
            }
        } catch (_: java.net.SocketTimeoutException) {
            ProbeOutcome("|||", timedOut = true, socketError = false)
        } catch (_: Exception) {
            ProbeOutcome("|||", timedOut = false, socketError = true)
        }
    }

    // ==================== Packet building ====================

    private fun chooseGrease(rng: Random = Random.Default): ByteArray {
        val list = listOf(0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a, 0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa)
        val b = list[rng.nextInt(list.size)].toByte()
        return byteArrayOf(b, b) // GREASE values are always two identical bytes, e.g. 0x0a0a
    }

    internal val CIPHERS_ALL: List<ByteArray> = listOf(
        "0016", "0033", "0067", "c09e", "c0a2", "009e", "0039", "006b", "c09f", "c0a3", "009f", "0045", "00be", "0088", "00c4",
        "009a", "c008", "c009", "c023", "c0ac", "c0ae", "c02b", "c00a", "c024", "c0ad", "c0af", "c02c", "c072", "c073", "cca9",
        "1302", "1301", "cc14", "c007", "c012", "c013", "c027", "c02f", "c014", "c028", "c030", "c060", "c061", "c076", "c077",
        "cca8", "1305", "1304", "1303", "cc13", "c011", "000a", "002f", "003c", "c09c", "c0a0", "009c", "0035", "003d", "c09d",
        "c0a1", "009d", "0041", "00ba", "0084", "00c0", "0007", "0004", "0005"
    ).map { hexToBytes(it) }

    internal val CIPHERS_NO13: List<ByteArray> = listOf(
        "0016", "0033", "0067", "c09e", "c0a2", "009e", "0039", "006b", "c09f", "c0a3", "009f", "0045", "00be", "0088", "00c4",
        "009a", "c008", "c009", "c023", "c0ac", "c0ae", "c02b", "c00a", "c024", "c0ad", "c0af", "c02c", "c072", "c073", "cca9",
        "cc14", "c007", "c012", "c013", "c027", "c02f", "c014", "c028", "c030", "c060", "c061", "c076", "c077", "cca8", "cc13",
        "c011", "000a", "002f", "003c", "c09c", "c0a0", "009c", "0035", "003d", "c09d", "c0a1", "009d", "0041", "00ba", "0084",
        "00c0", "0007", "0004", "0005"
    ).map { hexToBytes(it) }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> ((Character.digit(hex[i * 2], 16) shl 4) + Character.digit(hex[i * 2 + 1], 16)).toByte() }

    /** Port of cipher_mung() — reorders a list per JARM's probe spec. Verified against the reference
     * for REVERSE/TOP_HALF/BOTTOM_HALF/MIDDLE_OUT on both odd- and even-length lists (see test). */
    internal fun cipherMung(ciphers: List<ByteArray>, request: String): List<ByteArray> {
        val n = ciphers.size
        return when (request) {
            "REVERSE" -> ciphers.reversed()
            "BOTTOM_HALF" -> if (n % 2 == 1) ciphers.subList(n / 2 + 1, n) else ciphers.subList(n / 2, n)
            "TOP_HALF" -> {
                val out = mutableListOf<ByteArray>()
                if (n % 2 == 1) out += ciphers[n / 2]
                out += cipherMung(cipherMung(ciphers, "REVERSE"), "BOTTOM_HALF")
                out
            }
            "MIDDLE_OUT" -> {
                val out = mutableListOf<ByteArray>()
                val middle = n / 2
                if (n % 2 == 1) {
                    out += ciphers[middle]
                    for (i in 1..middle) { out += ciphers[middle + i]; out += ciphers[middle - i] }
                } else {
                    for (i in 1..middle) { out += ciphers[middle - 1 + i]; out += ciphers[middle - i] }
                }
                out
            }
            else -> ciphers
        }
    }

    private fun getCiphers(spec: ProbeSpec, rng: Random): ByteArray {
        var list = if (spec.cipherList == "ALL") CIPHERS_ALL else CIPHERS_NO13
        if (spec.cipherOrder != "FORWARD") list = cipherMung(list, spec.cipherOrder)
        val out = java.io.ByteArrayOutputStream()
        if (spec.grease) out.write(chooseGrease(rng))
        list.forEach { out.write(it) }
        return out.toByteArray()
    }

    private fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())
    private fun u8(v: Int) = byteArrayOf(v.toByte())

    private fun extensionServerName(host: String): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x00, 0x00))
        out.write(u16(hostBytes.size + 5))
        out.write(u16(hostBytes.size + 3))
        out.write(u8(0x00))
        out.write(u16(hostBytes.size))
        out.write(hostBytes)
        return out.toByteArray()
    }

    private val ALPN_ALL = listOf("http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq").map {
        byteArrayOf(it.length.toByte()) + it.toByteArray(Charsets.US_ASCII)
    }
    private val ALPN_RARE = listOf("http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq").map {
        byteArrayOf(it.length.toByte()) + it.toByteArray(Charsets.US_ASCII)
    }

    private fun appLayerProtoNegotiation(spec: ProbeSpec): ByteArray {
        var alpns = if (spec.rareAlpn) ALPN_RARE else ALPN_ALL
        if (spec.extOrder != "FORWARD") alpns = cipherMung(alpns, spec.extOrder)
        val all = java.io.ByteArrayOutputStream(); alpns.forEach { all.write(it) }
        val allBytes = all.toByteArray()
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x00, 0x10))
        out.write(u16(allBytes.size + 2))
        out.write(u16(allBytes.size))
        out.write(allBytes)
        return out.toByteArray()
    }

    private fun keyShare(grease: Boolean, rng: Random): ByteArray {
        val share = java.io.ByteArrayOutputStream()
        if (grease) { share.write(chooseGrease(rng)); share.write(byteArrayOf(0x00, 0x01, 0x00)) }
        share.write(byteArrayOf(0x00, 0x1d)) // group: x25519
        share.write(byteArrayOf(0x00, 0x20)) // key_exchange_length: 32
        share.write(rng.nextBytes(32))
        val shareBytes = share.toByteArray()
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x00, 0x33))
        out.write(u16(shareBytes.size + 2))
        out.write(u16(shareBytes.size))
        out.write(shareBytes)
        return out.toByteArray()
    }

    private fun supportedVersions(spec: ProbeSpec, grease: Boolean, rng: Random): ByteArray {
        var tls = if (spec.versionSupport == "1.2_SUPPORT") listOf("0301", "0302", "0303") else listOf("0301", "0302", "0303", "0304")
        var tlsBytes = tls.map { hexToBytes(it) }
        if (spec.extOrder != "FORWARD") tlsBytes = cipherMung(tlsBytes, spec.extOrder)
        val versions = java.io.ByteArrayOutputStream()
        if (grease) versions.write(chooseGrease(rng))
        tlsBytes.forEach { versions.write(it) }
        val vBytes = versions.toByteArray()
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x00, 0x2b))
        out.write(u16(vBytes.size + 1))
        out.write(u8(vBytes.size))
        out.write(vBytes)
        return out.toByteArray()
    }

    private fun getExtensions(host: String, spec: ProbeSpec, rng: Random): ByteArray {
        val all = java.io.ByteArrayOutputStream()
        var grease = false
        if (spec.grease) { all.write(chooseGrease(rng)); all.write(byteArrayOf(0x00, 0x00)); grease = true }
        all.write(extensionServerName(host))
        all.write(byteArrayOf(0x00, 0x17, 0x00, 0x00)) // extended_master_secret
        all.write(byteArrayOf(0x00, 0x01, 0x00, 0x01, 0x01)) // max_fragment_length
        all.write(byteArrayOf(0xff.toByte(), 0x01, 0x00, 0x01, 0x00)) // renegotiation_info
        all.write(byteArrayOf(0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19)) // supported_groups
        all.write(byteArrayOf(0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)) // ec_point_formats
        all.write(byteArrayOf(0x00, 0x23, 0x00, 0x00)) // session_ticket
        all.write(appLayerProtoNegotiation(spec))
        all.write(byteArrayOf(0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01)) // signature_algorithms
        all.write(keyShare(grease, rng))
        all.write(byteArrayOf(0x00, 0x2d, 0x00, 0x02, 0x01, 0x01)) // psk_key_exchange_modes
        if (spec.version == "TLS_1.3" || spec.versionSupport == "1.2_SUPPORT") all.write(supportedVersions(spec, grease, rng))
        val allBytes = all.toByteArray()
        val out = java.io.ByteArrayOutputStream()
        out.write(u16(allBytes.size))
        out.write(allBytes)
        return out.toByteArray()
    }

    private fun buildClientHello(host: String, spec: ProbeSpec, rng: Random = Random.Default): ByteArray {
        val payload = java.io.ByteArrayOutputStream()
        payload.write(0x16)
        val recordVersion: ByteArray
        val helloVersion: ByteArray
        when (spec.version) {
            "TLS_1.3" -> { recordVersion = byteArrayOf(0x03, 0x01); helloVersion = byteArrayOf(0x03, 0x03) }
            "TLS_1" -> { recordVersion = byteArrayOf(0x03, 0x01); helloVersion = byteArrayOf(0x03, 0x01) }
            "TLS_1.1" -> { recordVersion = byteArrayOf(0x03, 0x02); helloVersion = byteArrayOf(0x03, 0x02) }
            else -> { recordVersion = byteArrayOf(0x03, 0x03); helloVersion = byteArrayOf(0x03, 0x03) } // TLS_1.2
        }
        payload.write(recordVersion)

        val clientHello = java.io.ByteArrayOutputStream()
        clientHello.write(helloVersion)
        clientHello.write(rng.nextBytes(32)) // client random
        val sessionId = rng.nextBytes(32)
        clientHello.write(u8(sessionId.size))
        clientHello.write(sessionId)

        val ciphers = getCiphers(spec, rng)
        clientHello.write(u16(ciphers.size))
        clientHello.write(ciphers)
        clientHello.write(0x01) // compression methods length
        clientHello.write(0x00) // null compression

        clientHello.write(getExtensions(host, spec, rng))

        val chBytes = clientHello.toByteArray()
        val handshake = java.io.ByteArrayOutputStream()
        handshake.write(0x01) // handshake type: client_hello
        val lenBytes = ByteArray(3)
        lenBytes[0] = ((chBytes.size ushr 16) and 0xff).toByte()
        lenBytes[1] = ((chBytes.size ushr 8) and 0xff).toByte()
        lenBytes[2] = (chBytes.size and 0xff).toByte()
        handshake.write(lenBytes)
        handshake.write(chBytes)

        val hsBytes = handshake.toByteArray()
        payload.write(u16(hsBytes.size))
        payload.write(hsBytes)
        return payload.toByteArray()
    }

    // ==================== Response parsing ====================

    /** Port of read_packet(). [data] is the raw bytes received from the socket. */
    internal fun readPacket(data: ByteArray): String {
        try {
            if (data.isEmpty()) return "|||"
            val u = { i: Int -> data[i].toInt() and 0xff }
            if (u(0) == 21) return "|||"
            if (u(0) == 22 && data.size > 5 && u(5) == 2) {
                val serverHelloLength = (u(3) shl 8) or u(4)
                if (data.size <= 43) return "|||"
                val counter = u(43)
                if (data.size < counter + 46) return "|||"
                val selectedCipher = data.copyOfRange(counter + 44, counter + 46)
                val version = data.copyOfRange(9, 11)
                val sb = StringBuilder()
                sb.append(selectedCipher.joinToString("") { "%02x".format(it) })
                sb.append("|")
                sb.append(version.joinToString("") { "%02x".format(it) })
                sb.append("|")
                sb.append(extractExtensionInfo(data, counter, serverHelloLength))
                return sb.toString()
            }
            return "|||"
        } catch (_: Exception) {
            return "|||"
        }
    }

    /** Port of extract_extension_info() + find_extension(). */
    private fun extractExtensionInfo(data: ByteArray, counter: Int, serverHelloLength: Int): String {
        try {
            val u = { i: Int -> if (i < data.size) data[i].toInt() and 0xff else -1 }
            if (u(counter + 47) == 11) return "|"
            val a = if (counter + 53 <= data.size) data.copyOfRange(counter + 50, counter + 53) else null
            val b = if (data.size >= 85) data.copyOfRange(82, 85) else null
            if ((a != null && a.contentEquals(byteArrayOf(0x0e, 0xac.toByte(), 0x0b))) ||
                (b != null && b.contentEquals(byteArrayOf(0x0f, 0xf0.toByte(), 0x0b)))) return "|"
            if (counter + 42 >= serverHelloLength) return "|"

            var count = 49 + counter
            val length = (u(counter + 47) shl 8) or u(counter + 48)
            val maximum = length + (count - 1)
            val types = mutableListOf<ByteArray>()
            val values = mutableListOf<ByteArray?>()
            while (count < maximum) {
                if (count + 4 > data.size) break
                types += data.copyOfRange(count, count + 2)
                val extLength = (u(count + 2) shl 8) or u(count + 3)
                if (extLength == 0) {
                    count += 4
                    values.add(null)
                } else {
                    if (count + 4 + extLength > data.size) break
                    values += data.copyOfRange(count + 4, count + 4 + extLength)
                    count += extLength + 4
                }
            }
            val alpnType = byteArrayOf(0x00, 0x10)
            var alpn = ""
            for (i in types.indices) {
                if (types[i].contentEquals(alpnType)) {
                    val v = values[i]
                    if (v != null && v.size > 3) alpn = String(v, 3, v.size - 3, Charsets.US_ASCII)
                    break
                }
            }
            val sb = StringBuilder(alpn).append("|")
            for (i in types.indices) {
                sb.append(types[i].joinToString("") { "%02x".format(it) })
                if (i != types.size - 1) sb.append("-")
            }
            return sb.toString()
        } catch (_: IndexOutOfBoundsException) {
            return "|"
        } catch (_: Exception) {
            return "|"
        }
    }

    // ==================== Fuzzy hash ====================

    /** Cipher list used ONLY by cipherBytes() for the fuzzy hash index — a DIFFERENT (shorter, sorted) list
     * than the ClientHello cipher list above. Generated directly from the reference Python source's own
     * list (see the commit that added this file) rather than hand-transcribed, after an earlier
     * hand-transcription attempt of CIPHERS_ALL turned out to have a duplicated/misplaced entry. */
    private val HASH_CIPHER_INDEX: List<String> = listOf(
        "0004", "0005", "0007", "000a", "0016", "002f", "0033", "0035", "0039", "003c", "003d", "0041", "0045", "0067",
        "006b", "0084", "0088", "009a", "009c", "009d", "009e", "009f", "00ba", "00be", "00c0", "00c4", "c007", "c008",
        "c009", "c00a", "c011", "c012", "c013", "c014", "c023", "c024", "c027", "c028", "c02b", "c02c", "c02f", "c030",
        "c060", "c061", "c072", "c073", "c076", "c077", "c09c", "c09d", "c09e", "c09f", "c0a0", "c0a1", "c0a2", "c0a3",
        "c0ac", "c0ad", "c0ae", "c0af", "cc13", "cc14", "cca8", "cca9", "1301", "1302", "1303", "1304", "1305"
    )

    internal fun cipherBytes(cipher: String): String {
        if (cipher.isEmpty()) return "00"
        val idx = HASH_CIPHER_INDEX.indexOf(cipher)
        val count = if (idx < 0) HASH_CIPHER_INDEX.size + 1 else idx + 1
        val hex = Integer.toHexString(count)
        return if (hex.length < 2) "0$hex" else hex
    }

    internal fun versionByte(version: String): String {
        if (version.isEmpty()) return "0"
        val options = "abcdef"
        val count = version[3] - '0'
        return options[count].toString()
    }

    /** Port of jarm_hash(). [jarmRaw] is 10 comma-separated "cipher|version|alpn|extlist" segments. */
    internal fun jarmHash(jarmRaw: String): String {
        if (jarmRaw == List(10) { "|||" }.joinToString(",")) return "0".repeat(62)
        val fuzzy = StringBuilder()
        val alpnsAndExt = StringBuilder()
        for (handshake in jarmRaw.split(",")) {
            val c = handshake.split("|")
            fuzzy.append(cipherBytes(c.getOrElse(0) { "" }))
            fuzzy.append(versionByte(c.getOrElse(1) { "" }))
            alpnsAndExt.append(c.getOrElse(2) { "" })
            alpnsAndExt.append(c.getOrElse(3) { "" })
        }
        val sha256 = MessageDigest.getInstance("SHA-256").digest(alpnsAndExt.toString().toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        fuzzy.append(sha256.substring(0, 32))
        return fuzzy.toString()
    }
}
