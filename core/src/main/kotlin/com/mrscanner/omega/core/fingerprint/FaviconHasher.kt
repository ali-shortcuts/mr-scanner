package com.mrscanner.omega.core.fingerprint

import java.util.Base64

/**
 * Shodan-compatible favicon hashing: base64-encode the icon bytes with
 * Python's base64.encodebytes() line wrapping (a newline every 76
 * output characters, including a trailing one - NOT plain unwrapped
 * base64, which hashes to a completely different value), then
 * MurmurHash3 x86_32 (seed 0) the resulting text as a signed 32-bit int.
 * This is exactly what Shodan's http.favicon.hash field is, which is
 * the point - it lets a hash computed here be compared against
 * Shodan's own index of the same icon.
 *
 * murmur3x86_32 itself is verified against the reference mmh3
 * Python package (see FaviconHasherTest) - not assumed from memory.
 */
object FaviconHasher {
    fun hash(bytes: ByteArray): Int = murmur3x86_32(pythonStyleBase64(bytes).toByteArray(Charsets.US_ASCII), 0)

    /** Mimics Python's base64.encodebytes(): standard alphabet, 76-char lines, trailing newline. */
    internal fun pythonStyleBase64(bytes: ByteArray): String {
        val raw = Base64.getEncoder().encodeToString(bytes)
        val sb = StringBuilder()
        var i = 0
        while (i < raw.length) {
            val end = minOf(i + 76, raw.length)
            sb.append(raw, i, end).append('\n')
            i = end
        }
        if (raw.length == 0) sb.append('\n')
        return sb.toString()
    }

    /** MurmurHash3 x86_32 (Austin Appleby, public domain). */
    fun murmur3x86_32(data: ByteArray, seed: Int): Int {
        val c1 = 0xcc9e2d51L.toInt()
        val c2 = 0x1b873593L.toInt()
        var h = seed
        val nblocks = data.size / 4
        for (i in 0 until nblocks) {
            val off = i * 4
            var k = (data[off].toInt() and 0xff) or
                ((data[off + 1].toInt() and 0xff) shl 8) or
                ((data[off + 2].toInt() and 0xff) shl 16) or
                ((data[off + 3].toInt() and 0xff) shl 24)
            k *= c1
            k = (k shl 15) or (k ushr 17)
            k *= c2
            h = h xor k
            h = (h shl 13) or (h ushr 19)
            h = h * 5 + 0xe6546b64L.toInt()
        }
        val tail = nblocks * 4
        var k1 = 0
        val rem = data.size and 3
        if (rem == 3) k1 = k1 xor ((data[tail + 2].toInt() and 0xff) shl 16)
        if (rem >= 2) k1 = k1 xor ((data[tail + 1].toInt() and 0xff) shl 8)
        if (rem >= 1) {
            k1 = k1 xor (data[tail].toInt() and 0xff)
            k1 *= c1
            k1 = (k1 shl 15) or (k1 ushr 17)
            k1 *= c2
            h = h xor k1
        }
        h = h xor data.size
        h = h xor (h ushr 16)
        h *= 0x85ebca6bL.toInt()
        h = h xor (h ushr 13)
        h *= 0xc2b2ae35L.toInt()
        h = h xor (h ushr 16)
        return h
    }
}
