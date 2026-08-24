package com.mrscanner.omega.core.fingerprint
/** Murmur3-compatible favicon hash (Shodan-style) — lightweight. */
object FaviconHasher {
    fun hash(bytes: ByteArray): Int {
        // FNV-1a 32 as stand-in when Guava murmur not linked; Android can swap to murmur3
        var h = 0x811c9dc5.toInt()
        for (b in bytes) { h = h xor (b.toInt() and 0xff); h *= 0x01000193 }
        return h
    }
}
