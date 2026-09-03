package com.mrscanner.omega.core.fingerprint

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Every expected value here was cross-checked against Python's reference
 * `mmh3` package (pip install mmh3) — not taken from memory. See the
 * commit that added this file for the exact commands used.
 */
class FaviconHasherTest {

    @Test
    fun murmur3MatchesReferenceVectors() {
        assertEquals(0, FaviconHasher.murmur3x86_32("".toByteArray(), 0))
        assertEquals(1009084850, FaviconHasher.murmur3x86_32("a".toByteArray(), 0))
        assertEquals(-1681926305, FaviconHasher.murmur3x86_32("ab".toByteArray(), 0))
        assertEquals(-1277324294, FaviconHasher.murmur3x86_32("abc".toByteArray(), 0))
        assertEquals(1139631978, FaviconHasher.murmur3x86_32("abcd".toByteArray(), 0))
        assertEquals(-392455434, FaviconHasher.murmur3x86_32("abcde".toByteArray(), 0))
        assertEquals(-1167338989, FaviconHasher.murmur3x86_32("test".toByteArray(), 0))
        assertEquals(613153351, FaviconHasher.murmur3x86_32("hello".toByteArray(), 0))
    }

    @Test
    fun fullPipelineMatchesShodanConventionReference() {
        // Same 600-byte synthetic blob used to generate the Python reference value.
        val data = (byteArrayOf(137.toByte(), 80, 78, 71, 13, 10, 26, 10) +
            (0..255).map { it.toByte() }.toByteArray() +
            (0..255).map { it.toByte() }.toByteArray() +
            (0..255).map { it.toByte() }.toByteArray()).sliceArray(0 until 600)
        assertEquals(-976150112, FaviconHasher.hash(data))
    }

    @Test
    fun pythonStyleBase64WrapsAt76CharsWithTrailingNewline() {
        val longInput = ByteArray(60) { 'A'.code.toByte() } // encodes to 80 base64 chars, longer than one 76-char line
        val encoded = FaviconHasher.pythonStyleBase64(longInput)
        val lines = encoded.trimEnd('\n').split("\n")
        assertEquals(76, lines[0].length)
        assertEquals(true, encoded.endsWith("\n"))
    }

    @Test
    fun emptyInputEncodesToJustANewline() {
        assertEquals("\n", FaviconHasher.pythonStyleBase64(ByteArray(0)))
    }
}
