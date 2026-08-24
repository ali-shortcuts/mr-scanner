package com.mrscanner.omega.core.network

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class FragmentingSocketTest {
    @Test
    fun clientHelloBuildsWithSni() {
        val hello = ClientHelloBuilder.build("example.com")
        assertTrue(hello.size > 50)
        assertEquals(1, hello[0].toInt())
        val asStr = hello.toString(Charsets.ISO_8859_1)
        assertTrue(asStr.contains("example.com"))
    }

    @Test
    fun ja3FromHello() {
        val hello = ClientHelloBuilder.build("example.com")
        val ja3 = Ja3Calculator.fromClientHello(hello)
        assertTrue(ja3.length >= 16)
        assertFalse(ja3 == "unknown")
    }

    @Test
    fun tlsRecordFragmentProbeDoesNotCrash() {
        val r = FragmentingSocket.probe("example.com", fragmentAt = 2, timeoutMs = 4000)
        assertNotNull(r.mode)
        assertTrue(r.clientHello.isNotEmpty())
    }
}
