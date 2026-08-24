package com.mrscanner.omega.core.network

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class DoTClientTest {
    @Test
    fun dotQueryDoesNotCrash() {
        val a = DoTClient.queryA("example.com", "1.1.1.1", timeoutMs = 4000, serverName = "cloudflare-dns.com")
        // Network dependent — just ensure structure
        assertTrue(a.rttMs >= 0)
        assertNotNull(a.resolver)
    }

    @Test
    fun dnsWireRoundtripBuilders() {
        val q = DnsUdpClient.buildQuery("example.com", 1)
        assertTrue(q.size > 20)
    }
}
