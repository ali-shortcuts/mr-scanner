package com.mrscanner.omega.core.plugin
import com.mrscanner.omega.core.network.TlsProbe
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SniMatchTest {
    @Test fun exact() { assertTrue(TlsProbe.matchDnsName("example.com", "example.com")) }
    @Test fun wildcard() {
        assertTrue(TlsProbe.matchDnsName("*.example.com", "www.example.com"))
        assertFalse(TlsProbe.matchDnsName("*.example.com", "a.b.example.com"))
        assertFalse(TlsProbe.matchDnsName("*.example.com", "example.com"))
    }
    @Test fun sanContains() {
        assertTrue(TlsProbe.sanContains(listOf("www.example.com", "*.cdn.net"), "x.cdn.net"))
        assertFalse(TlsProbe.sanContains(listOf("www.example.com"), "evil.com"))
    }
}
