package com.mrscanner.omega.core.plugin
import com.mrscanner.omega.core.network.MultiResolverDns
import com.mrscanner.omega.core.settings.ConsoleSettings

object PluginRegistry {
    fun createAll(settings: ConsoleSettings): List<ScanPlugin> {
        val multi = MultiResolverDns(settings.customDnsServers, settings.dnsRegion)
        val all = mutableListOf<ScanPlugin>()
        // 22 base
        all += TcpConnectPlugin(); all += DnsPlugin(multi); all += DnsMultiPlugin(multi)
        all += Ipv4Plugin(); all += Ipv6Plugin(); all += HttpPlugin(); all += HttpsPlugin()
        all += TlsPlugin(); all += CertificatePlugin(); all += RedirectPlugin()
        all += HeaderPlugin(); all += ServerPlugin(); all += CompressionPlugin()
        all += HttpVersionPlugin(); all += SecurityHeaderPlugin(); all += CookiePlugin()
        all += RobotsPlugin(); all += SitemapPlugin(); all += FingerprintPlugin()
        all += BannerPlugin(); all += CdnWafPlugin(); all += TlsFingerprintPlugin()
        // 9 bypass
        all += SniFrontingPlugin { settings.sniSpoofCandidates.ifEmpty { listOf("cloudflare.com","www.cloudflare.com","cdnjs.cloudflare.com") } }
        if (settings.testFragmentBypass) all += TlsFragmentationPlugin()
        all += PayloadInjectionPlugin(); all += DohBypassPlugin(); all += HeaderInjectionPlugin()
        all += ZeroRatedPlugin(); all += SniSpoofingPlugin(); all += MisconfigPlugin(); all += CveAuditPlugin()
        // 10 advanced
        all += DnsConsistencyPlugin(multi)
        if (settings.testFragmentBypass) all += RecordFragmentPlugin { settings.recordFragmentSplits }
        all += SniExploitabilityPlugin()
        if (settings.testEch) all += EchPlugin()
        if (settings.testDnsTransport) all += DnsTransportPlugin()
        if (settings.testJa3Self) all += Ja3SelfPlugin()
        if (settings.testCdnEdge) all += CdnEdgePlugin()
        if (settings.testAlpnMatrix) all += AlpnMatrixPlugin()
        if (settings.testQuic) all += QuicPlugin()
        return all
    }

    data class CatalogEntry(val id: String, val name: String, val voting: Boolean, val evidence: String, val group: String)

    fun catalog(): List<CatalogEntry> = listOf(
        CatalogEntry("tcpconnect","TCP Connect",false,"—","base"),
        CatalogEntry("dns","DNS",true,"MODERATE","base"), CatalogEntry("ipv4","IPv4",true,"MODERATE","base"),
        CatalogEntry("ipv6","IPv6",true,"MODERATE","base"), CatalogEntry("http","HTTP",true,"WEAK","base"),
        CatalogEntry("https","HTTPS",true,"MODERATE","base"), CatalogEntry("tls","TLS",true,"STRONG","base"),
        CatalogEntry("certificate","Certificate",true,"STRONG","base"), CatalogEntry("redirect","Redirect",true,"WEAK","base"),
        CatalogEntry("header","Headers",true,"WEAK","base"), CatalogEntry("server","Server",true,"WEAK","base"),
        CatalogEntry("compression","Compression",true,"WEAK","base"), CatalogEntry("httpversion","HTTP Version",true,"WEAK","base"),
        CatalogEntry("securityheader","Security Headers",true,"WEAK","base"), CatalogEntry("cookie","Cookies",true,"WEAK","base"),
        CatalogEntry("robots","robots.txt",true,"WEAK","base"), CatalogEntry("sitemap","sitemap",true,"WEAK","base"),
        CatalogEntry("fingerprint","Fingerprint",true,"MODERATE","base"), CatalogEntry("dnsmulti","DNS Multi",true,"MODERATE","base"),
        CatalogEntry("banner","Banner",true,"WEAK","base"), CatalogEntry("cdnwaf","CDN/WAF",true,"MODERATE","base"),
        CatalogEntry("tlsfingerprint","TLS FP",true,"WEAK","base"),
        CatalogEntry("snifronting","SNI Fronting",true,"STRONG","bypass"), CatalogEntry("tlsfragment","TLS Fragment",true,"DEFINITIVE","bypass"),
        CatalogEntry("payloadinjection","Payload Injection",true,"MODERATE","bypass"), CatalogEntry("dohbypass","DoH",true,"MODERATE","bypass"),
        CatalogEntry("headerinjection","Header Injection",true,"MODERATE","bypass"), CatalogEntry("zerorated","Zero-Rated",true,"STRONG","bypass"),
        CatalogEntry("snispoofing","SNI Spoof",true,"STRONG","bypass"), CatalogEntry("misconfig","Misconfig",true,"MODERATE","bypass"),
        CatalogEntry("cveaudit","CVE Audit",true,"STRONG","bypass"),
        CatalogEntry("plugin.host.dnsconsistency","DNS Consistency",true,"STRONG","advanced"),
        CatalogEntry("plugin.host.recordfragment","Record Fragment",true,"DEFINITIVE","advanced"),
        CatalogEntry("plugin.host.snisan","SNI SAN",true,"DEFINITIVE","advanced"),
        CatalogEntry("plugin.host.ech","ECH",true,"STRONG","advanced"),
        CatalogEntry("plugin.host.dnstransport","DoT/DoQ",true,"MODERATE","advanced"),
        CatalogEntry("plugin.host.ja3self","JA3 Self",false,"—","advanced"),
        CatalogEntry("plugin.host.cdnedge","CDN Edge",true,"MODERATE","advanced"),
        CatalogEntry("plugin.host.alpnmatrix","ALPN",true,"WEAK","advanced"),
        CatalogEntry("plugin.host.quic","QUIC",true,"MODERATE","advanced"),
        CatalogEntry("plugin.host.timeconsistency","Time Consistency",false,"—","advanced")
    )
}
