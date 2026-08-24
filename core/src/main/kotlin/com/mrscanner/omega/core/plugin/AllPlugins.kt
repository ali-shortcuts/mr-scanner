package com.mrscanner.omega.core.plugin

import com.mrscanner.omega.core.network.*
import okhttp3.Request
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/* ========== BASE (22) ========== */

class TcpConnectPlugin : ScanPlugin {
    override val id = "tcpconnect"; override val displayName = "TCP Connect"
    override val evidenceClass: EvidenceClass? = null
    override val cost = PluginCost(400, 0, 1)
    override val dependsOn = emptySet<String>()
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.WEAK, t0) {
            ctx.ensureActive()
            val alive = TcpConnect.isAlive(target.host, target.port, ctx.timeoutMs.toInt().coerceIn(200, 30_000))
            ctx.put("alive", alive)
            PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK, if (alive) "alive" else "dead"),
                if (alive) "alive ${target.host}:${target.port}" else "dead ${target.host}:${target.port}",
                mapOf("alive" to alive.toString(), "port" to target.port.toString()), durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class DnsPlugin(private val multi: MultiResolverDns = MultiResolverDns()) : ScanPlugin {
    override val id = "dns"; override val displayName = "DNS Resolve"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(300, 512, 0)
    override val dependsOn = emptySet<String>()
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.MODERATE, t0) {
            ctx.ensureActive()
            val answers = multi.lookupAll(target.host)
            ctx.put("dns.answers", answers)
            val ips = answers.values.flatten().mapNotNull { it.hostAddress }.distinct()
            ctx.put("resolved.ips", ips)
            PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, if (ips.isEmpty()) "nxdomain" else "ok"),
                if (ips.isEmpty()) "no A/AAAA" else "resolved ${ips.size} addr",
                mapOf("ips" to ips.joinToString()), durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class DnsMultiPlugin(private val multi: MultiResolverDns = MultiResolverDns()) : ScanPlugin {
    override val id = "dnsmulti"; override val displayName = "DNS Multi-Resolver"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(400, 1024, 0)
    override val dependsOn = setOf("dns")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        @Suppress("UNCHECKED_CAST")
        val answers = ctx.get<Map<String, List<InetAddress>>>("dns.answers") ?: multi.lookupAll(target.host)
        ctx.put("dns.answers", answers)
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE),
            "resolvers=${answers.size}", mapOf("count" to answers.size.toString()), durationMs = System.currentTimeMillis() - t0)
    }
}

class Ipv4Plugin : ScanPlugin {
    override val id = "ipv4"; override val displayName = "IPv4"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(50, 256, 0)
    override val dependsOn = setOf("dns")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        @Suppress("UNCHECKED_CAST")
        val answers = ctx.get<Map<String, List<InetAddress>>>("dns.answers").orEmpty()
        val v4 = answers.values.flatten().filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress }.distinct()
        ctx.put("resolved.ipv4", v4)
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE),
            if (v4.isEmpty()) "no A" else "A ${v4.joinToString()}", mapOf("ipv4" to v4.joinToString()),
            durationMs = System.currentTimeMillis() - t0)
    }
}

class Ipv6Plugin : ScanPlugin {
    override val id = "ipv6"; override val displayName = "IPv6"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(50, 256, 0)
    override val dependsOn = setOf("dns")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        @Suppress("UNCHECKED_CAST")
        val answers = ctx.get<Map<String, List<InetAddress>>>("dns.answers").orEmpty()
        val v6 = answers.values.flatten().filterIsInstance<Inet6Address>().mapNotNull { it.hostAddress }.distinct()
        ctx.put("resolved.ipv6", v6)
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE),
            if (v6.isEmpty()) "no AAAA" else "AAAA ${v6.size}", mapOf("ipv6" to v6.joinToString()),
            durationMs = System.currentTimeMillis() - t0)
    }
}

class TlsPlugin : ScanPlugin {
    override val id = "tls"; override val displayName = "TLS Handshake"
    override val evidenceClass = EvidenceClass.STRONG
    override val cost = PluginCost(1200, 8192, 1)
    override val dependsOn = setOf("tcpconnect")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.STRONG, t0) {
            ctx.ensureActive()
            if (ctx.get<Boolean>("alive") == false) return@safeScan PluginHelpers.abstain(id, "host dead", t0, EvidenceClass.STRONG)
            val probe = TlsProbe(ctx.timeoutMs.toInt()).probe(target)
            ctx.put("tls.probe", probe)
            if (probe.certificate != null) {
                ctx.put("tls.certificate", probe.certificate)
                ctx.put("tls.sans", probe.sans)
                ctx.put("tls.cn", probe.cn)
            }
            PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.STRONG, if (probe.success) "ok" else probe.error),
                probe.toShortString(), mapOf(
                    "success" to probe.success.toString(), "protocol" to (probe.protocol ?: ""),
                    "cipher" to (probe.cipher ?: ""), "cn" to (probe.cn ?: ""), "sans" to probe.sans.joinToString(),
                    "error" to (probe.error ?: "")
                ), durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class CertificatePlugin : ScanPlugin {
    override val id = "certificate"; override val displayName = "Certificate"
    override val evidenceClass = EvidenceClass.STRONG
    override val cost = PluginCost(50, 0, 0)
    override val dependsOn = setOf("tls")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val cert = ctx.get<java.security.cert.X509Certificate>("tls.certificate")
            ?: return PluginHelpers.abstain(id, "no certificate", t0, EvidenceClass.STRONG)
        val sans = ctx.get<List<String>>("tls.sans") ?: TlsProbe.extractSans(cert)
        val cn = ctx.get<String>("tls.cn") ?: TlsProbe.extractCn(cert)
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.STRONG, "parsed"),
            "CN=${cn ?: "?"} SANs=${sans.size}",
            mapOf("cn" to (cn ?: ""), "sans" to sans.joinToString(), "issuer" to cert.issuerX500Principal.name),
            durationMs = System.currentTimeMillis() - t0)
    }
}

class HttpsPlugin : ScanPlugin {
    override val id = "https"; override val displayName = "HTTPS GET"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(1500, 32768, 1)
    override val dependsOn = setOf("tcpconnect")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.MODERATE, t0) {
            ctx.ensureActive()
            if (ctx.get<Boolean>("alive") == false) return@safeScan PluginHelpers.abstain(id, "host dead", t0, EvidenceClass.MODERATE)
            val client = SharedOkHttpFactory.get(ctx.timeoutMs)
            val req = Request.Builder().url("https://${target.host}:${target.port}/")
                .header("User-Agent", "MrScannerOmega/2.0").header("Host", target.effectiveSni).get().build()
            client.newCall(req).execute().use { resp ->
                val server = resp.header("Server")
                ctx.put("http.status", resp.code)
                ctx.put("http.server", server)
                ctx.put("http.headers", resp.headers.toMultimap())
                PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, "http ${resp.code}"),
                    "HTTP ${resp.code} server=${server ?: "?"}",
                    mapOf("status" to resp.code.toString(), "server" to (server ?: "")),
                    durationMs = System.currentTimeMillis() - t0)
            }
        }
    }
}

class HttpPlugin : ScanPlugin {
    override val id = "http"; override val displayName = "HTTP GET"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(1200, 16384, 1)
    override val dependsOn = setOf("tcpconnect")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.WEAK, t0) {
            try {
                val client = SharedOkHttpFactory.get(ctx.timeoutMs)
                val req = Request.Builder().url("http://${target.host}/").header("User-Agent", "MrScannerOmega/2.0").get().build()
                client.newCall(req).execute().use { resp ->
                    ctx.put("http.clear.status", resp.code)
                    PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK), "HTTP ${resp.code}",
                        mapOf("status" to resp.code.toString()), durationMs = System.currentTimeMillis() - t0)
                }
            } catch (e: Exception) {
                PluginHelpers.abstain(id, e.message ?: "http fail", t0, EvidenceClass.WEAK)
            }
        }
    }
}

private fun headerMap(ctx: ScanContext): Map<String, List<String>> {
    @Suppress("UNCHECKED_CAST")
    return ctx.get<Map<String, List<String>>>("http.headers").orEmpty()
}

class HeaderPlugin : ScanPlugin {
    override val id = "header"; override val displayName = "Headers"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(20, 0, 0)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val headers = headerMap(ctx)
        if (headers.isEmpty()) return PluginHelpers.abstain(id, "no headers", t0)
        val keys = listOf("server", "x-powered-by", "via", "x-cache", "cf-ray", "x-cdn", "strict-transport-security")
        val found = keys.mapNotNull { k -> headers.entries.find { it.key.equals(k, true) }?.let { it.key to it.value.joinToString() } }.toMap()
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
            "headers interesting=${found.size}", found, durationMs = System.currentTimeMillis() - t0)
    }
}

class ServerPlugin : ScanPlugin {
    override val id = "server"; override val displayName = "Server"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(10, 0, 0)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val server = ctx.get<String>("http.server")
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
            server ?: "unknown", mapOf("server" to (server ?: "")), durationMs = System.currentTimeMillis() - t0)
    }
}

class RedirectPlugin : ScanPlugin {
    override val id = "redirect"; override val displayName = "Redirect"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(20, 0, 0)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val status = ctx.get<Int>("http.status")
        val loc = headerMap(ctx).entries.find { it.key.equals("location", true) }?.value?.firstOrNull()
        val redir = status != null && status in 300..399
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
            if (redir) "redirect -> ${loc ?: "?"}" else "no redirect",
            mapOf("status" to (status?.toString() ?: ""), "location" to (loc ?: "")),
            durationMs = System.currentTimeMillis() - t0)
    }
}

class CompressionPlugin : ScanPlugin {
    override val id = "compression"; override val displayName = "Compression"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(10, 0, 0)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val enc = headerMap(ctx).entries.find { it.key.equals("content-encoding", true) }?.value?.joinToString()
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
            enc ?: "identity", mapOf("encoding" to (enc ?: "")), durationMs = System.currentTimeMillis() - t0)
    }
}

class HttpVersionPlugin : ScanPlugin {
    override val id = "httpversion"; override val displayName = "HTTP Version"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(10, 0, 0)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val v = ctx.get<TlsProbeResult>("tls.probe")?.protocol ?: "unknown"
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
            "tls=$v", mapOf("tlsProtocol" to v), durationMs = System.currentTimeMillis() - t0)
    }
}

class SecurityHeaderPlugin : ScanPlugin {
    override val id = "securityheader"; override val displayName = "Security Headers"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(15, 0, 0)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val keys = listOf("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy")
        val found = keys.mapNotNull { k -> headerMap(ctx).entries.find { it.key.equals(k, true) }?.let { k to it.value.joinToString() } }.toMap()
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
            "security-headers=${found.size}/${keys.size}", found, durationMs = System.currentTimeMillis() - t0)
    }
}

class CookiePlugin : ScanPlugin {
    override val id = "cookie"; override val displayName = "Cookies"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(15, 0, 0)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val cookies = headerMap(ctx).entries.filter { it.key.equals("set-cookie", true) }.flatMap { it.value }
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
            "cookies=${cookies.size}", mapOf("count" to cookies.size.toString()), durationMs = System.currentTimeMillis() - t0)
    }
}

class RobotsPlugin : ScanPlugin {
    override val id = "robots"; override val displayName = "robots.txt"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(800, 4096, 1)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.WEAK, t0) {
            val client = SharedOkHttpFactory.get(ctx.timeoutMs)
            val req = Request.Builder().url("https://${target.host}/robots.txt").header("User-Agent", "MrScannerOmega/2.0").get().build()
            client.newCall(req).execute().use { resp ->
                PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
                    "robots ${resp.code}", mapOf("status" to resp.code.toString()), durationMs = System.currentTimeMillis() - t0)
            }
        }
    }
}

class SitemapPlugin : ScanPlugin {
    override val id = "sitemap"; override val displayName = "sitemap.xml"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(800, 4096, 1)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.WEAK, t0) {
            val client = SharedOkHttpFactory.get(ctx.timeoutMs)
            val req = Request.Builder().url("https://${target.host}/sitemap.xml").header("User-Agent", "MrScannerOmega/2.0").get().build()
            client.newCall(req).execute().use { resp ->
                PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
                    "sitemap ${resp.code}", mapOf("status" to resp.code.toString()), durationMs = System.currentTimeMillis() - t0)
            }
        }
    }
}

class CdnWafPlugin : ScanPlugin {
    override val id = "cdnwaf"; override val displayName = "CDN/WAF"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(30, 0, 0)
    override val dependsOn = setOf("https", "header")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val blob = headerMap(ctx).entries.joinToString(" ") { (k, v) -> "$k:${v.joinToString()}" }.lowercase()
        val server = (ctx.get<String>("http.server") ?: "").lowercase()
        val cdn = when {
            "cf-ray" in blob || "cloudflare" in blob || "cloudflare" in server -> "cloudflare"
            "x-amz-cf" in blob || "cloudfront" in blob -> "cloudfront"
            "akamai" in blob -> "akamai"
            "fastly" in blob -> "fastly"
            else -> null
        }
        ctx.put("cdn.provider", cdn)
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, cdn),
            cdn?.let { "cdn=$it" } ?: "no CDN fingerprint", mapOf("cdn" to (cdn ?: "")),
            durationMs = System.currentTimeMillis() - t0)
    }
}

class TlsFingerprintPlugin : ScanPlugin {
    override val id = "tlsfingerprint"; override val displayName = "TLS FP"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(20, 0, 0)
    override val dependsOn = setOf("tls")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val probe = ctx.get<TlsProbeResult>("tls.probe") ?: return PluginHelpers.abstain(id, "no tls", t0)
        val fp = listOfNotNull(probe.protocol, probe.cipher).joinToString("|")
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
            fp.ifEmpty { "n/a" }, mapOf("fp" to fp), durationMs = System.currentTimeMillis() - t0)
    }
}

class BannerPlugin : ScanPlugin {
    override val id = "banner"; override val displayName = "Banner"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(10, 0, 0)
    override val dependsOn = setOf("server", "tls")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val banner = listOfNotNull(ctx.get<String>("http.server"), ctx.get<String>("tls.cn")?.let { "cn=$it" }).joinToString(" | ")
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK),
            banner.ifEmpty { "n/a" }, mapOf("banner" to banner), durationMs = System.currentTimeMillis() - t0)
    }
}

class FingerprintPlugin : ScanPlugin {
    override val id = "fingerprint"; override val displayName = "Fingerprint"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(30, 0, 0)
    override val dependsOn = setOf("header", "server", "cdnwaf")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val tags = mutableListOf<String>()
        ctx.get<String>("cdn.provider")?.let { tags += "cdn:$it" }
        ctx.get<String>("http.server")?.let { tags += "server:$it" }
        ctx.put("tech.tags", tags)
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE),
            if (tags.isEmpty()) "no tags" else tags.joinToString(), mapOf("tags" to tags.joinToString()),
            durationMs = System.currentTimeMillis() - t0)
    }
}

/* ========== BYPASS (9) ========== */

class TlsFragmentationPlugin : ScanPlugin {
    override val id = "tlsfragment"; override val displayName = "TLS Fragmentation"
    override val evidenceClass = EvidenceClass.DEFINITIVE
    override val cost = PluginCost(2000, 12000, 2)
    override val dependsOn = setOf("tcpconnect", "tls")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.DEFINITIVE, t0) {
            ctx.ensureActive()
            val probe = TlsProbe(ctx.timeoutMs.toInt())
            val normal = ctx.get<TlsProbeResult>("tls.probe") ?: probe.probe(target)
            val frag = probe.probe(target, 2)
            val signal = when {
                !normal.success && frag.success -> PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE, "frag works")
                normal.success && frag.success -> PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.DEFINITIVE, "both ok")
                normal.success && !frag.success -> PluginSignal(id, SignalPolarity.REFUTES_BYPASS, EvidenceClass.STRONG, "frag fails")
                else -> PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.DEFINITIVE, "both fail")
            }
            PluginResult(id, signal, "normal=${normal.success} frag=${frag.success}",
                mapOf("normal" to normal.toShortString(), "frag" to frag.toShortString()),
                durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class SniSpoofingPlugin : ScanPlugin {
    override val id = "snispoofing"; override val displayName = "SNI Spoof"
    override val evidenceClass = EvidenceClass.STRONG
    override val cost = PluginCost(1500, 8000, 1)
    override val dependsOn = setOf("tls")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val sans = ctx.get<List<String>>("tls.sans").orEmpty()
        val covered = sans.any { TlsProbe.matchDnsName(it, target.host) }
        val signal = when {
            sans.isEmpty() -> PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.STRONG, "no sans")
            covered -> PluginSignal(id, SignalPolarity.REFUTES_BYPASS, EvidenceClass.MODERATE, "host in SAN")
            else -> PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.MODERATE, "host not in SAN")
        }
        return PluginResult(id, signal, signal.reason ?: "", mapOf("sans" to sans.joinToString()), durationMs = System.currentTimeMillis() - t0)
    }
}

class SniFrontingPlugin(
    private val candidates: () -> List<String> = { listOf("cloudflare.com", "www.cloudflare.com", "cdnjs.cloudflare.com") }
) : ScanPlugin {
    override val id = "snifronting"; override val displayName = "SNI Fronting"
    override val evidenceClass = EvidenceClass.STRONG
    override val cost = PluginCost(3000, 16000, 2)
    override val dependsOn = setOf("tcpconnect")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.STRONG, t0) {
            ctx.ensureActive()
            val probe = TlsProbe(ctx.timeoutMs.toInt())
            val hits = candidates().take(3).filter { !it.equals(target.host, true) }.filter { probe.probe(target.copy(sni = it)).success }
            val signal = if (hits.isNotEmpty()) PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG, "fronting: $hits")
            else PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.STRONG, "no fronting")
            PluginResult(id, signal, if (hits.isEmpty()) "no fronting" else "fronting via ${hits.joinToString()}",
                mapOf("hits" to hits.joinToString()), durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class DohBypassPlugin : ScanPlugin {
    override val id = "dohbypass"; override val displayName = "DoH Bypass"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(1200, 4000, 1)
    override val dependsOn = setOf("dns")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.MODERATE, t0) {
            val rr = DnsHttpsRecordQuery().query(target.host)
            val signal = if (rr.present || rr.rawHint != null) PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.MODERATE, "doh works")
            else PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, rr.rawHint)
            PluginResult(id, signal, if (rr.present) "DoH+HTTPS RR" else "DoH probe",
                mapOf("httpsRr" to rr.present.toString(), "echHint" to rr.echHint.toString()),
                durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class ZeroRatedPlugin : ScanPlugin {
    override val id = "zerorated"; override val displayName = "Zero-Rated"
    override val evidenceClass = EvidenceClass.STRONG
    override val cost = PluginCost(800, 4000, 1)
    override val dependsOn = setOf("https")
    override val requiredProfile = setOf(NetworkProfile.CELLULAR_METERED)
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.STRONG, "needs operator pack"),
            "cellular — operator pack not loaded", mapOf("profile" to ctx.profile.name), durationMs = System.currentTimeMillis() - t0)
    }
}

class PayloadInjectionPlugin : ScanPlugin {
    override val id = "payloadinjection"; override val displayName = "Payload Injection"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(100, 0, 0)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, "passive"),
            "passive — no attack payloads by policy", mapOf("mode" to "passive"), durationMs = System.currentTimeMillis() - t0)
    }
}

class HeaderInjectionPlugin : ScanPlugin {
    override val id = "headerinjection"; override val displayName = "Header Injection"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(100, 0, 0)
    override val dependsOn = setOf("https")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, "passive"),
            "passive — authorized labs only", mapOf("mode" to "passive"), durationMs = System.currentTimeMillis() - t0)
    }
}

class MisconfigPlugin : ScanPlugin {
    override val id = "misconfig"; override val displayName = "Misconfig"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(40, 0, 0)
    override val dependsOn = setOf("securityheader", "certificate")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val hasHsts = headerMap(ctx).keys.any { it.equals("strict-transport-security", true) }
        val issues = if (!hasHsts) listOf("missing-hsts") else emptyList()
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, issues.joinToString().ifEmpty { "clean" }),
            if (issues.isEmpty()) "no common misconfig" else issues.joinToString(),
            mapOf("issues" to issues.joinToString()), durationMs = System.currentTimeMillis() - t0)
    }
}

class CveAuditPlugin : ScanPlugin {
    override val id = "cveaudit"; override val displayName = "CVE Audit"
    override val evidenceClass = EvidenceClass.STRONG
    override val cost = PluginCost(50, 0, 0)
    override val dependsOn = setOf("server", "fingerprint")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val server = (ctx.get<String>("http.server") ?: "").lowercase()
        val hits = mutableListOf<String>()
        if (server.contains("apache/2.2")) hits += "legacy-apache-2.2"
        if (server.contains("openssl/1.0.1")) hits += "legacy-openssl-1.0.1"
        val signal = if (hits.isNotEmpty()) PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG, hits.joinToString())
        else PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.STRONG, "no offline CVE hit")
        return PluginResult(id, signal, if (hits.isEmpty()) "no offline CVE hits" else "hits=${hits.joinToString()}",
            mapOf("hits" to hits.joinToString()), durationMs = System.currentTimeMillis() - t0)
    }
}

/* ========== ADVANCED (10) ========== */

class DnsConsistencyPlugin(private val multi: MultiResolverDns = MultiResolverDns()) : ScanPlugin {
    override val id = "plugin.host.dnsconsistency"; override val displayName = "DNS Consistency"
    override val evidenceClass = EvidenceClass.STRONG
    override val cost = PluginCost(200, 2048, 0)
    override val dependsOn = setOf("dns", "dnsmulti")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.STRONG, t0) {
            ctx.ensureActive()
            @Suppress("UNCHECKED_CAST")
            val answers = ctx.get<Map<String, List<InetAddress>>>("dns.answers") ?: multi.lookupAll(target.host)
            if (answers.isEmpty()) return@safeScan PluginHelpers.abstain(id, "no answers", t0, EvidenceClass.STRONG)
            val sets = answers.values.map { it.mapNotNull { a -> a.hostAddress }.toSet() }
            if (sets.all { it.isEmpty() }) return@safeScan PluginHelpers.abstain(id, "all empty", t0, EvidenceClass.STRONG)
            val intersection = sets.reduce { a, b -> a.intersect(b) }
            val union = sets.reduce { a, b -> a.union(b) }
            val divergent = union - intersection
            val signal = if (divergent.isNotEmpty()) PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG, "divergent=${divergent.size}")
            else PluginSignal(id, SignalPolarity.REFUTES_BYPASS, EvidenceClass.MODERATE, "consistent")
            PluginResult(id, signal, "resolvers=${answers.size} divergent=${divergent.size}",
                mapOf("intersection" to intersection.joinToString(), "divergent" to divergent.joinToString()),
                durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class RecordFragmentPlugin(private val splits: () -> List<Int> = { listOf(1, 2, 5, 10) }) : ScanPlugin {
    override val id = "plugin.host.recordfragment"; override val displayName = "Record Fragment"
    override val evidenceClass = EvidenceClass.DEFINITIVE
    override val cost = PluginCost(2500, 16384, 4)
    override val dependsOn = setOf("tcpconnect", "tls")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.DEFINITIVE, t0) {
            ctx.ensureActive()
            val probe = TlsProbe(ctx.timeoutMs.toInt())
            val normal = ctx.get<TlsProbeResult>("tls.probe") ?: probe.probe(target)
            val hits = splits().map { sp -> sp to probe.probe(target, sp) }
            val anyOk = hits.any { it.second.success }
            val signal = when {
                !normal.success && anyOk -> PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE, "multi-frag works")
                normal.success && anyOk -> PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.DEFINITIVE, "both ok")
                normal.success && !anyOk -> PluginSignal(id, SignalPolarity.REFUTES_BYPASS, EvidenceClass.STRONG, "frag fails")
                else -> PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.DEFINITIVE, "both fail")
            }
            PluginResult(id, signal, "normal=${normal.success} frag=${hits.filter { it.second.success }.map { it.first }}",
                hits.associate { "split_${it.first}" to it.second.toShortString() },
                durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class SniExploitabilityPlugin : ScanPlugin {
    override val id = "plugin.host.snisan"; override val displayName = "SNI SAN"
    override val evidenceClass = EvidenceClass.DEFINITIVE
    override val cost = PluginCost(1200, 8192, 0)
    override val dependsOn = setOf("tls", "certificate")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.DEFINITIVE, t0) {
            ctx.ensureActive()
            val sans = ctx.get<List<String>>("tls.sans")
            val cn = ctx.get<String>("tls.cn")
            if (sans == null && cn == null) return@safeScan PluginHelpers.abstain(id, "no certificate", t0, EvidenceClass.DEFINITIVE)
            val sanList = sans.orEmpty()
            val hostInCert = TlsProbe.sanContains(sanList, target.host) || TlsProbe.cnEqualsOrWildcard(cn, target.host)
            val signal = when {
                !hostInCert && sanList.isNotEmpty() -> PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE, "SAN mismatch — exploitable")
                hostInCert -> PluginSignal(id, SignalPolarity.REFUTES_BYPASS, EvidenceClass.DEFINITIVE, "SAN covers host")
                else -> PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.DEFINITIVE, "empty SAN/CN")
            }
            PluginResult(id, signal, signal.reason ?: "",
                mapOf("cn" to (cn ?: ""), "sans" to sanList.joinToString(), "host" to target.host),
                durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class EchPlugin : ScanPlugin {
    override val id = "plugin.host.ech"; override val displayName = "ECH Probe"
    override val evidenceClass = EvidenceClass.STRONG
    override val cost = PluginCost(1000, 4000, 1)
    override val dependsOn = setOf("dns")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.STRONG, t0) {
            val rr = DnsHttpsRecordQuery().query(target.host)
            val signal = when {
                rr.echHint -> PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG, "ECH present")
                rr.present -> PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.STRONG, "HTTPS RR only")
                else -> PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.STRONG, rr.rawHint ?: "no RR")
            }
            PluginResult(id, signal, when { rr.echHint -> "ECH hinted"; rr.present -> "HTTPS RR"; else -> "no ECH" },
                mapOf("httpsRr" to rr.present.toString(), "ech" to rr.echHint.toString()),
                durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class DnsTransportPlugin : ScanPlugin {
    override val id = "plugin.host.dnstransport"; override val displayName = "DoT/DoQ"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(1500, 4000, 2)
    override val dependsOn = setOf("dns")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginHelpers.safeScan(id, EvidenceClass.MODERATE, t0) {
            val open = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9").filter {
                TcpConnect.isAlive(it, 853, ctx.timeoutMs.toInt().coerceAtMost(2000))
            }
            val signal = if (open.isNotEmpty()) PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.MODERATE, "DoT: $open")
            else PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, "DoT closed")
            PluginResult(id, signal, "DoT open=${open.size}/3", mapOf("dot" to open.joinToString()),
                durationMs = System.currentTimeMillis() - t0)
        }
    }
}

class Ja3SelfPlugin : ScanPlugin {
    override val id = "plugin.host.ja3self"; override val displayName = "JA3 Self"
    override val evidenceClass: EvidenceClass? = null
    override val cost = PluginCost(5, 0, 0)
    override val dependsOn = setOf("tls")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val probe = ctx.get<TlsProbeResult>("tls.probe")
        val pseudo = listOfNotNull(probe?.protocol, probe?.cipher).joinToString(",")
        val hash = pseudo.hashCode().toUInt().toString(16)
        ctx.put("ja3self", hash)
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK, "informational"),
            "ja3self≈$hash", mapOf("hash" to hash), durationMs = System.currentTimeMillis() - t0)
    }
}

class AlpnMatrixPlugin : ScanPlugin {
    override val id = "plugin.host.alpnmatrix"; override val displayName = "ALPN Matrix"
    override val evidenceClass = EvidenceClass.WEAK
    override val cost = PluginCost(1500, 8000, 1)
    override val dependsOn = setOf("tls")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        val probe = ctx.get<TlsProbeResult>("tls.probe")
        val s = "protocol=${probe?.protocol ?: "?"}"
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK, s), s,
            mapOf("protocol" to (probe?.protocol ?: "")), durationMs = System.currentTimeMillis() - t0)
    }
}

class QuicPlugin : ScanPlugin {
    override val id = "plugin.host.quic"; override val displayName = "QUIC/H3"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(1000, 4000, 1)
    override val dependsOn = setOf("dns")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, "cronet-only on Android"),
            "QUIC deferred (Cronet on Android)", mapOf("status" to "unsupported_on_jvm_core"),
            durationMs = System.currentTimeMillis() - t0)
    }
}

class CdnEdgePlugin : ScanPlugin {
    override val id = "plugin.host.cdnedge"; override val displayName = "CDN Edge"
    override val evidenceClass = EvidenceClass.MODERATE
    override val cost = PluginCost(5000, 64000, 4)
    override val dependsOn = setOf("dns", "https", "cdnwaf")
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        @Suppress("UNCHECKED_CAST")
        val ips = ctx.get<List<String>>("resolved.ips").orEmpty()
        val cdn = ctx.get<String>("cdn.provider")
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.MODERATE, "edge scan lite"),
            "ips=${ips.size} cdn=${cdn ?: "-"}", mapOf("ips" to ips.joinToString(), "cdn" to (cdn ?: "")),
            durationMs = System.currentTimeMillis() - t0)
    }
}

class TimeConsistencyPlugin : ScanPlugin {
    override val id = "plugin.host.timeconsistency"; override val displayName = "Time Consistency"
    override val evidenceClass: EvidenceClass? = null
    override val cost = PluginCost(0, 0, 0)
    override val dependsOn = emptySet<String>()
    override val requiredProfile = emptySet<NetworkProfile>()
    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = System.currentTimeMillis()
        return PluginResult(id, PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.WEAK, "metadata"),
            "use reverify / WorkManager", mapOf("scheduled" to "false"), durationMs = System.currentTimeMillis() - t0)
    }
}
