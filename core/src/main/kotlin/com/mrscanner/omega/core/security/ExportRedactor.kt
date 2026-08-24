package com.mrscanner.omega.core.security
import com.mrscanner.omega.core.model.*
import com.mrscanner.omega.core.settings.RedactionLevel
import java.security.MessageDigest

object ExportRedactor {
    fun redact(dto: ScanExportDto, level: RedactionLevel): ScanExportDto {
        if (level == RedactionLevel.NONE) return dto
        return dto.copy(hosts = dto.hosts.map { h ->
            when (level) {
                RedactionLevel.STANDARD -> h.copy(
                    resolved = h.resolved.map { if (isPrivate(it)) "x.x.x.x" else it },
                    pluginSummaries = h.pluginSummaries.map { it.replace(Regex("""(/home|/data|/storage)/[^\s]+"""), "<path>") }
                )
                RedactionLevel.STRICT -> h.copy(
                    input = "h:" + sha(h.input).take(12), resolved = emptyList(), explanation = h.verdict,
                    signals = h.signals.map { SignalDto(it.pluginId, it.polarity, it.evidenceClass, null) },
                    pluginSummaries = emptyList()
                )
                else -> h
            }
        })
    }
    private fun isPrivate(ip: String) = ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") ||
        (ip.startsWith("172.") && (ip.split(".").getOrNull(1)?.toIntOrNull() ?: -1) in 16..31)
    private fun sha(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
}
