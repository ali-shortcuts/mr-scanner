package com.mrscanner.omega.core.export

import com.mrscanner.omega.core.model.HostResultDto
import com.mrscanner.omega.core.model.ScanExportDto
import com.mrscanner.omega.core.security.ExportRedactor
import com.mrscanner.omega.core.settings.RedactionLevel
import java.io.File

/** CSV sibling of [ResultJsonCodec] — same DTO, same redaction pass, spreadsheet-friendly output. */
object ResultCsvCodec {
    private val HEADER = listOf("host", "resolved", "verdict", "confidence", "logOdds", "explanation", "signals", "pluginSummaries")

    fun encode(dto: ScanExportDto, redaction: RedactionLevel = RedactionLevel.STANDARD): String {
        val redacted = ExportRedactor.redact(dto, redaction)
        val sb = StringBuilder()
        sb.append(HEADER.joinToString(",") { csvField(it) }).append("\r\n")
        for (h in redacted.hosts) sb.append(rowFor(h)).append("\r\n")
        return sb.toString()
    }

    fun write(dto: ScanExportDto, file: File, redaction: RedactionLevel = RedactionLevel.STANDARD) {
        file.parentFile?.mkdirs(); file.writeText(encode(dto, redaction))
    }

    private fun rowFor(h: HostResultDto): String = listOf(
        h.input,
        h.resolved.joinToString(";"),
        h.verdict,
        h.confidence.toString(),
        h.logOdds.toString(),
        h.explanation,
        h.signals.joinToString(";") { "${it.pluginId}:${it.polarity}:${it.evidenceClass}" },
        h.pluginSummaries.joinToString(";")
    ).joinToString(",") { csvField(it) }

    /** RFC 4180: quote any field containing a comma, quote, or line break; double up embedded quotes. */
    private fun csvField(s: String): String =
        if (s.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) "\"${s.replace("\"", "\"\"")}\"" else s
}
