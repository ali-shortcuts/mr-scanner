package com.mrscanner.omega.core.export
import com.mrscanner.omega.core.model.ScanExportDto
import com.mrscanner.omega.core.security.ExportRedactor
import com.mrscanner.omega.core.settings.RedactionLevel
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File

object ResultJsonCodec {
    val json = Json { prettyPrint = true; encodeDefaults = true; ignoreUnknownKeys = true }
    fun encode(dto: ScanExportDto, redaction: RedactionLevel = RedactionLevel.STANDARD) =
        json.encodeToString(ExportRedactor.redact(dto, redaction))
    fun write(dto: ScanExportDto, file: File, redaction: RedactionLevel = RedactionLevel.STANDARD) {
        file.parentFile?.mkdirs(); file.writeText(encode(dto, redaction))
    }
    fun read(file: File): ScanExportDto = json.decodeFromString(file.readText())
}
