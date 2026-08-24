package com.mrscanner.omega.core.fingerprint
object JarmLite {
    fun fromProbe(protocol: String?, cipher: String?): String =
        listOfNotNull(protocol, cipher).joinToString("|").ifEmpty { "unknown" }.hashCode().toUInt().toString(16)
}
