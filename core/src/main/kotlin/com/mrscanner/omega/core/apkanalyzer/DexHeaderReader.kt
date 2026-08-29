package com.mrscanner.omega.core.apkanalyzer

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Reads the fixed DEX header (the first 0x70 bytes of any classes*.dex)
 * for real counts instead of guessing from printable-string extraction.
 * Verified against this project's own classes.dex in dist/.
 */
object DexHeaderReader {
    data class DexStats(
        val stringIdsCount: Int, val typeIdsCount: Int, val protoIdsCount: Int,
        val fieldIdsCount: Int, val methodIdsCount: Int, val classDefsCount: Int
    )

    /** Returns null (never throws) if [data] doesn't start with a valid "dex\n0XX\0" magic. */
    fun read(data: ByteArray): DexStats? {
        if (data.size < 0x70) return null
        if (data[0] != 'd'.code.toByte() || data[1] != 'e'.code.toByte() || data[2] != 'x'.code.toByte() || data[3] != '\n'.code.toByte()) return null
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        return DexStats(
            stringIdsCount = buf.getInt(0x38),
            typeIdsCount = buf.getInt(0x40),
            protoIdsCount = buf.getInt(0x48),
            fieldIdsCount = buf.getInt(0x50),
            methodIdsCount = buf.getInt(0x58),
            classDefsCount = buf.getInt(0x60)
        )
    }
}
