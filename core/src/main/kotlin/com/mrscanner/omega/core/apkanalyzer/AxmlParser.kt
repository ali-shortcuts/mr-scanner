package com.mrscanner.omega.core.apkanalyzer

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Real parser for Android's binary XML format (AXML) — the format
 * AndroidManifest.xml is actually stored in inside an APK. It is NOT
 * plain-text XML; a build tool (aapt/aapt2) compiles it into a binary
 * chunk format (string pool + resource-id map + a flat stream of
 * element start/end chunks with typed attributes).
 *
 * The old approach (`extractPrintableStrings` + substring matching over
 * the raw manifest bytes) can only ever guess — e.g. it can't tell the
 * difference between the attribute `android:debuggable="false"` and the
 * word "debuggable" appearing as part of some unrelated string, both of
 * which contain the same printable bytes. This parser decodes the real
 * chunk structure so attribute values (booleans, ints, string refs) are
 * read out exactly as the OS itself would read them.
 *
 * Chunk format reference (types are ResChunk_header.type values):
 *   0x0001 RES_STRING_POOL_TYPE
 *   0x0180 RES_XML_RESOURCE_MAP_TYPE
 *   0x0100 / 0x0101 RES_XML_START_NAMESPACE / END_NAMESPACE_TYPE
 *   0x0102 / 0x0103 RES_XML_START_ELEMENT / END_ELEMENT_TYPE
 * This has been validated by hand against this project's own built APKs
 * in dist/ — not assumed from memory alone.
 */
object AxmlParser {

    data class Attr(val namespace: String?, val name: String, val value: Any?, val rawType: Int)
    data class Element(val name: String, val attrs: List<Attr>, val children: MutableList<Element> = mutableListOf()) {
        fun attr(name: String): Any? = attrs.firstOrNull { it.name == name }?.value
        fun attrString(name: String): String? = attr(name)?.toString()
        fun attrBool(name: String): Boolean? = attr(name) as? Boolean
        fun attrInt(name: String): Int? = (attr(name) as? Int)
        fun all(tag: String): List<Element> = children.filter { it.name == tag } +
            children.flatMap { it.all(tag) }
    }

    /** Returns null (never throws) if [data] isn't a valid AXML chunk — callers fall back to heuristics. */
    fun parse(data: ByteArray): Element? = try {
        parseInternal(data)
    } catch (_: Exception) {
        null
    }

    private fun parseInternal(data: ByteArray): Element? {
        if (data.size < 8) return null
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val xmlType = buf.getShort(0).toInt() and 0xffff
        if (xmlType != 0x0003) return null // not RES_XML_TYPE
        val strings = readStringPool(buf, 8) ?: return null

        var off = 8 + (buf.getInt(8 + 4).let { chunkSizeOfStringPool(buf) })
        val root = Element("__root__", emptyList())
        val stack = ArrayDeque<Element>()
        stack.addLast(root)

        while (off + 8 <= data.size) {
            val ctype = buf.getShort(off).toInt() and 0xffff
            val csize = buf.getInt(off + 4)
            if (csize <= 0 || off + csize > data.size + 8) break
            when (ctype) {
                0x0102 -> { // start element
                    val ns = buf.getInt(off + 16)
                    val nameIdx = buf.getInt(off + 20)
                    val attrStart = buf.getShort(off + 24).toInt() and 0xffff
                    val attrCount = buf.getShort(off + 28).toInt() and 0xffff
                    val name = strings.getOrNull(nameIdx) ?: "?"
                    val attrs = mutableListOf<Attr>()
                    var apos = off + 16 + attrStart
                    repeat(attrCount) {
                        if (apos + 20 <= data.size) {
                            val aNsIdx = buf.getInt(apos)
                            val aNameIdx = buf.getInt(apos + 4)
                            val aDataType = data[apos + 15].toInt() and 0xff
                            val aData = buf.getInt(apos + 16)
                            val aName = strings.getOrNull(aNameIdx) ?: "?"
                            val aNs = if (aNsIdx >= 0) strings.getOrNull(aNsIdx) else null
                            val value: Any? = when (aDataType) {
                                0x03 -> strings.getOrNull(aData) // TYPE_STRING
                                0x12 -> aData != 0 // TYPE_INT_BOOLEAN
                                0x10, 0x11 -> aData // TYPE_INT_DEC / TYPE_INT_HEX
                                else -> aData
                            }
                            attrs += Attr(aNs, aName, value, aDataType)
                        }
                        apos += 20
                    }
                    val el = Element(name, attrs)
                    stack.last().children += el
                    stack.addLast(el)
                    if (ns == -2) Unit // unused, keeps ns var referenced without warning noise
                }
                0x0103 -> { // end element
                    if (stack.size > 1) stack.removeLast()
                }
                else -> Unit
            }
            off += csize
        }
        return root.children.firstOrNull()
    }

    private fun chunkSizeOfStringPool(buf: ByteBuffer): Int = buf.getInt(8 + 4)

    /** Reads a RES_STRING_POOL_TYPE chunk starting at [base]; returns the decoded strings. */
    private fun readStringPool(buf: ByteBuffer, base: Int): List<String>? {
        val type = buf.getShort(base).toInt() and 0xffff
        if (type != 0x0001) return null
        val stringCount = buf.getInt(base + 8)
        val flags = buf.getInt(base + 16)
        val stringsStart = buf.getInt(base + 20)
        val isUtf8 = (flags and (1 shl 8)) != 0
        val out = ArrayList<String>(stringCount)
        val data = buf.array()
        for (i in 0 until stringCount) {
            val entryOff = base + 28 + i * 4
            if (entryOff + 4 > data.size) { out.add(""); continue }
            val strOff = base + stringsStart + buf.getInt(entryOff)
            out.add(readOneString(data, strOff, isUtf8))
        }
        return out
    }

    private fun readOneString(data: ByteArray, start: Int, isUtf8: Boolean): String {
        var pos = start
        if (pos < 0 || pos >= data.size) return ""
        return if (isUtf8) {
            fun readLen(): Int {
                val b0 = data[pos].toInt() and 0xff
                return if (b0 and 0x80 != 0) {
                    val b1 = data[pos + 1].toInt() and 0xff
                    pos += 2; ((b0 and 0x7f) shl 8) or b1
                } else { pos += 1; b0 }
            }
            readLen() // utf16 char-length, unused
            val byteLen = readLen()
            if (pos + byteLen > data.size) "" else String(data, pos, byteLen, Charsets.UTF_8)
        } else {
            fun readLen16(): Int {
                val w0 = (data[pos].toInt() and 0xff) or ((data[pos + 1].toInt() and 0xff) shl 8)
                return if (w0 and 0x8000 != 0) {
                    val w1 = (data[pos + 2].toInt() and 0xff) or ((data[pos + 3].toInt() and 0xff) shl 8)
                    pos += 4; ((w0 and 0x7fff) shl 16) or w1
                } else { pos += 2; w0 }
            }
            val charLen = readLen16()
            val byteLen = charLen * 2
            if (pos + byteLen > data.size) "" else String(data, pos, byteLen, Charsets.UTF_16LE)
        }
    }
}
