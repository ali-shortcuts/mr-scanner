package com.mrscanner.omega.core.db
import com.mrscanner.omega.core.model.*
import com.mrscanner.omega.core.plugin.Verdict
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

class HoleAgeStore(private val persistDir: File? = null) {
    private val map = ConcurrentHashMap<String, HoleRecord>()
    init { persistDir?.mkdirs(); load() }
    fun applyVerdict(host: String, verdict: Verdict, confidence: Double, technique: String = "aggregate") {
        val id = holeId(host, technique); val now = System.currentTimeMillis()
        when (verdict) {
            Verdict.CONFIRMED_CANDIDATE -> {
                val e = map[id]
                if (e == null) map[id] = HoleRecord(id, host, technique, "open", now, now, lastConfidence = confidence, lastVerdict = verdict.name)
                else { e.status = "open"; e.lastConfirmedAt = now; e.lastConfidence = confidence; e.lastVerdict = verdict.name; e.closedAt = null; e.closedReason = null }
            }
            Verdict.CONFIRMED_NOT_VULNERABLE -> {
                val e = map[id]
                if (e != null && e.status == "open") { e.status = "closed"; e.closedAt = now; e.closedReason = "DEFINITIVE_REFUTE"; e.lastConfidence = confidence; e.lastVerdict = verdict.name }
                else if (e == null) map[id] = HoleRecord(id, host, technique, "closed", now, now, now, "DEFINITIVE_REFUTE", confidence, verdict.name)
                else { e.lastConfidence = confidence; e.lastVerdict = verdict.name }
            }
            Verdict.WEAK_SIGNAL_ONLY -> map[id]?.let { it.lastSeenWeakAt = now; it.lastConfidence = confidence; it.lastVerdict = verdict.name }
        }
        save()
    }
    fun list(openOnly: Boolean? = null) = map.values.filter {
        openOnly == null || (openOnly && it.status == "open") || (!openOnly && it.status == "closed")
    }.sortedByDescending { it.lastConfirmedAt }
    private fun holeId(h: String, t: String) = MessageDigest.getInstance("SHA-256").digest("$h|$t".toByteArray()).joinToString("") { "%02x".format(it) }.take(16)
    private fun save() {
        val dir = persistDir ?: return
        File(dir, "holes.tsv").writeText(map.values.joinToString("\n") { r ->
            listOf(r.holeId, r.host, r.technique, r.status, r.firstSeenAt, r.lastConfirmedAt, r.closedAt ?: "", r.closedReason ?: "", r.lastConfidence, r.lastVerdict, r.lastSeenWeakAt ?: "").joinToString("\t")
        })
    }
    private fun load() {
        val f = File(persistDir ?: return, "holes.tsv"); if (!f.exists()) return
        f.readLines().forEach { line ->
            val p = line.split("\t"); if (p.size < 10) return@forEach
            map[p[0]] = HoleRecord(p[0], p[1], p[2], p[3], p[4].toLongOrNull() ?: 0, p[5].toLongOrNull() ?: 0,
                p[6].toLongOrNull(), p[7].ifBlank { null }, p[8].toDoubleOrNull() ?: 0.0, p[9], p.getOrNull(10)?.toLongOrNull())
        }
    }
}

class CheckpointStore(private val persistDir: File? = null) {
    private val map = ConcurrentHashMap<String, CheckpointRecord>()
    init { persistDir?.mkdirs() }
    fun save(cp: CheckpointRecord) {
        cp.updatedAt = System.currentTimeMillis(); map[cp.scanId] = cp
        val dir = persistDir ?: return
        File(dir, "checkpoint-${cp.scanId}.txt").writeText(buildString {
            appendLine(cp.scanId); appendLine(cp.configHash); appendLine(cp.cursorIndex); appendLine(cp.totalHosts)
            cp.completedHosts.forEach { appendLine(it) }
        })
    }
    fun get(id: String) = map[id] ?: load(id)
    fun list(): List<CheckpointRecord> {
        persistDir?.listFiles()?.filter { it.name.startsWith("checkpoint-") }?.forEach { load(it.name.removePrefix("checkpoint-").removeSuffix(".txt")) }
        return map.values.sortedByDescending { it.updatedAt }
    }
    fun clear(id: String) { map.remove(id); persistDir?.let { File(it, "checkpoint-$id.txt").delete() } }
    private fun load(id: String): CheckpointRecord? {
        val f = File(persistDir ?: return null, "checkpoint-$id.txt"); if (!f.exists()) return null
        val lines = f.readLines(); if (lines.size < 4) return null
        return CheckpointRecord(lines[0], configHash = lines[1], cursorIndex = lines[2].toIntOrNull() ?: 0,
            totalHosts = lines[3].toIntOrNull() ?: 0, completedHosts = lines.drop(4).toMutableList()).also { map[id] = it }
    }
}

class ScanHistoryStore {
    private val scans = ConcurrentHashMap<String, MutableList<HostScanResult>>()
    fun put(id: String, r: List<HostScanResult>) { scans[id] = r.toMutableList() }
    fun get(id: String) = scans[id]
    fun ids() = scans.keys().toList()
}
