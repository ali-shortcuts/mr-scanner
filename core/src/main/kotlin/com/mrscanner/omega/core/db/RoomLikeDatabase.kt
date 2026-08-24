package com.mrscanner.omega.core.db

import com.mrscanner.omega.core.model.CheckpointRecord
import com.mrscanner.omega.core.model.HoleRecord
import com.mrscanner.omega.core.plugin.Verdict
import java.io.File
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.ConcurrentHashMap

/**
 * SQLite-backed persistence (Room-compatible schema).
 * On Android this file can be swapped for Room DAOs with identical table shapes.
 * On JVM desktop we use the bundled JDBC SQLite when available, else durable TSV.
 *
 * Schema matches architecture §18:
 *  checkpoints(scanId PK, schemaVersion, configHash, cursorIndex, totalHosts, completedHostsJson, createdAt, updatedAt)
 *  hole_age(holeId PK, host, technique, status, firstSeenAt, lastConfirmedAt, closedAt, closedReason, lastConfidence, lastVerdict, lastSeenWeakAt)
 */
class OmegaDatabase private constructor(private val dbFile: File) {
    private val jdbcAvailable: Boolean = try {
        Class.forName("org.sqlite.JDBC"); true
    } catch (_: Throwable) { false }

    private val conn: Connection? = if (jdbcAvailable) {
        DriverManager.getConnection("jdbc:sqlite:${dbFile.absolutePath}").also { initSchema(it) }
    } else null

    // fallback stores
    private val holeFallback = HoleAgeStore(dbFile.parentFile)
    private val cpFallback = CheckpointStore(dbFile.parentFile)

    val holes = HoleRepository(conn, holeFallback)
    val checkpoints = CheckpointRepository(conn, cpFallback)

    private fun initSchema(c: Connection) {
        c.createStatement().use { st ->
            st.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                  scanId TEXT PRIMARY KEY,
                  schemaVersion INTEGER NOT NULL,
                  configHash TEXT NOT NULL,
                  cursorIndex INTEGER NOT NULL,
                  totalHosts INTEGER NOT NULL,
                  completedHostsJson TEXT NOT NULL,
                  createdAt INTEGER NOT NULL,
                  updatedAt INTEGER NOT NULL
                );
                """.trimIndent()
            )
            st.execute(
                """
                CREATE TABLE IF NOT EXISTS hole_age (
                  holeId TEXT PRIMARY KEY,
                  host TEXT NOT NULL,
                  technique TEXT NOT NULL,
                  status TEXT NOT NULL,
                  firstSeenAt INTEGER NOT NULL,
                  lastConfirmedAt INTEGER NOT NULL,
                  closedAt INTEGER,
                  closedReason TEXT,
                  lastConfidence REAL NOT NULL,
                  lastVerdict TEXT NOT NULL,
                  lastSeenWeakAt INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_hole_host ON hole_age(host);
                CREATE INDEX IF NOT EXISTS idx_hole_status ON hole_age(status);
                """.trimIndent()
            )
            st.execute(
                """
                CREATE TABLE IF NOT EXISTS host_fingerprints (
                  host TEXT PRIMARY KEY,
                  faviconHash TEXT,
                  jarmLite TEXT,
                  ja3Self TEXT,
                  techTagsJson TEXT,
                  updatedAt INTEGER NOT NULL
                );
                """.trimIndent()
            )
        }
    }

    companion object {
        fun open(dir: File): OmegaDatabase {
            dir.mkdirs()
            return OmegaDatabase(File(dir, "omega.db"))
        }
    }
}

class HoleRepository(
    private val conn: Connection?,
    private val fallback: HoleAgeStore
) {
    fun applyVerdict(host: String, verdict: Verdict, confidence: Double, technique: String = "aggregate") {
        if (conn == null) {
            fallback.applyVerdict(host, verdict, confidence, technique); return
        }
        val id = holeId(host, technique)
        val now = System.currentTimeMillis()
        when (verdict) {
            Verdict.CONFIRMED_CANDIDATE -> upsertOpen(id, host, technique, now, confidence, verdict)
            Verdict.CONFIRMED_NOT_VULNERABLE -> upsertClosed(id, host, technique, now, confidence, verdict)
            Verdict.WEAK_SIGNAL_ONLY -> touchWeak(id, now, confidence, verdict)
        }
    }

    fun list(openOnly: Boolean? = null): List<HoleRecord> {
        if (conn == null) return fallback.list(openOnly)
        val sql = buildString {
            append("SELECT * FROM hole_age")
            when (openOnly) {
                true -> append(" WHERE status='open'")
                false -> append(" WHERE status='closed'")
                null -> {}
            }
            append(" ORDER BY lastConfirmedAt DESC")
        }
        return conn.createStatement().use { st ->
            st.executeQuery(sql).use { rs ->
                val out = mutableListOf<HoleRecord>()
                while (rs.next()) {
                    out += HoleRecord(
                        holeId = rs.getString("holeId"),
                        host = rs.getString("host"),
                        technique = rs.getString("technique"),
                        status = rs.getString("status"),
                        firstSeenAt = rs.getLong("firstSeenAt"),
                        lastConfirmedAt = rs.getLong("lastConfirmedAt"),
                        closedAt = rs.getLong("closedAt").takeIf { !rs.wasNull() },
                        closedReason = rs.getString("closedReason"),
                        lastConfidence = rs.getDouble("lastConfidence"),
                        lastVerdict = rs.getString("lastVerdict"),
                        lastSeenWeakAt = rs.getLong("lastSeenWeakAt").takeIf { !rs.wasNull() }
                    )
                }
                out
            }
        }
    }

    private fun upsertOpen(id: String, host: String, technique: String, now: Long, conf: Double, v: Verdict) {
        conn!!.prepareStatement(
            """
            INSERT INTO hole_age(holeId,host,technique,status,firstSeenAt,lastConfirmedAt,closedAt,closedReason,lastConfidence,lastVerdict,lastSeenWeakAt)
            VALUES(?,?,?,?,?,?,NULL,NULL,?,?,NULL)
            ON CONFLICT(holeId) DO UPDATE SET status='open', lastConfirmedAt=excluded.lastConfirmedAt,
              lastConfidence=excluded.lastConfidence, lastVerdict=excluded.lastVerdict, closedAt=NULL, closedReason=NULL
            """.trimIndent()
        ).use { ps ->
            ps.setString(1, id); ps.setString(2, host); ps.setString(3, technique); ps.setString(4, "open")
            ps.setLong(5, now); ps.setLong(6, now); ps.setDouble(7, conf); ps.setString(8, v.name)
            ps.executeUpdate()
        }
    }

    private fun upsertClosed(id: String, host: String, technique: String, now: Long, conf: Double, v: Verdict) {
        conn!!.prepareStatement(
            """
            INSERT INTO hole_age(holeId,host,technique,status,firstSeenAt,lastConfirmedAt,closedAt,closedReason,lastConfidence,lastVerdict,lastSeenWeakAt)
            VALUES(?,?,?,?,?,?,?,?,?,?,NULL)
            ON CONFLICT(holeId) DO UPDATE SET status='closed', closedAt=excluded.closedAt, closedReason='DEFINITIVE_REFUTE',
              lastConfidence=excluded.lastConfidence, lastVerdict=excluded.lastVerdict
            """.trimIndent()
        ).use { ps ->
            ps.setString(1, id); ps.setString(2, host); ps.setString(3, technique); ps.setString(4, "closed")
            ps.setLong(5, now); ps.setLong(6, now); ps.setLong(7, now); ps.setString(8, "DEFINITIVE_REFUTE")
            ps.setDouble(9, conf); ps.setString(10, v.name)
            ps.executeUpdate()
        }
    }

    private fun touchWeak(id: String, now: Long, conf: Double, v: Verdict) {
        conn!!.prepareStatement(
            "UPDATE hole_age SET lastSeenWeakAt=?, lastConfidence=?, lastVerdict=? WHERE holeId=?"
        ).use { ps ->
            ps.setLong(1, now); ps.setDouble(2, conf); ps.setString(3, v.name); ps.setString(4, id)
            ps.executeUpdate()
        }
    }

    private fun holeId(host: String, technique: String): String {
        val d = MessageDigest.getInstance("SHA-256").digest("$host|$technique".toByteArray())
        return d.joinToString("") { "%02x".format(it) }.take(16)
    }
}

class CheckpointRepository(
    private val conn: Connection?,
    private val fallback: CheckpointStore
) {
    fun save(cp: CheckpointRecord) {
        if (conn == null) { fallback.save(cp); return }
        cp.updatedAt = System.currentTimeMillis()
        val json = cp.completedHosts.joinToString("\n")
        conn.prepareStatement(
            """
            INSERT INTO checkpoints(scanId,schemaVersion,configHash,cursorIndex,totalHosts,completedHostsJson,createdAt,updatedAt)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(scanId) DO UPDATE SET cursorIndex=excluded.cursorIndex, completedHostsJson=excluded.completedHostsJson,
              updatedAt=excluded.updatedAt, configHash=excluded.configHash, totalHosts=excluded.totalHosts
            """.trimIndent()
        ).use { ps ->
            ps.setString(1, cp.scanId); ps.setInt(2, cp.schemaVersion); ps.setString(3, cp.configHash)
            ps.setInt(4, cp.cursorIndex); ps.setInt(5, cp.totalHosts); ps.setString(6, json)
            ps.setLong(7, cp.createdAt); ps.setLong(8, cp.updatedAt)
            ps.executeUpdate()
        }
    }

    fun get(id: String): CheckpointRecord? {
        if (conn == null) return fallback.get(id)
        conn.prepareStatement("SELECT * FROM checkpoints WHERE scanId=?").use { ps ->
            ps.setString(1, id)
            ps.executeQuery().use { rs ->
                if (!rs.next()) return null
                return CheckpointRecord(
                    scanId = rs.getString("scanId"),
                    schemaVersion = rs.getInt("schemaVersion"),
                    configHash = rs.getString("configHash"),
                    cursorIndex = rs.getInt("cursorIndex"),
                    totalHosts = rs.getInt("totalHosts"),
                    completedHosts = rs.getString("completedHostsJson").lines().filter { it.isNotBlank() }.toMutableList(),
                    createdAt = rs.getLong("createdAt"),
                    updatedAt = rs.getLong("updatedAt")
                )
            }
        }
    }

    fun list(): List<CheckpointRecord> {
        if (conn == null) return fallback.list()
        return conn.createStatement().use { st ->
            st.executeQuery("SELECT scanId FROM checkpoints ORDER BY updatedAt DESC").use { rs ->
                val ids = mutableListOf<String>()
                while (rs.next()) ids += rs.getString(1)
                ids.mapNotNull { get(it) }
            }
        }
    }

    fun clear(id: String) {
        if (conn == null) { fallback.clear(id); return }
        conn.prepareStatement("DELETE FROM checkpoints WHERE scanId=?").use { it.setString(1, id); it.executeUpdate() }
    }
}
