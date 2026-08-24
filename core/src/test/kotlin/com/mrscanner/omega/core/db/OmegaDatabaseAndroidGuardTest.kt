package com.mrscanner.omega.core.db

import com.mrscanner.omega.core.plugin.Verdict
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class OmegaDatabaseAndroidGuardTest {
    @TempDir lateinit var dir: File

    @Test
    fun opensWithoutCrashingOnJvm() {
        val db = OmegaDatabase.open(dir)
        assertNotNull(db.holes)
        db.holes.applyVerdict("example.com", Verdict.CONFIRMED_CANDIDATE, 0.9)
        assertTrue(db.holes.list(openOnly = true).any { it.host == "example.com" })
    }
}
