package com.mrscanner.omega.core.intelligence
import com.mrscanner.omega.core.plugin.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ConfidenceEngineV3Test {
    private fun sig(p: SignalPolarity, c: EvidenceClass, id: String = "p") = PluginSignal(id, p, c)

    @Test fun t1_definitive_support() {
        val r = ConfidenceEngineV3.compute(listOf(sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE)))
        assertEquals(Verdict.CONFIRMED_CANDIDATE, r.verdict); assertTrue(r.confidence >= 0.9)
    }
    @Test fun t2_definitive_refute() {
        val r = ConfidenceEngineV3.compute(listOf(sig(SignalPolarity.REFUTES_BYPASS, EvidenceClass.DEFINITIVE)))
        assertEquals(Verdict.CONFIRMED_NOT_VULNERABLE, r.verdict); assertTrue(r.confidence <= 0.1)
    }
    @Test fun t3_two_strong_support() {
        val r = ConfidenceEngineV3.compute(listOf(
            sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG, "a"),
            sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG, "b")))
        assertEquals(Verdict.CONFIRMED_CANDIDATE, r.verdict)
    }
    @Test fun t4_single_strong_weak_label() {
        val r = ConfidenceEngineV3.compute(listOf(sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG)))
        assertEquals(Verdict.WEAK_SIGNAL_ONLY, r.verdict); assertTrue(r.confidence > 0.7)
    }
    @Test fun t5_ten_weak_not_confirmed() {
        val r = ConfidenceEngineV3.compute((1..10).map { sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.WEAK, "w$it") })
        assertEquals(Verdict.WEAK_SIGNAL_ONLY, r.verdict)
    }
    @Test fun t6_empty_mid() {
        val r = ConfidenceEngineV3.compute(emptyList())
        assertEquals(Verdict.WEAK_SIGNAL_ONLY, r.verdict); assertEquals(0.5, r.confidence, 1e-9)
    }
    @Test fun t7_definitive_not_diluted() {
        val r = ConfidenceEngineV3.compute(
            listOf(sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE, "d")) +
                (1..10).map { sig(SignalPolarity.REFUTES_BYPASS, EvidenceClass.WEAK, "w$it") })
        assertEquals(Verdict.CONFIRMED_CANDIDATE, r.verdict)
    }
    @Test fun t8_conflict() {
        val r = ConfidenceEngineV3.compute(listOf(
            sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE, "s"),
            sig(SignalPolarity.REFUTES_BYPASS, EvidenceClass.DEFINITIVE, "r")))
        assertEquals(Verdict.WEAK_SIGNAL_ONLY, r.verdict)
    }
    @Test fun t9_abstain_timeouts() {
        val r = ConfidenceEngineV3.compute(listOf(
            sig(SignalPolarity.ABSTAIN, EvidenceClass.DEFINITIVE, "t1"),
            sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG, "one")))
        assertEquals(Verdict.WEAK_SIGNAL_ONLY, r.verdict)
    }
    @Test fun t10_clamped() {
        val hi = ConfidenceEngineV3.compute((1..5).map { sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE, "d$it") })
        assertEquals(0.95, hi.confidence, 1e-9)
        val lo = ConfidenceEngineV3.compute((1..5).map { sig(SignalPolarity.REFUTES_BYPASS, EvidenceClass.DEFINITIVE, "d$it") })
        assertEquals(0.05, lo.confidence, 1e-9)
    }
    @Test fun contributing_excludes_abstain() {
        val r = ConfidenceEngineV3.compute(listOf(
            sig(SignalPolarity.ABSTAIN, EvidenceClass.STRONG, "a"),
            sig(SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE, "b")))
        assertEquals(1, r.contributingSignals.size)
    }
    @Test fun symmetric_two_strong_refute() {
        val r = ConfidenceEngineV3.compute(listOf(
            sig(SignalPolarity.REFUTES_BYPASS, EvidenceClass.STRONG, "a"),
            sig(SignalPolarity.REFUTES_BYPASS, EvidenceClass.STRONG, "b")))
        assertEquals(Verdict.CONFIRMED_NOT_VULNERABLE, r.verdict)
    }
}
