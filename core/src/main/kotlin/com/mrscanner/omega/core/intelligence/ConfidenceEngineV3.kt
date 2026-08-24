package com.mrscanner.omega.core.intelligence

import com.mrscanner.omega.core.plugin.*
import kotlin.math.exp

object ConfidenceEngineV3 {
    fun compute(signals: List<PluginSignal>): ConfidenceReport {
        val logOdds = signals.sumOf { s ->
            when (s.polarity) {
                SignalPolarity.SUPPORTS_BYPASS -> +s.evidenceClass.logOddsWeight
                SignalPolarity.REFUTES_BYPASS -> -s.evidenceClass.logOddsWeight
                SignalPolarity.ABSTAIN -> 0.0
            }
        }
        val raw = 1.0 / (1.0 + exp(-logOdds))
        val clamped = raw.coerceIn(0.05, 0.95)
        val support = decisive(signals, SignalPolarity.SUPPORTS_BYPASS)
        val refute = decisive(signals, SignalPolarity.REFUTES_BYPASS)
        val verdict = when {
            support && refute -> resolveConflict(signals)
            support -> Verdict.CONFIRMED_CANDIDATE
            refute -> Verdict.CONFIRMED_NOT_VULNERABLE
            else -> Verdict.WEAK_SIGNAL_ONLY
        }
        val active = signals.filter { it.polarity != SignalPolarity.ABSTAIN }
        return ConfidenceReport(clamped, logOdds, verdict, active, EvidenceExplainer.explain(verdict, active, clamped))
    }

    private fun decisive(signals: List<PluginSignal>, p: SignalPolarity): Boolean {
        val def = signals.any { it.evidenceClass == EvidenceClass.DEFINITIVE && it.polarity == p }
        val strong = signals.count { it.evidenceClass == EvidenceClass.STRONG && it.polarity == p } >= 2
        return def || strong
    }

    private fun resolveConflict(signals: List<PluginSignal>): Verdict {
        fun score(p: SignalPolarity) = signals.filter { it.polarity == p }.sumOf { it.evidenceClass.logOddsWeight }
        val s = score(SignalPolarity.SUPPORTS_BYPASS)
        val r = score(SignalPolarity.REFUTES_BYPASS)
        return when {
            s > r + 1.0 -> Verdict.CONFIRMED_CANDIDATE
            r > s + 1.0 -> Verdict.CONFIRMED_NOT_VULNERABLE
            else -> Verdict.WEAK_SIGNAL_ONLY
        }
    }
}

object EvidenceExplainer {
    fun explain(v: Verdict, signals: List<PluginSignal>, conf: Double): String {
        if (signals.isEmpty()) return "verdict=$v conf=${"%.2f".format(conf)} top=[]"
        val top = signals.sortedByDescending { it.evidenceClass.logOddsWeight }.take(5)
            .joinToString { "${it.pluginId.substringAfterLast('.')}:${it.polarity.name}/${it.evidenceClass.name}" }
        val dS = signals.count { it.evidenceClass == EvidenceClass.DEFINITIVE && it.polarity == SignalPolarity.SUPPORTS_BYPASS }
        val dR = signals.count { it.evidenceClass == EvidenceClass.DEFINITIVE && it.polarity == SignalPolarity.REFUTES_BYPASS }
        val sS = signals.count { it.evidenceClass == EvidenceClass.STRONG && it.polarity == SignalPolarity.SUPPORTS_BYPASS }
        val sR = signals.count { it.evidenceClass == EvidenceClass.STRONG && it.polarity == SignalPolarity.REFUTES_BYPASS }
        return "verdict=$v conf=${"%.2f".format(conf)} DEF xS$dS/R$dR STR xS$sS/R$sR top=[$top]"
    }
}
