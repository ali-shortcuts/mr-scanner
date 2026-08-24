package com.mrscanner.omega.core.eventbus
import com.mrscanner.omega.core.plugin.ConfidenceReport
import com.mrscanner.omega.core.plugin.NetworkProfile
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow

sealed class ScanEvent {
    data class LogEmitted(val level: String, val message: String, val ts: Long = System.currentTimeMillis()) : ScanEvent()
    data class Progress(val done: Int, val total: Int, val host: String?) : ScanEvent()
    data class HostVerdict(val host: String, val report: ConfidenceReport, val summaries: List<String> = emptyList()) : ScanEvent()
    data class CheckpointSaved(val scanId: String, val cursor: Int) : ScanEvent()
    data class HoleClosed(val holeId: String, val host: String, val reason: String) : ScanEvent()
    data class BudgetExceeded(val host: String, val skippedPlugins: List<String>) : ScanEvent()
    data class ProfileChanged(val profile: NetworkProfile) : ScanEvent()
    data class ScanFinished(val scanId: String, val hostCount: Int, val wallMs: Long) : ScanEvent()
}

class EventBus {
    private val _events = MutableSharedFlow<ScanEvent>(extraBufferCapacity = 256)
    val events = _events.asSharedFlow()
    suspend fun emit(e: ScanEvent) { _events.emit(e) }
    fun tryEmit(e: ScanEvent) = _events.tryEmit(e)
}
