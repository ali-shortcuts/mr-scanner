package com.mrscanner.omega.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Binds process network to cellular transport when available.
 * Critical for zero-rating / operator-path scans so traffic does not leak to Wi‑Fi.
 */
object CellularNetworkBinder {
    data class BindResult(
        val bound: Boolean,
        val detail: String,
        val network: Network? = null
    )

    fun bindToCellular(context: Context, timeoutMs: Long = 4_000): BindResult {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return BindResult(false, "no ConnectivityManager")
        // Already on cell?
        val active = cm.activeNetwork
        val caps = active?.let { cm.getNetworkCapabilities(it) }
        if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) {
            return BindResult(true, "already-cellular", active)
        }
        val latch = CountDownLatch(1)
        val found = AtomicReference<Network?>(null)
        val req = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                found.set(network)
                latch.countDown()
            }
        }
        return try {
            cm.requestNetwork(req, cb)
            val ok = latch.await(timeoutMs, TimeUnit.MILLISECONDS)
            val net = found.get()
            if (ok && net != null) {
                val bound = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    cm.bindProcessToNetwork(net)
                    true
                } else {
                    @Suppress("DEPRECATION")
                    ConnectivityManager.setProcessDefaultNetwork(net)
                    true
                }
                BindResult(bound, if (bound) "bound-cellular" else "bind-failed", net)
            } else {
                cm.unregisterNetworkCallback(cb)
                BindResult(false, "no-cellular-network")
            }
        } catch (e: Exception) {
            try { cm.unregisterNetworkCallback(cb) } catch (_: Exception) {}
            BindResult(false, e.message ?: "bind-error")
        }
    }

    fun clearBind(context: Context) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                cm.bindProcessToNetwork(null)
            } else {
                @Suppress("DEPRECATION")
                ConnectivityManager.setProcessDefaultNetwork(null)
            }
        } catch (_: Exception) {}
    }
}
