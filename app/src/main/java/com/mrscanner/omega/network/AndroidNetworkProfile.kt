package com.mrscanner.omega.network
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.mrscanner.omega.core.plugin.NetworkProfile

object AndroidNetworkProfile {
    fun detect(context: Context): NetworkProfile {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return NetworkProfile.UNKNOWN
        val net = cm.activeNetwork ?: return NetworkProfile.UNKNOWN
        val caps = cm.getNetworkCapabilities(net) ?: return NetworkProfile.UNKNOWN
        val vpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        val cell = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        val wifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        val metered = cm.isActiveNetworkMetered
        return when {
            vpn -> NetworkProfile.WIFI_PLUS_VPN
            cell || (metered && !wifi) -> NetworkProfile.CELLULAR_METERED
            wifi -> NetworkProfile.WIFI_UNMETERED
            else -> NetworkProfile.UNKNOWN
        }
    }
}
