package com.mrscanner.omega.network

import android.content.Context
import android.telephony.TelephonyManager

/**
 * Detects SIM/network operator without READ_PHONE_STATE.
 * getSimOperator() / getNetworkOperator() do not require that permission.
 */
object SimOperatorDetector {
    data class OperatorInfo(
        val simOperator: String?,      // MCC+MNC e.g. 41201
        val simOperatorName: String?,
        val networkOperator: String?,
        val networkOperatorName: String?,
        val mccMnc: String?           // 412-01 form
    )

    fun detect(context: Context): OperatorInfo {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            ?: return OperatorInfo(null, null, null, null, null)
        val sim = tm.simOperator?.takeIf { it.length >= 5 }
        val net = tm.networkOperator?.takeIf { it.length >= 5 }
        fun fmt(code: String?) = code?.let {
            if (it.length >= 5) "${it.substring(0, 3)}-${it.substring(3)}" else it
        }
        return OperatorInfo(
            simOperator = sim,
            simOperatorName = tm.simOperatorName,
            networkOperator = net,
            networkOperatorName = tm.networkOperatorName,
            mccMnc = fmt(sim) ?: fmt(net)
        )
    }
}
