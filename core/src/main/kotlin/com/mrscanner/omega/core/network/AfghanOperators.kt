package com.mrscanner.omega.core.network

/**
 * MCC 412 (Afghanistan) operator table — MNC codes cross-checked against
 * multiple independent sources (ITU Operational Bulletin listings, Routee's
 * MCC/MNC database, and Wikipedia's Asia/Oceania operator list) before being
 * hardcoded here, specifically to avoid shipping an invented or stale
 * mapping for something Ali uses for real field identification.
 *
 * Two of Ali's domains map to the SAME operator under different brand names
 * (AWCC/awcc.af and afghan-wireless.com are one network, 412-01; Afghan
 * Telecom/afghantelecom.af and Salaam/salaam.af are one network, 412-80).
 * "Areeba Afghanistan" (412-40) has rebranded to ATOMA per Wikipedia, but
 * ITU bulletins still list the older name — both are recorded here.
 */
object AfghanOperators {
    data class Operator(val mccMnc: String, val brand: String, val domain: String?, val notes: String? = null)

    val TABLE: List<Operator> = listOf(
        Operator("412-01", "AWCC / Afghan Wireless", "awcc.af"),
        Operator("412-20", "Roshan", "roshan.af"),
        Operator("412-40", "Areeba Afghanistan / ATOMA", "atoma.com.af", "rebranded from Areeba/MTN"),
        Operator("412-50", "Etisalat Afghanistan", "etisalat.af"),
        Operator("412-80", "Afghan Telecom (Salaam)", "afghantelecom.af"),
        Operator("412-88", "Afghan Telecom (Salaam)", "salaam.af")
    )

    /** [mccMnc] as reported by TelephonyManager, formatted "412-01" (see SimOperatorDetector). */
    fun lookup(mccMnc: String?): Operator? = mccMnc?.let { key -> TABLE.firstOrNull { it.mccMnc == key } }

    /** True if [mccMnc] belongs to any Afghan operator (MCC 412), even one not in [TABLE] yet. */
    fun isAfghan(mccMnc: String?): Boolean = mccMnc?.startsWith("412-") == true
}
