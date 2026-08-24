package com.mrscanner.omega.core.network
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

object SharedOkHttpFactory {
    @Volatile private var client: OkHttpClient? = null
    fun get(timeoutMs: Long = 5_000): OkHttpClient {
        client?.let { return it }
        return synchronized(this) {
            client ?: OkHttpClient.Builder()
                .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .writeTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .callTimeout(timeoutMs * 2, TimeUnit.MILLISECONDS)
                .connectionPool(ConnectionPool(32, 5, TimeUnit.MINUTES))
                .retryOnConnectionFailure(true)
                .followRedirects(false).followSslRedirects(false)
                .build().also { client = it }
        }
    }
}
