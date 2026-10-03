package dev.windowsunlock.phone

import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.json.JSONObject
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.concurrent.TimeUnit
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class Relay(config: JSONObject, private val token: String) {
    companion object {
        private var cachedKey = ""
        private var cachedClient: OkHttpClient? = null
    }
    private val url = config.getString("relayUrl").trimEnd('/').toHttpUrl()
    private val client: OkHttpClient
    init {
        require(url.isHttps && url.username.isEmpty() && url.password.isEmpty() && url.query == null && url.fragment == null)
        val key = JSONObject().put("url", url.toString()).put("pin", config.getString("tlsPin")).put("ca", config.getString("caPem")).toString()
        client = synchronized(Relay::class.java) {
            if (key == cachedKey && cachedClient != null) cachedClient!! else {
                val ca = config.optString("caPem")
                val ks = if (ca.isBlank()) null else KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                    load(null)
                    setCertificateEntry("relay-root", CertificateFactory.getInstance("X.509").generateCertificate(ca.byteInputStream()))
                }
                val tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }.trustManagers.single() as X509TrustManager
                val ssl = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), null) }
                val builder = OkHttpClient.Builder().sslSocketFactory(ssl.socketFactory, tm)
                val pin = config.getString("tlsPin")
                if (pin != "system") builder.certificatePinner(CertificatePinner.Builder().add(url.host, pin).build())
                val created = builder
                    .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS)).followRedirects(false).followSslRedirects(false)
                    .connectTimeout(5, TimeUnit.SECONDS).readTimeout(5, TimeUnit.SECONDS).callTimeout(8, TimeUnit.SECONDS).build()
                cachedClient?.connectionPool?.evictAll()
                cachedKey = key
                cachedClient = created
                created
            }
        }
    }
    fun call(method: String, path: String, body: JSONObject? = null): JSONObject {
        val target = url.toString().trimEnd('/') + path
        val builder = Request.Builder().url(target).header("Authorization", "Bearer $token")
        val data = body?.toString()?.toRequestBody("application/json".toMediaType())
        builder.method(method, data)
        client.newCall(builder.build()).execute().use { r ->
            check(r.isSuccessful) { "Relay unavailable or request rejected" }
            val bytes = r.body?.byteStream()?.use { boundedRead(it) } ?: byteArrayOf()
            require(bytes.size <= 65536)
            return if (bytes.isEmpty()) JSONObject() else Protocol.strictJson(String(bytes, Charsets.UTF_8))
        }
    }
}

fun boundedRead(stream: java.io.InputStream): ByteArray {
    val out = java.io.ByteArrayOutputStream(); val buffer = ByteArray(4096)
    while (true) { val n = stream.read(buffer, 0, minOf(buffer.size, 65537 - out.size())); if (n < 0) break
        require(n > 0); out.write(buffer, 0, n); require(out.size() <= 65536) }
    return out.toByteArray()
}
