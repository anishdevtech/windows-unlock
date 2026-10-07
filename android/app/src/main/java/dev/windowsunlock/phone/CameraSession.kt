package dev.windowsunlock.phone

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64
import org.json.JSONObject

class CameraSession(val id: String, private val config: JSONObject) : AutoCloseable {
    private val alias = "phoneunlock-camera-$id"
    private var sessionKey: ByteArray? = null
    private var expectedCommandHash = ""
    private var envelopeToken = ""
    fun bind(commandHash: String) { check(expectedCommandHash.isEmpty()); expectedCommandHash = commandHash }
    private var sequence = 0L
    val lastSequence: Long get() = sequence
    private val deadline = android.os.SystemClock.elapsedRealtime() + 60000
    val publicKey: JSONObject
    init {
        // API 35 exposes explicit MGF1 digest authorization for Keystore OAEP keys.
        if (Build.VERSION.SDK_INT < 35) error("Live camera requires Android 15+")
        @androidx.annotation.RequiresApi(35)
        fun generate(strongBox: Boolean): java.security.KeyPair {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setDigests(KeyProperties.DIGEST_SHA256).setMgf1Digests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(strongBox).build()
            return try { KeyPairGenerator.getInstance("RSA", "AndroidKeyStore").apply { initialize(spec) }.generateKeyPair() }
                catch (e: Exception) { Keys.delete(alias); throw e }
        }
        val pair = try { generate(true) } catch (_: StrongBoxUnavailableException) { Keys.delete(alias); generate(false) }
          catch (_: java.security.InvalidAlgorithmParameterException) { Keys.delete(alias); generate(false) }
          catch (_: java.security.ProviderException) { Keys.delete(alias); generate(false) }
        val info = KeyFactory.getInstance("RSA", "AndroidKeyStore").getKeySpec(pair.private, KeyInfo::class.java)
        if (info.securityLevel !in listOf(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, KeyProperties.SECURITY_LEVEL_STRONGBOX) && !BuildConfig.ALLOW_SOFTWARE_KEYS) { Keys.delete(alias); error("Hardware-backed viewer key required") }
        val key = pair.public as RSAPublicKey
        fun unsigned(n: BigInteger): ByteArray = n.toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        publicKey = JSONObject().put("kty", "RSA").put("n", Protocol.b64(unsigned(key.modulus))).put("e", Protocol.b64(unsigned(key.publicExponent)))
    }
    fun decrypt(frame: JSONObject): ByteArray {
        check(android.os.SystemClock.elapsedRealtime() < deadline)
        val seq = frame.getLong("sequence"); require(seq > sequence && seq <= 120)
        fun bytes(name: String): ByteArray {
            val value = frame.getString(name); val bytes = Base64.getUrlDecoder().decode(value)
            require(Protocol.b64(bytes) == value); return bytes
        }
        val token = frame.getString("envelopeJws")
        if (sessionKey == null) {
            check(expectedCommandHash.isNotEmpty())
            val windowsId = Protocol.decode(config.getString("invitationJws")).getString("windowsDeviceId")
            envelopeToken = CameraCrypto.verifyEnvelope(frame, config.getJSONObject("windowsJwk"), windowsId, config.getString("androidDeviceId"), config.getString("pairingId"), id, expectedCommandHash)
            val wrapped = bytes("wrappedKey"); require(wrapped.size == 256)
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            sessionKey = CameraCrypto.unwrap(store.getKey(alias, null) as PrivateKey, wrapped)
        }
        require(token == envelopeToken)
        val iv = bytes("iv"); require(iv.size == 12)
        val data = bytes("ciphertext"); require(data.size in 17..45016)
        return CameraCrypto.decrypt(sessionKey!!, iv, data, id, seq).also { sequence = seq }
    }
    override fun close() { sessionKey?.fill(0); sessionKey = null; Keys.delete(alias) }
}
