package dev.windowsunlock.phone

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.interfaces.ECPublicKey
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.util.Base64

object Keys {
    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    fun generate(id: String, auth: Boolean): JSONObject {
        fun create(strongBox: Boolean) {
            val spec = KeyGenParameterSpec.Builder(id, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256).setIsStrongBoxBacked(strongBox)
            if (auth) spec.setUserAuthenticationRequired(true).setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(spec.build()); generateKeyPair() }
        }
        try { create(true) } catch (_: StrongBoxUnavailableException) { create(false) }
        val key = store().getKey(id, null) as PrivateKey
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        @Suppress("DEPRECATION") val hardware = info.isInsideSecureHardware
        if (auth && !hardware && !BuildConfig.ALLOW_SOFTWARE_KEYS) { store().deleteEntry(id); error("Hardware-backed approval key unavailable") }
        val pub = store().getCertificate(id).publicKey as ECPublicKey
        return JSONObject(ECKey.Builder(Curve.P_256, pub).build().toPublicJWK().toJSONString())
    }
    fun signature(alias: String): Signature = Signature.getInstance("SHA256withECDSA").apply { initSign(store().getKey(alias, null) as PrivateKey) }
    fun delete(alias: String) { store().deleteEntry(alias) }
    fun cleanupCameraKeys() { val ks = store(); ks.aliases().toList().filter { it.startsWith("phoneunlock-camera-") }.forEach { ks.deleteEntry(it) } }
    fun save(context: Context, value: JSONObject) {
        val ks = store(); val alias = "phoneunlock-config"
        if (!ks.containsAlias(alias)) KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build()); generateKey()
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, ks.getKey(alias, null))
        val data = cipher.doFinal(value.toString().toByteArray(Charsets.UTF_8))
        val file = java.io.File(context.filesDir, "config.enc"); val tmp = java.io.File(context.filesDir, "config.tmp")
        tmp.writeText(JSONObject().put("iv", Base64.getEncoder().encodeToString(cipher.iv)).put("ciphertext", Base64.getEncoder().encodeToString(data)).toString())
        check(tmp.renameTo(file))
    }
    fun load(context: Context): JSONObject? {
        val file = java.io.File(context.filesDir, "config.enc"); if (!file.exists()) return null
        require(file.length() <= 131072); val envelope = JSONObject(file.readText())
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, store().getKey("phoneunlock-config", null), GCMParameterSpec(128, Base64.getDecoder().decode(envelope.getString("iv"))))
        return Protocol.strictJson(String(cipher.doFinal(Base64.getDecoder().decode(envelope.getString("ciphertext"))), Charsets.UTF_8))
    }
    fun clear(context: Context) { java.io.File(context.filesDir, "config.enc").delete() }
}
