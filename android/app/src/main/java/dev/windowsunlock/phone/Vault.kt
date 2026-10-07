package dev.windowsunlock.phone

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

object Vault {
    fun alias(id: String) = "phoneunlock-vault-$id"
    fun generate(id: String): JSONObject {
        if (Build.VERSION.SDK_INT < 35) error("Phone sign-in requires Android 15+")
        val name = alias(id)
        val existing = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (existing.containsAlias(name)) return publicKey(existing, name)
        @androidx.annotation.RequiresApi(35)
        fun create(strongBox: Boolean): java.security.KeyPair {
            val spec = KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setDigests(KeyProperties.DIGEST_SHA256).setMgf1Digests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .setIsStrongBoxBacked(strongBox).build()
            return try { KeyPairGenerator.getInstance("RSA", "AndroidKeyStore").apply { initialize(spec) }.generateKeyPair() }
                catch (e: Exception) { Keys.delete(name); throw e }
        }
        try { create(true) } catch (_: android.security.keystore.StrongBoxUnavailableException) { create(false) }
          catch (_: java.security.InvalidAlgorithmParameterException) { create(false) }
          catch (_: java.security.ProviderException) { create(false) }
        return publicKey(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }, name)
    }
    fun exists(id: String) = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias(id))
    private fun publicKey(store: KeyStore, name: String): JSONObject {
        if (Build.VERSION.SDK_INT < 35) error("Phone sign-in requires Android 15+")
        val info = KeyFactory.getInstance("RSA", "AndroidKeyStore").getKeySpec(store.getKey(name, null), KeyInfo::class.java)
        if (info.securityLevel !in listOf(KeyProperties.SECURITY_LEVEL_STRONGBOX, KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)) { Keys.delete(name); error("Hardware-backed vault key required") }
        require(info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds == 0 && info.isUserAuthenticationRequirementEnforcedBySecureHardware) { "Hardware-enforced per-use authentication required" }
        val pub = store.getCertificate(name).publicKey as RSAPublicKey
        fun unsigned(v: BigInteger) = v.toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        return JSONObject().put("kty", "RSA").put("n", Protocol.b64(unsigned(pub.modulus))).put("e", Protocol.b64(unsigned(pub.publicExponent)))
    }
    fun cipher(id: String): Cipher {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
            init(Cipher.DECRYPT_MODE, store.getKey(alias(id), null) as PrivateKey, OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT))
        }
    }
    fun release(cipher: Cipher, request: JSONObject): String {
        Protocol.lifetime(request, 60)
        val key = cipher.doFinal(VaultProtocol.bytes(request.getString("wrappedKey"), 256))
        try {
            require(key.size == 32)
            val j = request.getJSONObject("ephemeralJwk"); VaultProtocol.rsa(j)
            val pub = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(BigInteger(1, VaultProtocol.bytes(j.getString("n"), 256)), BigInteger.valueOf(65537)))
            val output = Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.ENCRYPT_MODE, pub, OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)) }.doFinal(key)
            return Protocol.b64(output)
        } finally { key.fill(0) }
    }
}

object VaultProtocol {
    private val types = setOf("vault-delegation", "vault-enroll", "vault-enrolled", "vault-unlock", "vault-response", "vault-cancel")
    fun allowed(type: String) = type in types
    fun bytes(value: String, size: Int): ByteArray = Base64.getUrlDecoder().decode(value).also { require(it.size == size && Protocol.b64(it) == value) }
    fun rsa(j: JSONObject) { require(j.keys().asSequence().toSet() == setOf("kty", "n", "e") && j.getString("kty") == "RSA" && j.getString("e") == "AQAB"); require((bytes(j.getString("n"), 256)[0].toInt() and 255) >= 128) }
    fun verify(token: String, config: JSONObject): JSONObject {
        val raw = Protocol.decode(token); require(raw.getString("type") in setOf("vault-enroll", "vault-unlock"))
        val delegation = Protocol.verify(raw.getString("delegationJws"), config.getJSONObject("windowsJwk"), "vault-delegation")
        require(delegation.length() == 11 && delegation.getString("purpose") == "password-unlock")
        require(delegation.getString("windowsDeviceId") == Protocol.decode(config.getString("invitationJws")).getString("windowsDeviceId") && delegation.getString("pairingId") == config.getString("pairingId") && delegation.getString("androidDeviceId") == config.getString("androidDeviceId"))
        for (name in listOf("vaultId", "accountBindingId")) require(delegation.getString(name).matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")))
        require(delegation.getString("windowsAccountSid").matches(Regex("S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+")))
        require(delegation.getString("loginName").length in 1..256 && !delegation.getString("loginName").any { it.code < 32 })
        Protocol.publicKey(delegation.getJSONObject("machineJwk"))
        val enroll = raw.getString("type") == "vault-enroll"
        val p = Protocol.verify(token, if (enroll) config.getJSONObject("windowsJwk") else delegation.getJSONObject("machineJwk"), raw.getString("type"))
        require(p.getString("purpose") == "password-unlock" && p.length() == (if (enroll) 8 else 12))
        Protocol.lifetime(p, if (enroll) 300 else 60)
        require(p.getString("requestId").matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")))
        if (!enroll) {
            require(p.getInt("sessionId") > 0 && p.getInt("usageScenario") in 1..2); rsa(p.getJSONObject("ephemeralJwk")); bytes(p.getString("wrappedKey"), 256)
            val record = config.getJSONObject("vaults").getJSONObject(delegation.getString("vaultId"))
            require(record.getString("delegationJws") == p.getString("delegationJws"))
        }
        return p
    }
    fun response(p: JSONObject, token: String, decision: String): JSONObject = Protocol.message(if (p.getString("type") == "vault-enroll") "vault-enrolled" else "vault-response", "password-unlock")
        .put("requestId", p.getString("requestId")).put("challengeHash", Protocol.hash(token)).put("decision", decision)
}
