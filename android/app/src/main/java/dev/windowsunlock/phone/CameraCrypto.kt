package dev.windowsunlock.phone

import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object CameraCrypto {
    fun verifyEnvelope(frame: org.json.JSONObject, windowsJwk: org.json.JSONObject, windowsId: String, phoneId: String, pairingId: String, cameraId: String, commandHash: String): String {
        require(commandHash.isNotEmpty())
        val token = frame.getString("envelopeJws")
        val e = Protocol.verify(token, windowsJwk, "camera-envelope")
        require(e.length() == 9 && e.getString("cameraId") == cameraId && e.getString("commandHash") == commandHash &&
            e.getString("windowsDeviceId") == windowsId && e.getString("androidDeviceId") == phoneId &&
            e.getString("pairingId") == pairingId && e.getString("keyHash") == Protocol.hash(frame.getString("wrappedKey")))
        return token
    }
    fun unwrap(key: PrivateKey, wrapped: ByteArray): ByteArray {
        require(wrapped.size == 256)
        val rsa = Cipher.getInstance("RSA/ECB/OAEPPadding")
        rsa.init(Cipher.DECRYPT_MODE, key, OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT))
        return rsa.doFinal(wrapped).also { require(it.size == 32) }
    }
    fun decrypt(key: ByteArray, iv: ByteArray, data: ByteArray, session: String, sequence: Long): ByteArray {
        require(key.size == 32 && iv.size == 12 && data.size in 17..45016)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD("$session:$sequence".toByteArray(Charsets.UTF_8))
        return cipher.doFinal(data)
    }
}
