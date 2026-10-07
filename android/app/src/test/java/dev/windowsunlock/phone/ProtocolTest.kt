package dev.windowsunlock.phone

import org.junit.Test
import org.junit.Assert.*
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.security.spec.ECGenParameterSpec

class ProtocolTest {
    @Test fun hashVector() { assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Protocol.hash("abc")) }
    @Test fun duplicateRejected() { try { Protocol.strictJson("{\"a\":1,\"\\u0061\":2}"); fail("Duplicate accepted") } catch (_: IllegalArgumentException) {} }
    @Test fun es256SignatureFormatAndPurpose() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val jwk = JSONObject(ECKey.Builder(Curve.P_256, pair.public as ECPublicKey).build().toJSONString())
        val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(pair.private) }
        val token = Protocol.sign(Protocol.input(Protocol.message("auth-response").put("decision", "approve")), sig)
        assertEquals("approve", Protocol.verify(token, jwk, "auth-response").getString("decision"))
        System.getProperty("phoneunlock.fixtureOutput")?.let { path -> java.io.File(path).apply { parentFile?.mkdirs(); writeText(JSONObject().put("jwk", jwk).put("token", token).toString()) } }
        try { Protocol.verify(token, jwk, "auth-request"); fail("Wrong purpose accepted") } catch (_: IllegalArgumentException) {}
    }
    @Test fun privateKeyRejected() { try { Protocol.publicKey(JSONObject().put("kty", "EC").put("crv", "P-256").put("x", "x").put("y", "y").put("d", "secret")); fail() } catch (_: IllegalArgumentException) {} }
    @Test fun windowsUnlockPurposeIsRestrictedToAuthenticationMessages() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val jwk = JSONObject(ECKey.Builder(Curve.P_256, pair.public as ECPublicKey).build().toJSONString())
        fun signed(type: String): String { val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(pair.private) }; return Protocol.sign(Protocol.input(Protocol.message(type, "windows-unlock")), sig) }
        assertEquals("windows-unlock", Protocol.verify(signed("auth-response"), jwk, "auth-response").getString("purpose"))
        try { Protocol.verify(signed("remote-command"), jwk, "remote-command"); fail("Unlock purpose accepted for remote command") } catch (_: IllegalArgumentException) {}
    }
    @Test fun cameraEnvelopeRejectsRelaySubstitutionAndWrongCommand() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val jwk = JSONObject(ECKey.Builder(Curve.P_256, pair.public as ECPublicKey).build().toJSONString())
        val wrapped = Protocol.b64(ByteArray(256) { it.toByte() })
        val envelope = Protocol.message("camera-envelope").put("cameraId", "camera").put("commandHash", "command")
            .put("windowsDeviceId", "windows").put("androidDeviceId", "phone").put("pairingId", "pair").put("keyHash", Protocol.hash(wrapped))
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(pair.private) }
        val token = Protocol.sign(Protocol.input(envelope), signature)
        val frame = JSONObject().put("envelopeJws", token).put("wrappedKey", wrapped)
        assertEquals(token, CameraCrypto.verifyEnvelope(frame, jwk, "windows", "phone", "pair", "camera", "command"))
        for (bad in listOf("other-command", "")) try { CameraCrypto.verifyEnvelope(frame, jwk, "windows", "phone", "pair", "camera", bad); fail("Wrong command accepted") } catch (_: IllegalArgumentException) {}
        frame.put("wrappedKey", Protocol.b64(ByteArray(256)))
        try { CameraCrypto.verifyEnvelope(frame, jwk, "windows", "phone", "pair", "camera", "command"); fail("Relay key substitution accepted") } catch (_: IllegalArgumentException) {}
    }
    @Test fun cngCameraEncryptionVerifiesOnJca() {
        val output = System.getProperty("phoneunlock.fixtureOutput") ?: return
        val root = java.io.File(output).parentFile?.parentFile ?: return
        val exe = root.resolve("build/windows/Release/core_tests.exe")
        org.junit.Assume.assumeTrue("Optional native interoperability check requires Windows build", exe.exists())
        val ec = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val jwk = JSONObject(ECKey.Builder(Curve.P_256, ec.public as ECPublicKey).build().toJSONString())
        val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(ec.private) }
        val token = Protocol.sign(Protocol.input(Protocol.message("auth-response")), sig)
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val pub = rsa.public as RSAPublicKey
        fun unsigned(n: java.math.BigInteger) = n.toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        val cameraJwk = JSONObject().put("kty", "RSA").put("n", Protocol.b64(unsigned(pub.modulus))).put("e", Protocol.b64(unsigned(pub.publicExponent)))
        val file = java.io.File(output + ".camera.json")
        file.writeText(JSONObject().put("jwk", jwk).put("token", token).put("cameraJwk", cameraJwk).toString())
        val process = ProcessBuilder(exe.absolutePath, "--interop", file.absolutePath).redirectErrorStream(true).start()
        check(process.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)); assertEquals(0, process.exitValue())
        val frame = JSONObject(java.io.File(file.absolutePath + ".windows.json").readText()).getJSONObject("cameraFrame")
        fun bytes(field: String) = Base64.getUrlDecoder().decode(frame.getString(field))
        val key = CameraCrypto.unwrap(rsa.private, bytes("wrappedKey"))
        val data = bytes("ciphertext"); val iv = bytes("iv")
        assertEquals("camera", String(CameraCrypto.decrypt(key, iv, data, "test-session", 1)))
        data[0] = (data[0].toInt() xor 1).toByte()
        try { CameraCrypto.decrypt(key, iv, data, "test-session", 1); fail("Tampered frame accepted") } catch (_: javax.crypto.AEADBadTagException) {}
        key.fill(0)
    }
}
