package dev.windowsunlock.phone

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.UUID
import java.util.Base64

class VaultTest {
    private fun ec() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun rsa() = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private fun jwk(pub: RSAPublicKey): JSONObject {
        fun unsigned(n: java.math.BigInteger) = n.toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        return JSONObject().put("kty", "RSA").put("n", Protocol.b64(unsigned(pub.modulus))).put("e", "AQAB")
    }
    private fun signed(k: java.security.KeyPair, p: JSONObject) = Protocol.sign(Protocol.input(p), Signature.getInstance("SHA256withECDSA").apply { initSign(k.private) })
    private fun rejected(f: () -> Unit) { try { f(); fail("Untrusted vault input accepted") } catch (_: IllegalArgumentException) {} }
    @Test fun vaultRequestsRequireRootDelegationAndExactEnrollment() {
        val root = ec(); val machine = ec(); val stranger = ec(); val rsa = rsa()
        fun ecJwk(k: java.security.KeyPair) = JSONObject(ECKey.Builder(Curve.P_256, k.public as ECPublicKey).build().toJSONString())
        val wid = UUID.randomUUID().toString(); val aid = UUID.randomUUID().toString(); val pair = UUID.randomUUID().toString(); val id = UUID.randomUUID().toString()
        val d = Protocol.message("vault-delegation", "password-unlock").put("vaultId", id).put("windowsDeviceId", wid).put("androidDeviceId", aid).put("pairingId", pair)
            .put("accountBindingId", UUID.randomUUID().toString()).put("windowsAccountSid", "S-1-5-21-1-2-3-1001").put("loginName", "MicrosoftAccount\\test@example.com").put("machineJwk", ecJwk(machine))
        val delegate = signed(root, d)
        val c = JSONObject().put("windowsJwk", ecJwk(root)).put("androidDeviceId", aid).put("pairingId", pair)
            .put("invitationJws", signed(root, Protocol.message("pair-invitation").put("windowsDeviceId", wid)))
            .put("vaults", JSONObject().put(id, JSONObject().put("delegationJws", delegate)))
        val now = System.currentTimeMillis() / 1000
        val p = Protocol.message("vault-unlock", "password-unlock").put("requestId", UUID.randomUUID().toString()).put("nonce", Protocol.b64(ByteArray(32)))
            .put("issuedAt", now).put("expiresAt", now + 60).put("delegationJws", delegate).put("sessionId", 1).put("usageScenario", 1).put("ephemeralJwk", jwk(rsa.public as RSAPublicKey)).put("wrappedKey", Protocol.b64(ByteArray(256)))
        assertEquals("vault-unlock", VaultProtocol.verify(signed(machine, p), c).getString("type"))
        rejected { VaultProtocol.verify(signed(stranger, p), c) }
        for (changes in listOf(JSONObject().put("purpose", "desktop-approval"), JSONObject().put("sessionId", 0), JSONObject().put("password", "secret"), JSONObject().put("expiresAt", now - 1))) {
            val bad = JSONObject(p.toString()); changes.keys().forEach { bad.put(it, changes.get(it)) }; rejected { VaultProtocol.verify(signed(machine, bad), c) }
        }
        val modified = JSONObject(d.toString()).put("loginName", "OTHER\\account"); val bad = JSONObject(p.toString()).put("delegationJws", signed(root, modified))
        rejected { VaultProtocol.verify(signed(machine, bad), c) }
        rejected { VaultProtocol.rsa(JSONObject(jwk(rsa.public as RSAPublicKey).toString()).put("d", "private")) }
    }
    @Test fun releasedKeyIsEncryptedOnlyForFreshLaptopKey() {
        val phone = rsa(); val laptop = rsa(); val other = rsa(); val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
        val stored = Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.ENCRYPT_MODE, phone.public, oaep) }.doFinal(key)
        val now = System.currentTimeMillis() / 1000
        val r = JSONObject().put("issuedAt", now).put("expiresAt", now + 60).put("nonce", Protocol.b64(ByteArray(32))).put("wrappedKey", Protocol.b64(stored)).put("ephemeralJwk", jwk(laptop.public as RSAPublicKey))
        val decrypt = Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.DECRYPT_MODE, phone.private, oaep) }
        val released = Vault.release(decrypt, r)
        assertArrayEquals(key, Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.DECRYPT_MODE, laptop.private, oaep) }.doFinal(VaultProtocol.bytes(released, 256)))
        try { Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.DECRYPT_MODE, other.private, oaep) }.doFinal(VaultProtocol.bytes(released, 256)); fail("Wrong laptop decrypted key") } catch (_: javax.crypto.BadPaddingException) {}
        key.fill(0)
    }
    @Test fun windowsCngVaultEnvelopeDecryptsOnJava() {
        val output = System.getProperty("phoneunlock.fixtureOutput") ?: return
        val root = java.io.File(output).parentFile?.parentFile ?: return
        val exe = root.resolve("build/windows/Release/vault_tests.exe")
        org.junit.Assume.assumeTrue(exe.exists())
        val phone = rsa(); val file = java.io.File(output + ".vault.json"); file.writeText(JSONObject().put("rsaJwk", jwk(phone.public as RSAPublicKey)).toString())
        val process = ProcessBuilder(exe.absolutePath, "--interop", file.absolutePath).redirectErrorStream(true).start()
        assertTrue(process.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)); assertEquals(process.inputStream.bufferedReader().readText(), 0, process.exitValue())
        val c = JSONObject(java.io.File(file.absolutePath + ".windows.json").readText()); val env = c.getJSONObject("envelope")
        val key = Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.DECRYPT_MODE, phone.private, OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)) }.doFinal(VaultProtocol.bytes(c.getString("wrappedKey"), 256))
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, Base64.getUrlDecoder().decode(env.getString("iv")))); updateAAD(c.getString("aad").toByteArray()) }
            val plain = cipher.doFinal(Base64.getUrlDecoder().decode(env.getString("ciphertext")) + Base64.getUrlDecoder().decode(env.getString("tag")))
            assertEquals("dummy-Password-For-Test-Only-42!", String(plain, Charsets.UTF_16LE)); plain.fill(0)
        } finally { key.fill(0) }
    }
}
