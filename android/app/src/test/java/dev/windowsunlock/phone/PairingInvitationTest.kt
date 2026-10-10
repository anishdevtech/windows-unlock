package dev.windowsunlock.phone

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

class PairingInvitationTest {
    private fun invitation(expired: Boolean = false): JSONObject {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val now = System.currentTimeMillis() / 1000
        val payload = Protocol.message("pair-invitation").put("sessionId", UUID.randomUUID().toString()).put("windowsDeviceId", UUID.randomUUID().toString())
            .put("windowsName", "Test laptop").put("nonce", Protocol.b64(ByteArray(32) { 1 }))
            .put("issuedAt", if (expired) now - 301 else now).put("expiresAt", if (expired) now - 1 else now + 300)
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(key.private) }
        return JSONObject().put("relayUrl", "https://relay.example").put("tlsPin", "system").put("caPem", "")
            .put("windowsJwk", JSONObject(ECKey.Builder(Curve.P_256, key.public as ECPublicKey).build().toJSONString()))
            .put("invitationJws", Protocol.sign(Protocol.input(payload), signature)).put("pairingToken", Protocol.b64(ByteArray(32) { 2 }))
    }
    private fun rejected(text: String) { try { PairingInvitation.parse(text); fail("Untrusted pairing input accepted") } catch (_: Exception) { } }
    @Test fun compactQrAndFormattedFileUseTheSameInvitation() {
        val bundle = invitation()
        assertEquals(bundle.getString("invitationJws"), PairingInvitation.parse(bundle.toString()).getString("invitationJws"))
        assertEquals(bundle.getString("pairingToken"), PairingInvitation.parse(bundle.toString(2)).getString("pairingToken"))
    }
    @Test fun expiredOrSubstitutedSignatureCannotStartPairing() {
        rejected(invitation(true).toString())
        val original = invitation(); original.put("windowsJwk", invitation().getJSONObject("windowsJwk")); rejected(original.toString())
    }
    @Test fun scanRejectsOtherQrCodesAndUnsafeRelayOrigins() {
        rejected("https://example.com"); rejected("{\"a\":1,\"a\":2}")
        for (url in listOf("http://relay.example", "https://user:password@relay.example", "https://relay.example?token=private", "https://relay.example/path")) rejected(invitation().put("relayUrl", url).toString())
    }
    @Test fun invalidPairingTokenAndExtraFieldsAreRejected() {
        rejected(invitation().put("pairingToken", "wrong").toString())
        rejected(invitation().put("transportToken", "not-a-pairing-token").toString())
    }
}
