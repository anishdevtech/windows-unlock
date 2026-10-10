package dev.windowsunlock.phone

import org.json.JSONObject
import java.net.URI
import java.util.Base64

/** File imports and QR scans enter the same verification and consent flow. */
object PairingInvitation {
    fun parse(text: String): JSONObject {
        val bundle = Protocol.strictJson(text)
        require(bundle.keys().asSequence().toSet() == setOf("relayUrl", "tlsPin", "caPem", "windowsJwk", "invitationJws", "pairingToken"))
        val origin = URI(bundle.getString("relayUrl"))
        require(origin.scheme == "https" && !origin.host.isNullOrBlank() && origin.rawUserInfo == null && origin.rawQuery == null && origin.rawFragment == null && origin.path in listOf("", "/"))
        val token = bundle.getString("pairingToken")
        val bytes = Base64.getUrlDecoder().decode(token)
        require(bytes.size == 32 && Protocol.b64(bytes) == token)
        val pin = bundle.getString("tlsPin")
        require(pin == "system" || (pin.startsWith("sha256/") && Base64.getDecoder().decode(pin.removePrefix("sha256/")).size == 32))
        require(bundle.getString("caPem").length <= 16384)
        val invitation = Protocol.verify(bundle.getString("invitationJws"), bundle.getJSONObject("windowsJwk"), "pair-invitation")
        Protocol.lifetime(invitation, 300)
        require(invitation.length() == 9)
        val uuid = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        require(invitation.getString("sessionId").matches(uuid) && invitation.getString("windowsDeviceId").matches(uuid))
        require(invitation.getString("windowsName").length in 1..80)
        return bundle
    }
}
