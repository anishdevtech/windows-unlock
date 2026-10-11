package dev.windowsunlock.phone

import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object MediaWire {
    const val CHUNK = 1100
    fun key(master: ByteArray, direction: String): ByteArray = MessageDigest.getInstance("SHA-256").digest("windows-unlock-media-v1:$direction:${Protocol.b64(master)}".toByteArray())
    fun encrypt(key: ByteArray, session: String, sequence: Long, payload: ByteArray): ByteArray {
        require(sequence > 0 && payload.size in 1..45000)
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            updateAAD("$session:$sequence".toByteArray())
        }
        return JSONObject().put("sequence", sequence).put("iv", Protocol.b64(iv)).put("ciphertext", Protocol.b64(cipher.doFinal(payload))).toString().toByteArray()
    }
    fun decrypt(key: ByteArray, session: String, sequence: Long, bytes: ByteArray): ByteArray {
        require(bytes.size <= 65536)
        val p = Protocol.strictJson(String(bytes, Charsets.UTF_8))
        require(p.length() == 3 && p.getLong("sequence") == sequence)
        val iv = java.util.Base64.getUrlDecoder().decode(p.getString("iv"))
        val data = java.util.Base64.getUrlDecoder().decode(p.getString("ciphertext"))
        require(iv.size == 12 && data.size in 17..45016)
        return CameraCrypto.decrypt(key, iv, data, session, sequence)
    }
    fun fragments(sequence: Long, message: ByteArray): List<ByteArray> {
        require(sequence > 0 && message.size in 1..65536)
        val count = (message.size + CHUNK - 1) / CHUNK
        return (0 until count).map { index ->
            ByteBuffer.allocate(16 + minOf(CHUNK, message.size - index * CHUNK)).put("WUM1".toByteArray())
                .putLong(sequence).putShort(index.toShort()).putShort(count.toShort())
                .put(message, index * CHUNK, minOf(CHUNK, message.size - index * CHUNK)).array()
        }
    }
    class Assembler {
        private data class Frame(val count: Int, val time: Long, val parts: MutableMap<Int, ByteArray> = mutableMapOf())
        private val frames = sortedMapOf<Long, Frame>()
        fun accept(packet: ByteArray, lastSequence: Long, now: Long): Pair<Long, ByteArray>? {
            if (packet.size !in 17..1116 || !packet.copyOfRange(0, 4).contentEquals("WUM1".toByteArray())) return null
            val b = ByteBuffer.wrap(packet); b.position(4)
            val seq = b.long; val index = b.short.toInt() and 65535; val count = b.short.toInt() and 65535
            if (seq <= lastSequence || count !in 1..60 || index >= count) return null
            frames.entries.removeAll { now - it.value.time > 200 || it.key <= lastSequence }
            if (!frames.containsKey(seq) && frames.size >= 4) frames.remove(frames.firstKey())
            val frame = frames.getOrPut(seq) { Frame(count, now) }
            if (frame.count != count) return null
            frame.parts[index] = packet.copyOfRange(16, packet.size)
            if (frame.parts.size != count) return null
            frames.remove(seq)
            val size = frame.parts.values.sumOf { it.size }
            if (size > 65536) return null
            val bytes = java.io.ByteArrayOutputStream(size)
            repeat(count) { bytes.write(frame.parts.getValue(it)) }
            return seq to bytes.toByteArray()
        }
    }
}

object MediaDescriptor {
    fun verify(response: JSONObject, config: JSONObject, id: String, commandHash: String, action: String): JSONObject {
        val p = Protocol.verify(response.getString("descriptorJws"), config.getJSONObject("windowsJwk"), "media-descriptor")
        Protocol.lifetime(p, if (action == "camera-start") 60 else 600)
        require(p.length() == 14 && p.getString("mediaId") == id && p.getString("commandHash") == commandHash && p.getString("action") == action &&
            p.getString("windowsDeviceId") == Protocol.decode(config.getString("invitationJws")).getString("windowsDeviceId") &&
            p.getString("androidDeviceId") == config.getString("androidDeviceId") && p.getString("pairingId") == config.getString("pairingId") &&
            p.getString("keyHash") == Protocol.hash(response.getString("wrappedKey")))
        val t = p.getJSONObject("transport")
        require(t.length() == 7 && t.getString("protocol") == "udp-aesgcm-v1" && t.getInt("port") in 1024..65535 && t.getInt("packetMs") == 20 && t.getInt("maxFps") == 15)
        require(t.getInt("sampleRate") == if (action == "audio-speaker-start") 48000 else 16000)
        require(t.getInt("channels") == if (action == "audio-speaker-start") 2 else 1)
        val addresses = t.getJSONArray("addresses"); require(addresses.length() <= 8)
        repeat(addresses.length()) { require(privateAddress(addresses.getString(it))) }
        return p
    }
    fun privateAddress(address: String): Boolean {
        if (!Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}").matches(address)) return false
        val n = address.split('.').map { it.toInt() }
        return n.all { it in 0..255 } && (n[0] == 10 || n[0] == 172 && n[1] in 16..31 || n[0] == 192 && n[1] == 168)
    }
}
