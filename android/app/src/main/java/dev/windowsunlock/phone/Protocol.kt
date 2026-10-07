package dev.windowsunlock.phone

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.ECKey
import org.json.JSONObject
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64

object Protocol {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    fun b64(bytes: ByteArray): String = encoder.encodeToString(bytes)
    fun hash(text: String): String = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 255) }
    fun message(type: String, purpose: String = "desktop-approval"): JSONObject = JSONObject().put("v", 1).put("purpose", purpose).put("type", type)
    fun publicKey(j: JSONObject): ECKey {
        require(j.keys().asSequence().toSet() == setOf("kty", "crv", "x", "y"))
        require(j.getString("kty") == "EC" && j.getString("crv") == "P-256")
        for (part in listOf("x", "y")) require(decode64(j.getString(part)).size == 32)
        return ECKey.parse(j.toString())
    }
    private fun decode64(s: String): ByteArray {
        require(s.isNotEmpty() && s.matches(Regex("[A-Za-z0-9_-]+")))
        val bytes = Base64.getUrlDecoder().decode(s); require(b64(bytes) == s); return bytes
    }
    fun decode(token: String): JSONObject {
        require(token.length <= 65536); val parts = token.split('.'); require(parts.size == 3)
        val header = strictJson(String(decode64(parts[0]), Charsets.UTF_8))
        require(header.keys().asSequence().toSet() == setOf("alg", "typ"))
        require(header.getString("alg") == "ES256" && header.getString("typ") == "phoneunlock+jws")
        require(decode64(parts[2]).size == 64)
        return strictJson(String(decode64(parts[1]), Charsets.UTF_8))
    }
    fun verify(token: String, key: JSONObject, type: String): JSONObject {
        val p = decode(token); require(JWSObject.parse(token).verify(ECDSAVerifier(publicKey(key))))
        val purpose = p.getString("purpose")
        require(p.getInt("v") == 1 && (purpose == "desktop-approval" || (purpose == "windows-unlock" && type in setOf("auth-request", "auth-response")) || (purpose == "password-unlock" && VaultProtocol.allowed(type))) && p.getString("type") == type)
        return p
    }
    fun input(payload: JSONObject): String = b64("{\"alg\":\"ES256\",\"typ\":\"phoneunlock+jws\"}".toByteArray()) + "." + b64(payload.toString().toByteArray(Charsets.UTF_8))
    fun sign(input: String, signature: Signature): String {
        signature.update(input.toByteArray(Charsets.US_ASCII))
        return input + "." + b64(ECDSA.transcodeSignatureToConcat(signature.sign(), 64))
    }
    fun lifetime(p: JSONObject, max: Long) {
        val issued = p.getLong("issuedAt"); val expires = p.getLong("expiresAt"); val time = System.currentTimeMillis() / 1000
        require(expires > issued && expires - issued <= max && issued <= time + 30 && expires > time)
        require(decode64(p.getString("nonce")).size == 32)
    }
    // Scan keys before JSONObject can overwrite duplicates. JSONObject validates scalar syntax.
    fun strictJson(text: String): JSONObject {
        require(text.toByteArray(Charsets.UTF_8).size <= 65536)
        var i = 0
        fun ws() { while (i < text.length && text[i] in " \r\n\t") i++ }
        fun string(): String {
            require(i < text.length && text[i] == '"'); val start = i++
            while (i < text.length) {
                if (text[i] == '\\') { i += 2; continue }
                if (text[i++] == '"') return org.json.JSONTokener(text.substring(start, i)).nextValue() as String
            }
            error("Invalid JSON")
        }
        fun value(depth: Int) {
            require(depth <= 16); ws(); require(i < text.length)
            when (text[i]) {
                '"' -> { string() }
                '{' -> {
                    i++; ws(); val keys = mutableSetOf<String>()
                    if (i < text.length && text[i] == '}') { i++; return }
                    while (true) { ws(); require(keys.add(string())); ws(); require(i < text.length && text[i++] == ':'); value(depth + 1); ws()
                        require(i < text.length); if (text[i] == '}') { i++; break }; require(text[i++] == ',') }
                }
                '[' -> { i++; ws(); if (i < text.length && text[i] == ']') { i++; return }
                    while (true) { value(depth + 1); ws(); require(i < text.length); if (text[i] == ']') { i++; break }; require(text[i++] == ',') } }
                else -> { val start = i; while (i < text.length && text[i] !in " \t\r\n,]}") i++; require(i > start)
                    require(text.substring(start, i).matches(Regex("null|true|false|-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?"))) }
            }
        }
        value(0); ws(); require(i == text.length); return JSONObject(text)
    }
}
