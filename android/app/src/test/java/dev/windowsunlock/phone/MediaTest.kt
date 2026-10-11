package dev.windowsunlock.phone

import org.junit.Assert.*
import org.junit.Test
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.Curve

class MediaTest {
    @Test fun signedDescriptorBindsSessionKeysEndpointsAndRecipient() {
        val ec=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val jwk=JSONObject(ECKey.Builder(Curve.P_256,ec.public as ECPublicKey).build().toJSONString())
        fun sign(p:JSONObject)=Protocol.sign(Protocol.input(p),Signature.getInstance("SHA256withECDSA").apply{initSign(ec.private)})
        val config=JSONObject().put("windowsJwk",jwk).put("androidDeviceId","phone").put("pairingId","pair")
            .put("invitationJws",sign(Protocol.message("pair-invitation").put("windowsDeviceId","windows")))
        val wrapped=Protocol.b64(ByteArray(256){it.toByte()});val now=System.currentTimeMillis()/1000
        val descriptor=Protocol.message("media-descriptor").put("mediaId","session").put("nonce",Protocol.b64(ByteArray(32)))
            .put("commandHash","command").put("windowsDeviceId","windows").put("androidDeviceId","phone").put("pairingId","pair")
            .put("action","camera-start").put("keyHash",Protocol.hash(wrapped)).put("issuedAt",now).put("expiresAt",now+59)
            .put("transport",JSONObject().put("protocol","udp-aesgcm-v1").put("addresses",org.json.JSONArray().put("192.168.1.2")).put("port",50123).put("sampleRate",16000).put("channels",1).put("packetMs",20).put("maxFps",15))
        val response=JSONObject().put("descriptorJws",sign(descriptor)).put("wrappedKey",wrapped)
        assertEquals("session",MediaDescriptor.verify(response,config,"session","command","camera-start").getString("mediaId"))
        for((field,value) in listOf("commandHash" to "other","androidDeviceId" to "other","pairingId" to "other","keyHash" to "bad","expiresAt" to now+1000)){
            val bad=JSONObject(response.toString()).put("descriptorJws",sign(JSONObject(descriptor.toString()).put(field,value)))
            try{MediaDescriptor.verify(bad,config,"session","command","camera-start");fail("Descriptor substitution accepted")}catch(_:IllegalArgumentException){}
        }
    }
    @Test fun boundedReassemblyHandlesLossReorderingAndReplay() {
        val bytes=ByteArray(44000){(it%251).toByte()};val fragments=MediaWire.fragments(10,bytes);val assembly=MediaWire.Assembler()
        var result: Pair<Long,ByteArray>?=null
        for(packet in fragments.reversed())result=assembly.accept(packet,0,0)?:result
        assertEquals(10L,result!!.first);assertArrayEquals(bytes,result.second)
        assertNull(assembly.accept(fragments[0],10,10))
        assertNull(assembly.accept(ByteArray(1200),0,10))
        val lost=MediaWire.Assembler();fragments.dropLast(1).forEach{assertNull(lost.accept(it,0,0))}
        assertNull(lost.accept(fragments.last(),0,250))
        val bad=fragments[0].copyOf();bad[14]=127;assertNull(assembly.accept(bad,0,0))
    }
    @Test fun packetsRejectTamperingDirectionAndSequence() {
        val master=ByteArray(32){it.toByte()};val up=MediaWire.key(master,"up");val down=MediaWire.key(master,"down")
        assertFalse(up.contentEquals(down));val payload=byteArrayOf(2)+ByteArray(3840)
        val packet=MediaWire.encrypt(up,"session:up",1,payload)
        assertArrayEquals(payload,MediaWire.decrypt(up,"session:up",1,packet))
        for((key,session,seq) in listOf(Triple(down,"session:up",1L),Triple(up,"session:down",1L),Triple(up,"session:up",2L))){try{MediaWire.decrypt(key,session,seq,packet);fail("Packet accepted with wrong binding")}catch(_:Exception){}}
    }
    @Test fun privateEndpointsAndUpdateSourcesAreRestricted() {
        for(ip in listOf("10.0.0.1","172.16.0.1","172.31.255.254","192.168.1.1"))assertTrue(MediaDescriptor.privateAddress(ip))
        for(ip in listOf("127.0.0.1","169.254.1.1","8.8.8.8","172.32.0.1","192.168.1.999","localhost","192.168.1.1/path"))assertFalse(MediaDescriptor.privateAddress(ip))
        val release=JSONObject().put("packageName","dev.windowsunlock.phone").put("versionCode",8).put("versionName","0.7.0").put("url","https://github.com/anishdevtech/windows-unlock/releases/download/v0.7.0/WINDOWS-UNLOCK-0.7.0-debug.apk").put("sha256","a".repeat(64)).put("size",1000)
        assertEquals(8L,AppRelease.parse(release).versionCode)
        for((field,value) in listOf("packageName" to "other.app","url" to "https://evil.example/app.apk","size" to 104857601,"sha256" to "invalid","versionCode" to 0)){
            try{AppRelease.parse(JSONObject(release.toString()).put(field,value));fail("Invalid update metadata accepted")}catch(_:IllegalArgumentException){}
        }
    }
    @Test fun javaAndWindowsMediaPacketsInteroperate() {
        val output=System.getProperty("phoneunlock.fixtureOutput")?:return
        val root=java.io.File(output).parentFile?.parentFile ?: return
        val exe=root.resolve("build/windows-media/Release/core_tests.exe")
        org.junit.Assume.assumeTrue(exe.isFile)
        val ec=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val jwk=JSONObject(ECKey.Builder(Curve.P_256,ec.public as ECPublicKey).build().toJSONString())
        val sig=Signature.getInstance("SHA256withECDSA").apply{initSign(ec.private)}
        val master=ByteArray(32){it.toByte()};val packet=MediaWire.encrypt(MediaWire.key(master,"up"),"interop:up",1,byteArrayOf(2,1,2,3))
        val file=java.io.File("$output.media.json");file.writeText(JSONObject().put("jwk",jwk).put("token",Protocol.sign(Protocol.input(Protocol.message("auth-response")),sig)).put("mediaMaster",Protocol.b64(master)).put("mediaUp",JSONObject(String(packet))).toString())
        val process=ProcessBuilder(exe.absolutePath,"--interop",file.absolutePath).redirectErrorStream(true).start()
        check(process.waitFor(20,java.util.concurrent.TimeUnit.SECONDS));assertEquals(0,process.exitValue())
        val down=JSONObject(java.io.File(file.absolutePath+".windows.json").readText()).getJSONObject("mediaDown");down.remove("wrappedKey")
        assertArrayEquals(byteArrayOf(2,4,5,6),MediaWire.decrypt(MediaWire.key(master,"down"),"interop:down",2,down.toString().toByteArray()))
    }
}
