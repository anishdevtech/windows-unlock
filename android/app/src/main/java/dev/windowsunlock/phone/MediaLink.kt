package dev.windowsunlock.phone

import android.os.SystemClock
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean

class MediaLink(val id: String, descriptor: JSONObject, master: ByteArray) : AutoCloseable {
    private val up = MediaWire.key(master, "up")
    private val down = MediaWire.key(master, "down")
    private val socket = DatagramSocket().apply { soTimeout = 200; receiveBufferSize = 512 * 1024; sendBufferSize = 512 * 1024 }
    private val targets: List<InetSocketAddress>
    private var peer: InetSocketAddress? = null
    private var sent = 0L
    private var received = 0L
    private var lastPing = 0L
    private var lastPacket = SystemClock.elapsedRealtime()
    private val deadline = SystemClock.elapsedRealtime() + (descriptor.getLong("expiresAt") - System.currentTimeMillis() / 1000).coerceIn(0, 600) * 1000
    private val closed = AtomicBoolean(false)
    private val assembler = MediaWire.Assembler()
    init {
        master.fill(0)
        val t = descriptor.getJSONObject("transport"); val a = t.getJSONArray("addresses")
        targets = (0 until a.length()).map { InetSocketAddress(InetAddress.getByName(a.getString(it)), t.getInt("port")) }
    }
    @Synchronized fun send(type: Int, payload: ByteArray = byteArrayOf(), target: InetSocketAddress? = peer) {
        if (closed.get() || target == null) return
        val sequence = ++sent
        val bytes = MediaWire.encrypt(up, "$id:up", sequence, byteArrayOf(type.toByte()) + payload)
        for (fragment in MediaWire.fragments(sequence, bytes)) socket.send(DatagramPacket(fragment, fragment.size, target))
    }
    fun connect(): Boolean {
        val end = SystemClock.elapsedRealtime() + 3500
        while (!closed.get() && SystemClock.elapsedRealtime() < minOf(end, deadline)) {
            for (target in targets) send(0, target = target)
            val packet = receive(false)
            if (packet != null && packet.first == 4) return true
        }
        return false
    }
    fun receive(heartbeat: Boolean = true): Pair<Int, ByteArray>? {
        check(!closed.get() && SystemClock.elapsedRealtime() < deadline) { "Media session ended" }
        if (heartbeat && SystemClock.elapsedRealtime() - lastPing >= 500) { send(4); lastPing = SystemClock.elapsedRealtime() }
        val bytes = ByteArray(1200); val packet = DatagramPacket(bytes, bytes.size)
        try { socket.receive(packet) } catch (_: SocketTimeoutException) {
            check(!heartbeat || SystemClock.elapsedRealtime() - lastPacket < 3000) { "Wi-Fi connection lost" }
            return null
        }
        val source = InetSocketAddress(packet.address, packet.port)
        if (source !in targets || peer != null && peer != source) return null
        val completed = assembler.accept(bytes.copyOf(packet.length), received, SystemClock.elapsedRealtime()) ?: return null
        val plain = try { MediaWire.decrypt(down, "$id:down", completed.first, completed.second) } catch (_: Exception) { return null }
        if (plain.isEmpty()) return null
        if (peer == null && plain[0].toInt() != 4) return null
        peer = source; received = completed.first; lastPacket = SystemClock.elapsedRealtime()
        check(plain[0].toInt() != 3) { "Laptop stopped sharing" }
        return plain[0].toInt() to plain.copyOfRange(1, plain.size)
    }
    fun abandon() { close(false) }
    override fun close() { close(true) }
    @Synchronized private fun close(notify: Boolean) {
        if (closed.get()) return
        if (notify) try { send(3) } catch (_: Exception) { }
        closed.set(true); socket.close(); up.fill(0); down.fill(0)
    }
}
