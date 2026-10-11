package dev.windowsunlock.phone

import android.Manifest
import android.app.*
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.media.*
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class AudioStreamService : Service() {
    data class Session(val mode: String, val link: MediaLink, val consent: Intent? = null)
    companion object {
        private var pending: Session? = null
        private val mutableStatus = MutableStateFlow("")
        val status = mutableStatus.asStateFlow()
        @Synchronized fun stage(session: Session) { pending?.link?.close(); pending = session }
        @Synchronized private fun take(): Session? = pending.also { pending = null }
        fun stop(context: android.content.Context) { context.stopService(Intent(context, AudioStreamService::class.java)) }
    }
    private val stopped = AtomicBoolean(false)
    private val executor = Executors.newFixedThreadPool(2)
    private var session: Session? = null
    private var projection: MediaProjection? = null
    private var recorder: AudioRecord? = null
    private var player: AudioTrack? = null
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "stop") { stopSelf(); return START_NOT_STICKY }
        if (session != null) return START_NOT_STICKY
        val selected = take() ?: run { stopSelf(); return START_NOT_STICKY }
        session = selected
        try {
            val capture = selected.mode == "audio-speaker-start"
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel("audio_sharing", "Audio sharing", NotificationManager.IMPORTANCE_LOW))
            val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val stop = PendingIntent.getService(this, 1, Intent(this, AudioStreamService::class.java).setAction("stop"), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val text = if (capture) "Phone audio → laptop speakers" else "Listening to laptop microphone"
            val notification = NotificationCompat.Builder(this, "audio_sharing").setSmallIcon(R.drawable.ic_notification).setContentTitle(text)
                .setContentText("Encrypted Wi-Fi audio · tap Stop to end").setOngoing(true).setContentIntent(open).addAction(0, "Stop", stop).build()
            startForeground(731, notification, if (capture) ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION else ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK)
            mutableStatus.value = "Connecting encrypted Wi-Fi audio…"
            if (capture) {
                check(ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED)
                projection = getSystemService(MediaProjectionManager::class.java).getMediaProjection(Activity.RESULT_OK, requireNotNull(selected.consent))
                projection!!.registerCallback(object : MediaProjection.Callback() { override fun onStop() { stopSelf() } }, Handler(Looper.getMainLooper()))
            }
            executor.execute {
                try {
                    check(selected.link.connect()) { "Use the same Wi-Fi and allow private-network access on Windows" }
                    if (capture) startCapture() else startPlayback()
                    mutableStatus.value = "$text · connected"
                    if (capture) executor.execute {
                        try { val bytes = ByteArray(3840); while (!stopped.get()) {
                            var offset = 0
                            while (offset < bytes.size && !stopped.get()) { val n = recorder?.read(bytes, offset, bytes.size - offset, AudioRecord.READ_BLOCKING) ?: break; check(n > 0); offset += n }
                            if (offset == bytes.size) selected.link.send(2, bytes)
                        } } catch (_: Exception) { if (!stopped.get()) fail("Phone audio capture ended") }
                    }
                    while (!stopped.get()) {
                        val packet = selected.link.receive() ?: continue
                        if (!capture && packet.first == 2 && packet.second.size == 640) player?.write(packet.second, 0, packet.second.size, AudioTrack.WRITE_NON_BLOCKING)
                    }
                } catch (e: Exception) { if (!stopped.get()) fail(if (e is IllegalStateException) e.message ?: "Audio ended" else "Audio ended. Check Wi-Fi and audio permissions.") }
            }
        } catch (_: Exception) { fail("Audio permission or capture consent unavailable. Start again from the app.") }
        return START_NOT_STICKY
    }
    @Synchronized private fun startCapture() {
        check(!stopped.get())
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) error("Audio capture permission removed")
        val format = AudioFormat.Builder().setEncoding(AudioFormat.ENCODING_PCM_16BIT).setSampleRate(48000).setChannelMask(AudioFormat.CHANNEL_IN_STEREO).build()
        val capture = AudioPlaybackCaptureConfiguration.Builder(requireNotNull(projection)).addMatchingUsage(AudioAttributes.USAGE_MEDIA).addMatchingUsage(AudioAttributes.USAGE_GAME).addMatchingUsage(AudioAttributes.USAGE_UNKNOWN).excludeUid(android.os.Process.myUid()).build()
        val audio = AudioRecord.Builder().setAudioFormat(format).setBufferSizeInBytes(maxOf(15360, AudioRecord.getMinBufferSize(48000, AudioFormat.CHANNEL_IN_STEREO, AudioFormat.ENCODING_PCM_16BIT))).setAudioPlaybackCaptureConfig(capture).build()
        check(audio.state == AudioRecord.STATE_INITIALIZED)
        recorder = audio; audio.startRecording()
    }
    @Synchronized private fun startPlayback() {
        check(!stopped.get())
        val audio = AudioTrack.Builder().setAudioAttributes(AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA).setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build())
            .setAudioFormat(AudioFormat.Builder().setEncoding(AudioFormat.ENCODING_PCM_16BIT).setSampleRate(16000).setChannelMask(AudioFormat.CHANNEL_OUT_MONO).build())
            .setTransferMode(AudioTrack.MODE_STREAM).setBufferSizeInBytes(maxOf(2560, AudioTrack.getMinBufferSize(16000, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT))).build()
        check(audio.state == AudioTrack.STATE_INITIALIZED); player = audio; audio.play()
    }
    private fun fail(message: String) { mutableStatus.value = message; stopSelf() }
    @Synchronized override fun onDestroy() {
        stopped.set(true)
        try { recorder?.stop() } catch (_: Exception) { }
        try { player?.stop() } catch (_: Exception) { }
        session?.let { it.link.close(); MediaStopWorker.request(this,it.link.id) }; recorder?.release(); player?.release(); projection?.stop(); executor.shutdownNow()
        if (mutableStatus.value.endsWith("connected") || mutableStatus.value.startsWith("Connecting")) mutableStatus.value = "Audio sharing stopped"
        session = null; super.onDestroy()
    }
}
