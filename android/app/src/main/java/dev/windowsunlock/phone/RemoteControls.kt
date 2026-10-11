package dev.windowsunlock.phone

import android.graphics.BitmapFactory
import android.os.Build
import android.content.Intent
import android.content.Context
import android.media.projection.MediaProjectionManager
import android.app.Activity
import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.*
import org.json.JSONObject
import java.security.Signature
import java.util.UUID

@Composable
fun RemoteControls(config: JSONObject, blocked: Boolean, authenticate: (Signature, String, (Signature) -> Unit, () -> Unit) -> Unit) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val audioStatus by AudioStreamService.status.collectAsState()
    val audioActive = audioStatus.endsWith("connected") || audioStatus.startsWith("Connecting")
    var projectionConsent by remember { mutableStateOf<Intent?>(null) }
    var directLink by remember { mutableStateOf<MediaLink?>(null) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var offer by remember { mutableStateOf<JSONObject?>(null) }
    var offerJws by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Checking laptop availability…") }
    var confirmation by remember { mutableStateOf<String?>(null) }
    var sending by remember { mutableStateOf(false) }
    var camera by remember { mutableStateOf<CameraSession?>(null) }
    var image by remember { mutableStateOf<ImageBitmap?>(null) }
    var cameraJob by remember { mutableStateOf<Job?>(null) }
    fun stopLocal() { camera?.let { MediaStopWorker.request(context,it.id) }; directLink?.close(); directLink = null; cameraJob?.cancel(); cameraJob = null; camera?.close(); camera = null; image = null }
    DisposableEffect(Unit) { onDispose { stopLocal() } }
    val relay = remember(config) { Relay(config, config.getString("transportToken")) }
    val windowsId = remember(config) { Protocol.decode(config.getString("invitationJws")).getString("windowsDeviceId") }
    LaunchedEffect(config, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            try {
                while (isActive) {
                    try {
                        val r = withContext(Dispatchers.IO) { relay.call("GET", "/v1/remote/offer") }
                        if (r.has("offerJws")) {
                            val token = r.getString("offerJws"); val p = Protocol.verify(token, config.getJSONObject("windowsJwk"), "remote-offer"); Protocol.lifetime(p, 60)
                            require(p.length() == 11 && p.getString("windowsDeviceId") == windowsId && p.getString("androidDeviceId") == config.getString("androidDeviceId") && p.getString("pairingId") == config.getString("pairingId"))
                            offer = p; offerJws = token
                        } else offer = null
                    } catch (e: CancellationException) { throw e } catch (_: Exception) { offer = null }
                    delay(1500)
                }
            } finally { stopLocal() }
        }
    }
    fun execute(action: String) {
        if (sending || blocked) return
        sending = true
        scope.launch {
        var candidate: CameraSession? = null
        try {
            val o = offer ?: error("Laptop unavailable"); Protocol.lifetime(o, 60)
            val id = UUID.randomUUID().toString()
            val viewer = if (action in listOf("camera-start", "audio-speaker-start", "audio-microphone-start")) withContext(Dispatchers.IO) { CameraSession(id, config, if (action == "camera-start") 60000 else 600000) } else null
            candidate = viewer
            if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) { viewer?.close(); sending = false; return@launch }
            val p = Protocol.message("remote-command").put("commandId", id).put("offerId", o.getString("offerId"))
                .put("windowsDeviceId", windowsId).put("androidDeviceId", config.getString("androidDeviceId")).put("pairingId", config.getString("pairingId"))
                .put("offerHash", Protocol.hash(offerJws)).put("action", action).put("viewerJwk", viewer?.publicKey ?: JSONObject.NULL)
            val input = Protocol.input(p); sending = true
            // Camera key remains in Keystore; this command authorizes its public recipient.
            if (action == "camera-start") camera = viewer ?: camera
            authenticate(Keys.signature(config.getString("approvalAlias")), "$action on your laptop", { signature ->
                Protocol.lifetime(o, 60); val jws = Protocol.sign(input, signature); viewer?.bind(Protocol.hash(jws))
                scope.launch {
                    var preparedLink: MediaLink? = null
                    try {
                        withContext(Dispatchers.IO) { relay.call("POST", "/v1/remote/commands", JSONObject().put("commandJws", jws)) }
                        offer = null; status = "Command sent. Waiting for laptop verification…"
                        if (action == "camera-stop" || action == "media-stop") { stopLocal(); AudioStreamService.stop(context) }
                        var accepted = false
                        repeat(15) {
                            if (!accepted) {
                                val r = withContext(Dispatchers.IO) { relay.call("GET", "/v1/remote/commands/$id") }
                                if (!r.isNull("resultJws")) {
                                    val result = Protocol.verify(r.getString("resultJws"), config.getJSONObject("windowsJwk"), "remote-result")
                                    require(result.length() == 7 && result.getString("commandId") == id && result.getString("commandHash") == Protocol.hash(jws))
                                    check(result.getString("result") == "accepted")
                                    accepted = true; status = "Laptop accepted: $action"
                                }
                                if (!accepted) delay(500)
                            }
                        }
                        check(accepted) { "No verified laptop receipt" }
                        if (viewer != null) {
                            val response = withContext(Dispatchers.IO) { relay.call("GET", "/v1/media/$id") }
                            val link = if (response.has("descriptorJws")) withContext(Dispatchers.IO) { viewer.media(response, action) } else null
                            preparedLink = link
                            check(lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) { "Return to the app to start media" }
                            if (action.startsWith("audio-")) {
                                check(link != null) { "Update the Windows companion for audio sharing" }
                                check(!audioActive) { "Stop the current audio session first" }
                                AudioStreamService.stage(AudioStreamService.Session(action, link, if (action == "audio-speaker-start") projectionConsent else null))
                                ContextCompat.startForegroundService(context, Intent(context, AudioStreamService::class.java))
                                viewer.close(); projectionConsent = null
                                status = "Audio sharing starts in the notification. You can use other apps."
                            } else {
                                directLink = link
                                cameraJob = scope.launch {
                                    val end = android.os.SystemClock.elapsedRealtime() + 60000
                                    try {
                                        val direct = link != null && withContext(Dispatchers.IO) { link.connect() }
                                        if (!direct) { link?.abandon(); directLink = null }
                                        status = if (direct) "Direct encrypted Wi-Fi video · up to 15 fps" else "Relay preview · connect to the same Wi-Fi for faster video"
                                        while (isActive && android.os.SystemClock.elapsedRealtime() < end) {
                                            val jpeg = withContext(Dispatchers.IO) {
                                                if (direct) { val packet = link!!.receive(); if (packet?.first == 1) packet.second else null }
                                                else { val frame = relay.call("GET", "/v1/camera/$id/frame?after=${viewer.lastSequence}"); if (frame.has("sequence") && frame.getLong("sequence") > viewer.lastSequence) viewer.decrypt(frame) else null }
                                            }
                                            if (jpeg != null) image = withContext(Dispatchers.Default) {
                                                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }; BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, bounds)
                                                require(bounds.outWidth in 1..640 && bounds.outHeight in 1..480)
                                                BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size)?.asImageBitmap()
                                            }
                                            if (!direct) delay(120)
                                        }
                                    } catch (e: CancellationException) { throw e } catch (_: Exception) { status = "Camera ended or Wi-Fi disconnected. Tap View live webcam to reconnect." }
                                    finally { link?.close(); MediaStopWorker.request(context,id); viewer.close(); if (camera === viewer) { camera = null; directLink = null; image = null } }
                                }
                            }
                        }
                    } catch (e: CancellationException) { preparedLink?.close(); viewer?.close(); throw e } catch (_: Exception) { preparedLink?.close(); viewer?.close(); if (camera === viewer) camera = null; status = "Command unavailable, expired or rejected by laptop." }
                    finally { sending = false }
                }
            }, { viewer?.close(); if (camera === viewer) camera = null; sending = false; status = "Authentication cancelled. No command sent." })
        } catch (e: CancellationException) { candidate?.close(); sending = false; throw e }
          catch (_: Exception) { candidate?.close(); stopLocal(); sending = false; status = "Laptop unavailable or secure camera key unsupported." }
        }
    }
    Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Control your laptop", style = MaterialTheme.typography.titleLarge)
        Text(if (offer == null) "Laptop offline or controls unavailable" else "Laptop online • permissions set on Windows")
        Text(status)
        val allowed = offer?.getJSONArray("actions")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            for (action in listOf("lock", "sleep")) OutlinedButton(modifier = Modifier.weight(1f), onClick = { confirmation = action }, enabled = action in allowed && !blocked && !sending) { Text(action.replaceFirstChar { it.uppercase() }) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            for (action in listOf("shutdown", "restart")) OutlinedButton(modifier = Modifier.weight(1f), onClick = { confirmation = action }, enabled = action in allowed && !blocked && !sending) { Text(if (action == "shutdown") "Shut down" else "Restart") }
        }
        Button(modifier = Modifier.fillMaxWidth(), onClick = { confirmation = "camera-start" }, enabled = Build.VERSION.SDK_INT >= 35 && "camera-start" in allowed && !blocked && !sending && camera == null && !audioActive) { Text("View live webcam") }
        if (offer != null && "camera-start" !in allowed) Text("Camera unavailable: unlock Windows and enable camera sharing in the laptop companion. It can remain in the tray.", style = MaterialTheme.typography.bodySmall)
        image?.let { Image(it, "Encrypted live laptop camera view", Modifier.fillMaxWidth().height(220.dp)) }
        if (camera != null) OutlinedButton(onClick = { stopLocal(); if ("camera-stop" in allowed && !blocked && !sending) execute("camera-stop") }, enabled = !blocked) { Text("Stop camera") }
        Text("Wi-Fi video: up to 640×480 / 15 fps. Relay fallback: 320×240 / up to 5 fps. Sessions last 60 seconds; closing this view stops the camera.", style = MaterialTheme.typography.bodySmall)
        HorizontalDivider()
        Text("Audio bridge", style = MaterialTheme.typography.titleMedium)
        PhoneAudioButton(enabled = Build.VERSION.SDK_INT >= 35 && "audio-speaker-start" in allowed && !blocked && !sending && camera == null && !audioActive,
            onConsent = { projectionConsent = it; execute("audio-speaker-start") }, onError = { status = it })
        OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = { confirmation = "audio-microphone-start" }, enabled = Build.VERSION.SDK_INT >= 35 && "audio-microphone-start" in allowed && !blocked && !sending && camera == null && !audioActive) { Text("Listen to laptop microphone") }
        if (audioStatus.isNotBlank()) Text(audioStatus, style = MaterialTheme.typography.bodyMedium)
        OutlinedButton(onClick = { AudioStreamService.stop(context); if ("media-stop" in allowed && !blocked && !sending) execute("media-stop") }) { Text("Stop audio sharing") }
        Text("Enable speaker or microphone sharing in Windows first. Audio needs the same private Wi-Fi and stops after 10 minutes, on laptop lock, or from the Stop notification. Some phone apps prohibit audio capture.", style = MaterialTheme.typography.bodySmall)
    } }
    confirmation?.let { action -> AlertDialog(onDismissRequest = { confirmation = null }, title = { Text("Confirm $action") },
        text = { Text(if (action == "camera-start") "View your laptop camera for up to 60 seconds? Windows must be unlocked. A visible sharing indicator appears on your laptop before capture." else if (action == "audio-microphone-start") "Listen to your laptop microphone over encrypted Wi-Fi for up to 10 minutes? A visible sharing window appears on the unlocked laptop. You can stop from either device." else "Send $action to your laptop? Sleep, shutdown and restart interrupt running work. System authentication is required.") },
        confirmButton = { TextButton(onClick = { confirmation = null; execute(action) }) { Text("Authenticate & continue") } },
        dismissButton = { TextButton(onClick = { confirmation = null }) { Text("Cancel") } }) }
}

@Composable
private fun PhoneAudioButton(enabled: Boolean, onConsent: (Intent) -> Unit, onError: (String) -> Unit) {
    val context = LocalContext.current
    var explain by remember { mutableStateOf(false) }
    val projection = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK && result.data != null) onConsent(result.data!!)
        else onError("Audio sharing cancelled. No phone audio captured.")
    }
    fun consent() { projection.launch(context.getSystemService(MediaProjectionManager::class.java).createScreenCaptureIntent()) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) consent() else onError("Audio capture permission denied. Allow it to share phone audio.")
    }
    Button(onClick = { explain = true }, enabled = enabled, modifier = Modifier.fillMaxWidth()) { Text("Play phone audio on laptop") }
    if (explain) AlertDialog(onDismissRequest = { explain = false }, title = { Text("Share phone audio") },
        text = { Text("Android will ask for audio/capture permission. Choose the entire screen to share audio across apps. Only audio is transmitted; screen images are never captured. Apps can block capture. Start music after the audio notification says connected.") },
        confirmButton = { TextButton(onClick = { explain = false; if (ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) consent() else permission.launch(Manifest.permission.RECORD_AUDIO) }) { Text("Continue") } },
        dismissButton = { TextButton(onClick = { explain = false }) { Text("Cancel") } })
}
