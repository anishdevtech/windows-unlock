package dev.windowsunlock.phone

import android.graphics.BitmapFactory
import android.os.Build
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
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var offer by remember { mutableStateOf<JSONObject?>(null) }
    var offerJws by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Checking laptop availability…") }
    var confirmation by remember { mutableStateOf<String?>(null) }
    var sending by remember { mutableStateOf(false) }
    var camera by remember { mutableStateOf<CameraSession?>(null) }
    var image by remember { mutableStateOf<ImageBitmap?>(null) }
    var cameraJob by remember { mutableStateOf<Job?>(null) }
    fun stopLocal() { cameraJob?.cancel(); cameraJob = null; camera?.close(); camera = null; image = null }
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
                    } catch (_: Exception) { offer = null }
                    delay(3000)
                }
            } finally { stopLocal() }
        }
    }
    fun execute(action: String) {
        try {
            val o = offer ?: error("Laptop unavailable"); Protocol.lifetime(o, 60)
            val id = UUID.randomUUID().toString()
            val viewer = if (action == "camera-start") CameraSession(id) else null
            val p = Protocol.message("remote-command").put("commandId", id).put("offerId", o.getString("offerId"))
                .put("windowsDeviceId", windowsId).put("androidDeviceId", config.getString("androidDeviceId")).put("pairingId", config.getString("pairingId"))
                .put("offerHash", Protocol.hash(offerJws)).put("action", action).put("viewerJwk", viewer?.publicKey ?: JSONObject.NULL)
            val input = Protocol.input(p); sending = true
            // Camera key remains in Keystore; this command authorizes its public recipient.
            camera = viewer ?: camera
            authenticate(Keys.signature(config.getString("approvalAlias")), "$action on your laptop", { signature ->
                Protocol.lifetime(o, 60); val jws = Protocol.sign(input, signature)
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) { relay.call("POST", "/v1/remote/commands", JSONObject().put("commandJws", jws)) }
                        offer = null; status = "Command sent. Waiting for laptop verification…"
                        if (action == "camera-stop") stopLocal()
                        var accepted = false
                        repeat(15) {
                            if (!accepted) {
                                delay(1000)
                                val r = withContext(Dispatchers.IO) { relay.call("GET", "/v1/remote/commands/$id") }
                                if (!r.isNull("resultJws")) {
                                    val result = Protocol.verify(r.getString("resultJws"), config.getJSONObject("windowsJwk"), "remote-result")
                                    require(result.length() == 7 && result.getString("commandId") == id && result.getString("commandHash") == Protocol.hash(jws))
                                    check(result.getString("result") == "accepted")
                                    accepted = true; status = "Laptop accepted: $action"
                                }
                            }
                        }
                        check(accepted) { "No verified laptop receipt" }
                        if (viewer != null) {
                            cameraJob = scope.launch {
                                val end = android.os.SystemClock.elapsedRealtime() + 60000
                                try {
                                    while (isActive && android.os.SystemClock.elapsedRealtime() < end) {
                                        val frame = withContext(Dispatchers.IO) { relay.call("GET", "/v1/camera/$id/frame") }
                                        if (frame.has("sequence") && frame.getLong("sequence") > viewer.lastSequence) {
                                            val jpeg = withContext(Dispatchers.IO) { viewer.decrypt(frame) }
                                            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }; BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size, bounds)
                                            require(bounds.outWidth == 320 && bounds.outHeight == 240)
                                            image = BitmapFactory.decodeByteArray(jpeg, 0, jpeg.size)?.asImageBitmap()
                                        }
                                        delay(500)
                                    }
                                } catch (_: Exception) { status = "Camera ended, connection lost or frame rejected." }
                                finally { viewer.close(); camera = null; image = null }
                            }
                        }
                    } catch (_: Exception) { viewer?.close(); if (camera === viewer) camera = null; status = "Command unavailable, expired or rejected by laptop." }
                    finally { sending = false }
                }
            }, { viewer?.close(); if (camera === viewer) camera = null; sending = false; status = "Authentication cancelled. No command sent." })
        } catch (_: Exception) { stopLocal(); sending = false; status = "Laptop unavailable or secure camera key unsupported." }
    }
    Card { Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Laptop controls", style = MaterialTheme.typography.titleLarge)
        Text(if (offer == null) "Laptop offline or controls unavailable" else "Laptop online • permissions set on Windows")
        Text(status)
        val allowed = offer?.getJSONArray("actions")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            for (action in listOf("lock", "sleep")) OutlinedButton(onClick = { confirmation = action }, enabled = action in allowed && !blocked && !sending) { Text(action.replaceFirstChar { it.uppercase() }) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            for (action in listOf("shutdown", "restart")) OutlinedButton(onClick = { confirmation = action }, enabled = action in allowed && !blocked && !sending) { Text(if (action == "shutdown") "Shut down" else "Restart") }
        }
        Button(onClick = { confirmation = "camera-start" }, enabled = Build.VERSION.SDK_INT >= 35 && "camera-start" in allowed && !blocked && !sending && camera == null) { Text("View live webcam") }
        image?.let { Image(it, "Encrypted live laptop camera view", Modifier.fillMaxWidth().height(220.dp)) }
        if (camera != null) OutlinedButton(onClick = { stopLocal(); if ("camera-stop" in allowed && !blocked && !sending) execute("camera-stop") }, enabled = !blocked) { Text("Stop camera") }
        Text("Live preview: 320×240, up to 2 frames/sec, 60 seconds. Closing the app stops viewing; the laptop also expires the session. Sleep/off stops remote connectivity.", style = MaterialTheme.typography.bodySmall)
    } }
    confirmation?.let { action -> AlertDialog(onDismissRequest = { confirmation = null }, title = { Text("Confirm $action") },
        text = { Text(if (action == "camera-start") "View your laptop camera for up to 60 seconds? Windows must be unlocked with its camera-sharing window visible." else "Send $action to your laptop? Sleep, shutdown and restart interrupt running work. System authentication is required.") },
        confirmButton = { TextButton(onClick = { confirmation = null; execute(action) }) { Text("Authenticate & continue") } },
        dismissButton = { TextButton(onClick = { confirmation = null }) { Text("Cancel") } }) }
}
