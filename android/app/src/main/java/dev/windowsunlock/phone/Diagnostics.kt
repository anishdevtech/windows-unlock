package dev.windowsunlock.phone

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.*
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date

@Composable
fun Diagnostics(config: JSONObject) {
    val scope = rememberCoroutineScope()
    var lines by remember { mutableStateOf(listOf<String>()) }
    var loading by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Laptop application events • 7-day server retention") }
    Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Activity & diagnostics", style = MaterialTheme.typography.titleLarge)
        Text(status, style = MaterialTheme.typography.bodySmall)
        lines.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        OutlinedButton(onClick = { scope.launch {
            loading = true
            try {
                val result = withContext(Dispatchers.IO) { Relay(config, config.getString("transportToken")).call("GET", "/v1/diagnostics") }
                val entries = result.getJSONArray("entries")
                lines = (0 until minOf(entries.length(), 8)).map { index ->
                    val e = entries.getJSONObject(index)
                    val label = when (e.getString("code")) {
                        "app_started" -> "Companion started"
                        "app_stopped" -> "Companion stopped"
                        "native_unavailable" -> "Native sign-in unavailable — use Windows PIN"
                        "native_ready" -> "Native service running"
                        "request_sent" -> "Approval request sent"
                        "push_sent" -> "Firebase accepted notification"
                        "push_failed" -> "Push delivery failed"
                        "push_missing" -> "Push token or Firebase missing"
                        "approval_verified" -> "Phone signature verified"
                        "credential_submitted" -> "Phone credential submitted to Windows"
                        "windows_signin_failed" -> "Windows rejected sign-in - refresh password enrollment"
                        "windows_result_success" -> "Windows reported successful sign-in"
                        "approval_denied" -> "Request denied"
                        "approval_expired" -> "Request expired"
                        "approval_failed" -> "Approval failed or cancelled"
                        "camera_started" -> "Camera sharing started"
                        "camera_stopped" -> "Camera sharing stopped"
                        "camera_failed" -> "Camera unavailable — check Windows camera privacy"
                        "remote_received" -> "Laptop verified remote command"
                        "remote_failed" -> "Remote action failed"
                        "session_locked" -> "Windows session locked"
                        "session_unlocked" -> "Windows session unlocked"
                        "relay_ready" -> "Relay connection verified"
                        "relay_unavailable", "network_retry" -> "Relay connection failed"
                        else -> "Application event"
                    }
                    val time = DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(e.getLong("timestamp") * 1000))
                    val duration = if (e.isNull("durationMs")) "" else " • ${e.getLong("durationMs")} ms"
                    "$time  $label$duration"
                }
                status = if (lines.isEmpty()) "No uploaded events. Enable diagnostics on the laptop; batches upload every 15 seconds." else "Latest laptop events • excludes credentials and camera frames"
            } catch (e: CancellationException) { throw e }
              catch (_: Exception) { status = "Diagnostics unavailable. Check the server connection and migration 003." }
            finally { loading = false }
        } }, enabled = !loading) { Text(if (loading) "Loading…" else "Refresh activity") }
    } }
}
