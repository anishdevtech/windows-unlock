package dev.windowsunlock.phone

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.json.JSONObject
import kotlinx.coroutines.delay

@Composable
fun UnlockDashboard(name: String, paired: Boolean, status: String, fingerprint: String,
    vault: JSONObject?, transport: JSONObject?, working: Boolean,
    approveVault: () -> Unit, denyVault: () -> Unit, approve: () -> Unit, deny: () -> Unit,
    controls: @Composable () -> Unit, settings: @Composable ColumnScope.() -> Unit) {
    var tab by remember { mutableIntStateOf(0) }
    val activeId = vault?.optString("requestId") ?: transport?.optString("requestId")
    LaunchedEffect(activeId) { if (activeId != null) tab = 0 }
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(Unit) { while (true) { delay(1000); now = System.currentTimeMillis() / 1000 } }
    Scaffold(containerColor = MaterialTheme.colorScheme.background, bottomBar = {
        NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
            listOf("Unlock", "Controls", "Settings").forEachIndexed { i, label ->
                NavigationBarItem(selected = tab == i, onClick = { tab = i },
                    icon = { TabGlyph(i) }, label = { Text(label) })
            }
        }
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).statusBarsPadding().padding(horizontal = 22.dp)) {
            Row(Modifier.fillMaxWidth().padding(top = 18.dp, bottom = 24.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("WINDOWS UNLOCK", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.secondary)
                    Text(listOf("Your secure key.", "Within reach.", "Make it yours.")[tab], style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold)
                }
                Box(Modifier.size(40.dp).background(MaterialTheme.colorScheme.primaryContainer, CircleShape), contentAlignment = Alignment.Center) { Text("W", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary) }
            }
            AnimatedContent(targetState = tab, transitionSpec = { (fadeIn(tween(220)) + slideInHorizontally(tween(260)) { it / 12 }) togetherWith fadeOut(tween(140)) }, label = "dashboard tab") { page ->
                Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(18.dp)) {
                    when (page) {
                        0 -> {
                            if (BuildConfig.ALLOW_SOFTWARE_KEYS) Text("TEST BUILD - Windows sign-in disabled", color = MaterialTheme.colorScheme.error)
                            DeviceHero(name, paired, activeId != null, working)
                            val r = vault ?: transport
                            AnimatedContent(targetState = activeId, transitionSpec = { (fadeIn(tween(220)) + expandVertically()) togetherWith fadeOut(tween(120)) }, label = "approval request") { id ->
                                if (id != null && r != null) {
                                    val enrollment = vault?.optString("type") == "vault-enroll"
                                    val test = vault == null && transport?.optString("purpose") != "windows-unlock"
                                    val remaining = (r.optLong("expiresAt") - now).coerceAtLeast(0)
                                    val duration = (r.optLong("expiresAt") - r.optLong("issuedAt")).coerceAtLeast(1)
                                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer), shape = RoundedCornerShape(28.dp)) {
                                        Column(Modifier.fillMaxWidth().padding(22.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                                            Text(if (enrollment) "ENABLE PHONE SIGN-IN" else if (test) "CONNECTION TEST" else "SIGN-IN REQUEST", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                                            Text(if (enrollment) "Connect your key" else if (test) "Test phone approval" else "Let yourself in.", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                                            Text(if (test) "This checks the connection. It will not sign in to Windows." else if (enrollment) "Enable phone approval for the encrypted password stored on your laptop. Continue only if you started setup." else "Review your laptop, then authenticate to release its sign-in key.")
                                            vault?.let { Text(Protocol.decode(it.getString("delegationJws")).getString("loginName"), style = MaterialTheme.typography.bodyMedium) }
                                            val progress by animateFloatAsState((remaining.toFloat() / duration).coerceIn(0f, 1f), tween(700), label = "expiry countdown")
                                            LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
                                            Text(if (remaining > 0) "$remaining seconds remaining" else "Request expired. Request again on Windows.", style = MaterialTheme.typography.labelMedium)
                                            Button(onClick = if (vault != null) approveVault else approve, enabled = remaining > 0 && !working, modifier = Modifier.fillMaxWidth().height(54.dp)) { Text(if (working) "Authenticating…" else if (enrollment) "Enable phone sign-in" else "Authenticate & approve") }
                                            OutlinedButton(onClick = if (vault != null) denyVault else deny, enabled = remaining > 0 && !working, modifier = Modifier.fillMaxWidth()) { Text("Deny request") }
                                        }
                                    }
                                } else {
                                    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(24.dp)) { Column(Modifier.padding(22.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Text(if (working) "Working securely…" else "All clear", style = MaterialTheme.typography.titleLarge)
                                        Text(if (paired) "A sign-in request will appear here when your laptop needs you." else "Pair your laptop in Settings to get started.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    } }
                                }
                            }
                            Surface(color = MaterialTheme.colorScheme.surface, shape = RoundedCornerShape(20.dp)) { Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("LATEST STATUS", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
                                Text(status, style = MaterialTheme.typography.bodyMedium)
                                if (fingerprint.isNotEmpty()) Text("Pairing code: $fingerprint", color = MaterialTheme.colorScheme.primary)
                                if (working) LinearProgressIndicator(Modifier.fillMaxWidth())
                            } }
                            Text("Your password stays on your laptop. Every approval uses Android system authentication.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        1 -> if (paired) controls() else Text("Pair your laptop in Settings to enable remote controls.")
                        2 -> settings()
                    }
                    Spacer(Modifier.height(20.dp))
                }
            }
        }
    }
}

@Composable
private fun TabGlyph(index: Int) {
    val ink = LocalContentColor.current
    Canvas(Modifier.size(24.dp)) {
        val unit = size.width / 24f
        val line = Stroke(1.8f * unit)
        when (index) {
            0 -> {
                drawArc(ink, 180f, 180f, false, Offset(7f * unit, 2f * unit), Size(10f * unit, 14f * unit), style = line)
                drawRoundRect(ink, Offset(4f * unit, 10f * unit), Size(16f * unit, 12f * unit), CornerRadius(3f * unit), style = line)
                drawCircle(ink, 1.6f * unit, Offset(12f * unit, 16f * unit))
            }
            1 -> for ((y, x) in listOf(6f to 8f, 12f to 16f, 18f to 10f)) {
                drawLine(ink, Offset(3f * unit, y * unit), Offset(21f * unit, y * unit), 1.8f * unit)
                drawCircle(MaterialThemePlaceholder, 3f * unit, Offset(x * unit, y * unit))
                drawCircle(ink, 3f * unit, Offset(x * unit, y * unit), style = line)
            }
            else -> {
                drawCircle(ink, 7f * unit, center, style = line)
                drawCircle(ink, 2.5f * unit, center, style = line)
                repeat(8) { step ->
                    val radians = step * Math.PI / 4
                    val dx = kotlin.math.cos(radians).toFloat(); val dy = kotlin.math.sin(radians).toFloat()
                    drawLine(ink, center + Offset(dx * 8f * unit, dy * 8f * unit), center + Offset(dx * 11f * unit, dy * 11f * unit), 2f * unit)
                }
            }
        }
    }
}

private val MaterialThemePlaceholder = Color(0xFF25322B)

@Composable
private fun DeviceHero(name: String, paired: Boolean, pending: Boolean, working: Boolean) {
    val color = MaterialTheme.colorScheme.primary
    val ring by animateFloatAsState(if (pending || working) 1f else .72f, spring(dampingRatio = Spring.DampingRatioNoBouncy), label = "device ring")
    Box(Modifier.fillMaxWidth().background(Brush.verticalGradient(listOf(Color(0xFF203D38), Color(0xFF14221F))), RoundedCornerShape(30.dp)).padding(24.dp)) {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Canvas(Modifier.size(130.dp)) {
                drawCircle(color.copy(alpha = .08f), radius = size.minDimension / 2 * ring)
                drawCircle(color.copy(alpha = .22f), radius = size.minDimension / 2 * ring, style = Stroke(1.dp.toPx()))
                drawRoundRect(color, Offset(size.width * .23f, size.height * .28f), Size(size.width * .54f, size.height * .36f), CornerRadius(6.dp.toPx()), style = Stroke(2.5.dp.toPx()))
                drawLine(color, Offset(size.width * .5f, size.height * .64f), Offset(size.width * .5f, size.height * .73f), 2.5.dp.toPx())
                drawLine(color, Offset(size.width * .36f, size.height * .74f), Offset(size.width * .64f, size.height * .74f), 2.5.dp.toPx())
            }
            Text(name.ifEmpty { "Your Windows laptop" }, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Surface(color = color.copy(alpha = .12f), shape = CircleShape) { Text(if (pending) "●  Approval needed" else if (paired) "●  Paired securely" else "○  Ready to pair", Modifier.padding(horizontal = 14.dp, vertical = 7.dp), color = color, style = MaterialTheme.typography.labelMedium) }
        }
    }
}
