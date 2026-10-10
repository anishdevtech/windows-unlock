package dev.windowsunlock.phone

import android.os.Bundle
import android.content.Intent
import android.Manifest
import android.os.Build
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.*
import org.json.JSONObject
import java.security.SecureRandom
import java.security.Signature
import java.util.UUID
import java.text.DateFormat
import java.util.Date

class MainActivity : FragmentActivity() {
    private var config by mutableStateOf<JSONObject?>(null)
    private var status by mutableStateOf("Import a Windows pairing invitation to begin.")
    private var request by mutableStateOf<JSONObject?>(null)
    private var requestToken = ""
    private var fingerprint by mutableStateOf("")
    private var pairedName by mutableStateOf("")
    private var working by mutableStateOf(false)
    private var prompt: BiometricPrompt? = null
    private var notificationRequestId: String? = null
    private var vaultRequest by mutableStateOf<JSONObject?>(null)
    private var vaultToken = ""
    private var overlayEnabled by mutableStateOf(false)
    private val overlayPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        overlayEnabled = android.provider.Settings.canDrawOverlays(this)
        ApprovalOverlay.setEnabled(this, overlayEnabled)
    }
    private var notificationSettings by mutableStateOf("")
    private var pushStatus by mutableStateOf("Popup notifications need Firebase configuration.")
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        pushStatus = if (granted) "Notifications allowed. Tap the popup to authenticate." else "Notifications disabled. You can still open the app to review requests."
        if (granted) Push.sync(this)
    }
    private var candidateAliases = emptyList<String>()
    private fun clearCandidateKeys() { candidateAliases.forEach { Keys.delete(it) }; candidateAliases = emptyList() }
    private val picker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && !working) lifecycleScope.launch {
            try {
                val text = withContext(Dispatchers.IO) { contentResolver.openInputStream(uri)!!.use { stream ->
                    val data = boundedRead(stream); String(data, Charsets.UTF_8)
                } }
                val bundle = Protocol.strictJson(text); val invitation = Protocol.verify(bundle.getString("invitationJws"), bundle.getJSONObject("windowsJwk"), "pair-invitation")
                Protocol.lifetime(invitation, 300)
                status = "Pair with ${invitation.getString("windowsName")}? Check that you exported this invitation from your own laptop."
                pendingInvitation = bundle
                showPairConsent = true
            } catch (_: Exception) { status = "Invalid, expired or untrusted invitation. Export a new one from Windows." }
        }
    }
    private var pendingInvitation: JSONObject? = null
    private var showPairConsent by mutableStateOf(false)
    private var showRemoveVaults by mutableStateOf(false)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try { Keys.cleanupCameraKeys() } catch (_: Exception) { /* No viewer is resumed across activity restarts. */ }
        notificationRequestId = intent.getStringExtra("approvalRequestId") ?: intent.getStringExtra("requestId")
        Push.channel(this)
        if (Push.configured(this)) { pushStatus = "Firebase configured. Enable popup approvals below."; Push.sync(this) }
        try { config = Keys.load(this); config?.let { pairedName = Protocol.decode(it.getString("invitationJws")).getString("windowsName"); fingerprint = if (it.optBoolean("paired")) "" else it.optString("fingerprint"); status = if (it.optBoolean("paired")) "Paired with $pairedName. Waiting for a secure request." else "Compare the pairing code and confirm on Windows." } }
        catch (_: Exception) { status = "Protected configuration cannot be opened. Reset local pairing and pair again." }
        setContent {
            UnlockTheme {
                UnlockDashboard(pairedName, config?.optBoolean("paired") == true, status, fingerprint,
                    vaultRequest, request, working, ::approveVault, ::denyVault, ::approve, ::deny,
                    controls = {
                        config?.takeIf { it.optBoolean("paired") }?.let { c -> RemoteControls(c, working) { sig, label, success, cancel ->
                            authenticate(sig, label, onCancel = cancel) { approved -> success(approved); working = false }
                        } }
                    }, settings = {
                        Text("Floating approvals", style = MaterialTheme.typography.titleLarge)
                        Text("Show a small request card over other apps. Tap it to review and authenticate securely.")
                        Switch(checked = overlayEnabled, onCheckedChange = { enabled ->
                            if (enabled && !android.provider.Settings.canDrawOverlays(this@MainActivity)) {
                                overlayPermission.launch(Intent(android.provider.Settings.ACTION_MANAGE_OVERLAY_PERMISSION, android.net.Uri.parse("package:$packageName")))
                            } else {
                                ApprovalOverlay.setEnabled(this@MainActivity, enabled); overlayEnabled = enabled
                            }
                        }, enabled = !working)
                        Text(if (overlayEnabled) "Display over other apps enabled" else "Floating card off · notifications still available", style = MaterialTheme.typography.bodySmall)
                        HorizontalDivider()

                    Text("Notifications", style = MaterialTheme.typography.titleLarge)
                    Text(notificationSettings, style = MaterialTheme.typography.bodyMedium)
                    Text(pushStatus, style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = { startActivity(Intent(android.provider.Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS).putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, packageName).putExtra(android.provider.Settings.EXTRA_CHANNEL_ID, Push.CHANNEL)) }) { Text("Open notification settings") }

                    OutlinedButton(onClick = {
                        if (!Push.configured(this@MainActivity)) pushStatus = "Add Firebase google-services.json and rebuild the APK. See docs/hosting.md."
                        else if (Build.VERSION.SDK_INT >= 33) notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                        else { Push.sync(this@MainActivity); pushStatus = "Popups enabled. Keep this notification channel enabled in Android settings." }
                    }, enabled = !working) { Text("Enable popup approvals") }
                    if (config == null) Button(onClick = { picker.launch(arrayOf("application/json", "text/plain", "application/octet-stream")) }, enabled = config == null && !working) { Text("Import pairing invitation") }
                    if ((config?.optJSONObject("vaults")?.length() ?: 0) > 0) {
                        Text("Phone sign-in enabled for ${config?.optJSONObject("vaults")?.length()} enrollment(s). Windows stores the encrypted password locally.")
                        OutlinedButton(onClick = { showRemoveVaults = true }, enabled = !working) { Text("Remove phone sign-in keys") }
                    }
                    OutlinedButton(onClick = { reset() }, enabled = !working) { Text("Reset local pairing") }
                    Text("With Firebase configured, requests arrive as popups while this app is closed. Tap to verify and authenticate. Android controls notification display.\n\nWindows PIN and password remain independent backup methods.", style = MaterialTheme.typography.bodySmall)

                        if (config?.optBoolean("paired") == true) Diagnostics(config!!)
                    })
                if (showPairConsent) AlertDialog(onDismissRequest = { showPairConsent = false; pendingInvitation = null }, title = { Text("Confirm laptop pairing") }, text = { Text(status) },
                    confirmButton = { TextButton(onClick = { showPairConsent = false; beginPair(pendingInvitation!!); pendingInvitation = null }) { Text("Pair this laptop") } },
                    dismissButton = { TextButton(onClick = { showPairConsent = false; pendingInvitation = null }) { Text("Cancel") } })
                if (showRemoveVaults) AlertDialog(onDismissRequest = { showRemoveVaults = false }, title = { Text("Remove phone sign-in keys?") }, text = { Text("This phone will no longer release your laptop's password key. Use Windows PIN or Password and run laptop enrollment again to restore phone sign-in. Pairing and camera controls remain available.") },
                    confirmButton = { TextButton(onClick = { showRemoveVaults = false; config?.let { c -> c.optJSONObject("vaults")?.keys()?.asSequence()?.toList()?.forEach { Keys.delete(Vault.alias(it)) }; c.remove("vaults"); Keys.save(this@MainActivity, c); config = JSONObject(c.toString()) }; vaultRequest = null; status = "Phone sign-in keys removed. Use Windows PIN." }) { Text("Remove keys") } },
                    dismissButton = { TextButton(onClick = { showRemoveVaults = false }) { Text("Cancel") } })
            }
        }
        lifecycleScope.launch { repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (isActive) { try { if (!working) poll() } catch (_: Exception) { status = "Phone authentication unavailable. Check connection; use Windows PIN if needed." }; delay(1000) }
        } }
    }
    override fun onStart() { super.onStart(); ApprovalOverlay.setForeground(true) }
    override fun onStop() { ApprovalOverlay.setForeground(false); super.onStop() }
    override fun onResume() {
        super.onResume()
        ApprovalOverlay.dismiss()
        overlayEnabled = ApprovalOverlay.enabled(this)
        val manager = getSystemService(android.app.NotificationManager::class.java)
        notificationSettings = when {
            !manager.areNotificationsEnabled() -> "Notifications blocked. Allow them in Android settings."
            (manager.getNotificationChannel(Push.CHANNEL)?.importance ?: 0) < android.app.NotificationManager.IMPORTANCE_HIGH -> "Popups disabled for this channel. Set it to high importance and enable banners."
            else -> "Notification permission and high-importance channel enabled."
        }
        val preferences = getSharedPreferences("push-health", MODE_PRIVATE)
        if (preferences.getBoolean("registered", false)) pushStatus = "Phone push token registered with your relay. On OPPO, allow background activity for WINDOWS-UNLOCK if delivery is delayed."
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); setIntent(intent); notificationRequestId = intent.getStringExtra("approvalRequestId") ?: intent.getStringExtra("requestId")
        lifecycleScope.launch { try { if (!working) poll() } catch (_: Exception) { status = "Request unavailable or expired. No approval sent." } }
    }
    private fun authenticate(signature: Signature, subtitle: String, onCancel: () -> Unit = {}, success: (Signature) -> Unit) {
        val flags = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        check(BiometricManager.from(this).canAuthenticate(flags) == BiometricManager.BIOMETRIC_SUCCESS)
        working = true
        prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                try { success(result.cryptoObject?.signature ?: error("Missing signing operation")) }
                catch (_: Exception) { onCancel(); clearCandidateKeys(); working = false; status = "Signing failed. Pair again if the key was invalidated." }
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { onCancel(); clearCandidateKeys(); working = false; status = "Authentication cancelled or unavailable. No approval sent." }
        })
        prompt!!.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("Authenticate for $subtitle")
            .setAllowedAuthenticators(flags).setConfirmationRequired(true).build(), BiometricPrompt.CryptoObject(signature))
    }
    private fun beginPair(bundle: JSONObject) {
        try {
            val invitation = Protocol.verify(bundle.getString("invitationJws"), bundle.getJSONObject("windowsJwk"), "pair-invitation"); Protocol.lifetime(invitation, 300)
            val id = UUID.randomUUID().toString(); val approvalAlias = "phoneunlock-approval-$id"; val identityAlias = "phoneunlock-identity-$id"
            candidateAliases = listOf(approvalAlias, identityAlias)
            val approval = Keys.generate(approvalAlias, true); val identity = Keys.generate(identityAlias, false)
            val token = Protocol.b64(ByteArray(32).also { SecureRandom().nextBytes(it) })
            val proposal = Protocol.message("pair-proposal").put("sessionId", invitation.getString("sessionId")).put("windowsDeviceId", invitation.getString("windowsDeviceId"))
                .put("androidDeviceId", id).put("phoneName", android.os.Build.MODEL.take(80)).put("approvalJwk", approval).put("identityJwk", identity)
                .put("invitationHash", Protocol.hash(bundle.getString("invitationJws"))).put("tokenHash", Protocol.hash(token))
            val input = Protocol.input(proposal)
            authenticate(Keys.signature(approvalAlias), invitation.getString("windowsName")) { signature ->
                val proof = Protocol.sign(input, signature); val c = JSONObject(bundle.toString()).put("androidDeviceId", id).put("approvalAlias", approvalAlias).put("identityAlias", identityAlias)
                    .put("transportToken", token).put("proposalJws", proof).put("sessionId", invitation.getString("sessionId")).put("paired", false)
                val code = Protocol.hash(bundle.getString("invitationJws") + "." + proof).take(16).uppercase(); c.put("fingerprint", code)
                lifecycleScope.launch {
                    try { withContext(Dispatchers.IO) { Relay(c, c.getString("pairingToken")).call("POST", "/v1/pairing-sessions/${c.getString("sessionId")}/proposal", JSONObject().put("proposalJws", proof)) }
                        Keys.save(this@MainActivity, c); config = c; candidateAliases = emptyList(); fingerprint = code; pairedName = invitation.getString("windowsName"); status = "Compare this code on Windows, then confirm there."
                    } catch (_: Exception) { clearCandidateKeys(); status = "Pairing failed. Create a new invitation." }
                    finally { working = false }
                }
            }
        } catch (_: Exception) { clearCandidateKeys(); working = false; status = "Secure key or system authentication unavailable. Set up a screen lock; hardware-backed signing is required." }
    }
    private suspend fun poll() {
        val c = config ?: return
        if (!c.getBoolean("paired")) {
            Protocol.lifetime(Protocol.decode(c.getString("invitationJws")), 300)
            val r = withContext(Dispatchers.IO) { Relay(c, c.getString("pairingToken")).call("GET", "/v1/pairing-sessions/${c.getString("sessionId")}") }
            if (config !== c || working) return
            if (r.has("receiptJws")) {
                val receipt = Protocol.verify(r.getString("receiptJws"), c.getJSONObject("windowsJwk"), "pair-receipt")
                val invite = Protocol.decode(c.getString("invitationJws"))
                require(receipt.getString("sessionId") == c.getString("sessionId") && receipt.getString("androidDeviceId") == c.getString("androidDeviceId")
                    && receipt.getString("windowsDeviceId") == invite.getString("windowsDeviceId") && receipt.getString("proposalHash") == Protocol.hash(c.getString("proposalJws")))
                c.put("pairingId", receipt.getString("pairingId")).put("paired", true); c.remove("pairingToken"); Keys.save(this, c); fingerprint = ""; status = "Paired. Waiting for requests from $pairedName."; Push.sync(this)
            }
            return
        }
        val vault = withContext(Dispatchers.IO) { Relay(c, c.getString("transportToken")).call("GET", "/v1/vault-requests/pending") }
        if (config !== c || working) return
        if (vault.has("requestJws")) {
            vaultToken = vault.getString("requestJws"); vaultRequest = VaultProtocol.verify(vaultToken, c); request = null
            status = "Review this Windows sign-in request before approving."
            notificationRequestId?.let { id -> if (id == vaultRequest!!.getString("requestId")) {
                notificationRequestId = null; getSystemService(android.app.NotificationManager::class.java).cancel(id.hashCode()); getSystemService(android.app.NotificationManager::class.java).cancel(id, 0)
            } }
            return
        }
        vaultRequest = null
        val r = withContext(Dispatchers.IO) { Relay(c, c.getString("transportToken")).call("GET", "/v1/authentication-requests/pending") }
        if (config !== c || working) return
        if (!r.has("requestJws")) { request = null; return }
        val token = r.getString("requestJws"); val p = Protocol.verify(token, c.getJSONObject("windowsJwk"), "auth-request"); Protocol.lifetime(p, 60)
        val invite = Protocol.decode(c.getString("invitationJws"))
        val unlock = p.getString("purpose") == "windows-unlock"
        if (unlock) require(!BuildConfig.ALLOW_SOFTWARE_KEYS)
        require(p.length() == (if (unlock) 15 else 11) && p.getString("windowsDeviceId") == invite.getString("windowsDeviceId") && p.getString("androidDeviceId") == c.getString("androidDeviceId") && p.getString("pairingId") == c.getString("pairingId"))
        if (unlock) require(p.getString("windowsAccountSid").matches(Regex("S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+")) && p.getInt("sessionId") > 0 && p.getInt("usageScenario") in 1..2 && p.getString("existingLogonId").matches(Regex("[0-9a-f]{16}")))
        requestToken = token; request = p; status = "Review this request before approving."
        notificationRequestId?.let { id -> if (id == p.getString("requestId")) {
            notificationRequestId = null
            getSystemService(android.app.NotificationManager::class.java).cancel(id.hashCode())
            getSystemService(android.app.NotificationManager::class.java).cancel(id, 0)
            // Notification tap shows the verified request. Approve still requires an explicit button press.
        } }
    }
    private fun response(r: JSONObject, token: String, decision: String): JSONObject = Protocol.message("auth-response", r.getString("purpose"))
        .put("requestId", r.getString("requestId")).put("pairingId", r.getString("pairingId")).put("windowsDeviceId", r.getString("windowsDeviceId"))
        .put("androidDeviceId", r.getString("androidDeviceId")).put("challengeHash", Protocol.hash(token)).put("decision", decision)
    private fun approve() {
        try { val c = config!!; val r = request ?: return; val token = requestToken; Protocol.lifetime(r, 60)
            val input = Protocol.input(response(r, token, "approve"))
            authenticate(Keys.signature(c.getString("approvalAlias")), pairedName) { sig ->
                Protocol.lifetime(r, 60); submit(c, r, Protocol.sign(input, sig))
            }
        } catch (_: Exception) { working = false; status = "Request expired or signing key unavailable. No approval sent." }
    }
    private fun deny() {
        try { val c = config!!; val r = request ?: return; Protocol.lifetime(r, 60); working = true
            submit(c, r, Protocol.sign(Protocol.input(response(r, requestToken, "deny")), Keys.signature(c.getString("identityAlias"))))
        } catch (_: Exception) { working = false; status = "Request unavailable. No approval sent." }
    }
    private fun submit(c: JSONObject, r: JSONObject, token: String) {
        request = null
        lifecycleScope.launch {
            try { withContext(Dispatchers.IO) { Relay(c, c.getString("transportToken")).call("POST", "/v1/authentication-requests/${r.getString("requestId")}/responses", JSONObject().put("responseJws", token)) }
                status = if (r.getString("purpose") == "windows-unlock") "Approval delivered. Windows verifies it independently." else "Connection test approved. This test cannot unlock Windows."
            } catch (_: Exception) { status = "Delivery failed or request expired. Use Windows PIN if needed." }
            finally { working = false }
        }
    }
    private fun approveVault() {
        val c = config ?: return; val r = vaultRequest ?: return; val token = vaultToken
        try { require(!BuildConfig.ALLOW_SOFTWARE_KEYS); VaultProtocol.verify(token, c); working = true
            if (r.getString("type") == "vault-enroll") lifecycleScope.launch {
                val id = Protocol.decode(r.getString("delegationJws")).getString("vaultId")
                val existed = Vault.exists(id)
                try {
                    val records = c.optJSONObject("vaults") ?: JSONObject()
                    require(records.length() < 4 || records.has(id)) { "Remove old sign-in enrollments first" }
                    if (records.has(id)) require(records.getJSONObject(id).getString("delegationJws") == r.getString("delegationJws"))
                    val pub = withContext(Dispatchers.IO) { Vault.generate(id) }
                    authenticate(Keys.signature(c.getString("approvalAlias")), "enable sign-in for $pairedName", onCancel = { if (!existed) Keys.delete(Vault.alias(id)) }) { sig ->
                        Protocol.lifetime(r, 300)
                        records.put(id, JSONObject().put("delegationJws", r.getString("delegationJws"))); c.put("vaults", records); Keys.save(this@MainActivity, c)
                        val p = VaultProtocol.response(r, token, "approve").put("phoneJwk", pub)
                        submitVault(c, r, Protocol.sign(Protocol.input(p), sig))
                    }
                } catch (_: Exception) { if (!existed) Keys.delete(Vault.alias(id)); working = false; status = "Hardware-backed phone sign-in setup failed. Use Windows PIN." }
            } else {
                val id = Protocol.decode(r.getString("delegationJws")).getString("vaultId")
                val cipher = Vault.cipher(id)
                prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        try { val released = Vault.release(result.cryptoObject?.cipher ?: error("Missing key operation"), r)
                            val p = VaultProtocol.response(r, token, "approve").put("wrappedKey", released)
                            submitVault(c, r, Protocol.sign(Protocol.input(p), Keys.signature(c.getString("identityAlias"))))
                        } catch (_: Exception) { working = false; status = "Key release failed or request expired. Use Windows PIN." }
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { working = false; status = "Approval cancelled. No key released." }
                })
                prompt!!.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("Authenticate to unlock $pairedName")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL).setConfirmationRequired(true).build(), BiometricPrompt.CryptoObject(cipher))
            }
        } catch (_: Exception) { working = false; status = "Phone sign-in unavailable. Use Windows PIN." }
    }
    private fun denyVault() { try { val c = config ?: return; val r = vaultRequest ?: return; val p = VaultProtocol.response(r, vaultToken, "deny"); working = true
        submitVault(c, r, Protocol.sign(Protocol.input(p), Keys.signature(c.getString("identityAlias"))))
    } catch (_: Exception) { working = false; status = "Request unavailable." } }
    private fun submitVault(c: JSONObject, r: JSONObject, token: String) { vaultRequest = null
        lifecycleScope.launch { try { withContext(Dispatchers.IO) { Relay(c, c.getString("transportToken")).call("POST", "/v1/vault-requests/${r.getString("requestId")}/responses", JSONObject().put("responseJws", token)) }; status = if (r.getString("type") == "vault-enroll") "Phone sign-in enabled. Finish setup on Windows." else "Key release delivered. Waiting for Windows to accept sign-in." }
            catch (_: Exception) { status = "Delivery failed. Use Windows PIN; retry setup if enrollment was interrupted." } finally { working = false } }
    }
    private fun reset() { ApprovalOverlay.setEnabled(this, false); overlayEnabled = false; config?.let { c -> Keys.delete(c.getString("approvalAlias")); Keys.delete(c.getString("identityAlias")); c.optJSONObject("vaults")?.keys()?.asSequence()?.toList()?.forEach { Keys.delete(Vault.alias(it)) } }; Keys.clear(this); getSharedPreferences("push-health", MODE_PRIVATE).edit().clear().apply(); config = null; request = null; vaultRequest = null; fingerprint = ""; pairedName = ""; status = "Local pairing removed. Also select Unpair on Windows before pairing again." }
}
