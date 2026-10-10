package dev.windowsunlock.phone

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.work.*
import com.google.android.gms.tasks.Tasks
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

object Push {
    const val CHANNEL = "approval_requests_v1"
    fun configured(context: Context): Boolean = try { FirebaseApp.initializeApp(context) != null || FirebaseApp.getApps(context).isNotEmpty() } catch (_: Exception) { false }
    fun channel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "Laptop approval requests", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "Time-limited requests that require system biometric approval"
            lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
        })
    }
    fun sync(context: Context) {
        if (!configured(context)) return
        WorkManager.getInstance(context).enqueueUniqueWork("push-registration", ExistingWorkPolicy.REPLACE,
            OneTimeWorkRequestBuilder<PushRegistration>().setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.SECONDS).build())
    }
}

class PhoneMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) { Push.sync(this) }
    override fun onMessageReceived(message: RemoteMessage) {
        if (message.data["kind"] != "approval") return
        val id = message.data["requestId"] ?: return
        if (!id.matches(Regex("[0-9a-fA-F-]{36}"))) return
        val expires = message.data["expiresAt"]?.toLongOrNull() ?: return
        val remaining = expires * 1000 - System.currentTimeMillis()
        if (remaining <= 0 || remaining > 300000) return
        ApprovalOverlay.show(this, id, remaining)
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        Push.channel(this)
        val intent = Intent(this, MainActivity::class.java).putExtra("approvalRequestId", id).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val review = PendingIntent.getActivity(this, id.hashCode(), intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        // A push is an untrusted hint. The activity fetches and verifies the laptop signature.
        val notification = NotificationCompat.Builder(this, Push.CHANNEL).setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Laptop approval requested").setContentText("Tap to verify your laptop and approve securely.")
            .setPriority(NotificationCompat.PRIORITY_HIGH).setCategory(NotificationCompat.CATEGORY_EVENT)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE).setAutoCancel(true).setTimeoutAfter(remaining)
            .setContentIntent(review).addAction(0, "Review & approve", review).build()
        getSystemService(NotificationManager::class.java).notify(id.hashCode(), notification)
    }
}

class PushRegistration(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val c = Keys.load(applicationContext) ?: return@withContext Result.success()
            if (!c.optBoolean("paired") || !Push.configured(applicationContext)) return@withContext Result.success()
            val token = Tasks.await(FirebaseMessaging.getInstance().token, 15, TimeUnit.SECONDS)
            val now = System.currentTimeMillis() / 1000
            val p = Protocol.message("push-registration").put("androidDeviceId", c.getString("androidDeviceId"))
                .put("pairingId", c.getString("pairingId")).put("token", token).put("appHandledPush", true)
                .put("nonce", Protocol.b64(ByteArray(32).also { SecureRandom().nextBytes(it) })).put("issuedAt", now).put("expiresAt", now + 300)
            val jws = Protocol.sign(Protocol.input(p), Keys.signature(c.getString("identityAlias")))
            Relay(c, c.getString("transportToken")).call("POST", "/v1/android/push-token", org.json.JSONObject().put("registrationJws", jws))
            applicationContext.getSharedPreferences("push-health", Context.MODE_PRIVATE).edit().putBoolean("registered", true).putLong("registeredAt", now).apply()
            Result.success()
        } catch (_: Exception) { applicationContext.getSharedPreferences("push-health", Context.MODE_PRIVATE).edit().putBoolean("registered", false).apply(); if (runAttemptCount < 5) Result.retry() else Result.failure() }
    }
}
