package dev.windowsunlock.phone

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import androidx.work.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

data class AppRelease(val versionCode: Long, val versionName: String, val url: String, val sha256: String, val size: Long) {
    companion object {
        fun parse(p: JSONObject): AppRelease {
            require(p.getString("packageName") == "dev.windowsunlock.phone")
            val version = p.getLong("versionCode"); val name = p.getString("versionName"); val url = p.getString("url")
            require(version > 0 && name.matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+")))
            require(url.matches(Regex("https://github\\.com/anishdevtech/windows-unlock/releases/download/v[0-9.]+/WINDOWS-UNLOCK-[0-9.]+-debug\\.apk")))
            val digest = p.getString("sha256"); require(digest.matches(Regex("[0-9a-f]{64}")))
            val size = p.getLong("size"); require(size in 1..104857600)
            return AppRelease(version, name, url, digest, size)
        }
    }
}

object AppUpdates {
    private const val FEED = "https://raw.githubusercontent.com/anishdevtech/windows-unlock/main/android-updates/stable.json"
    private val client = OkHttpClient.Builder().connectTimeout(10, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS)
        .callTimeout(5, TimeUnit.MINUTES).followRedirects(false).followSslRedirects(false).build()
    private fun preferences(context: Context) = context.getSharedPreferences("app-updates", Context.MODE_PRIVATE)
    fun automatic(context: Context): Boolean = preferences(context).getBoolean("automatic", true)
    fun schedule(context: Context) {
        val manager = WorkManager.getInstance(context)
        if (!automatic(context)) { manager.cancelUniqueWork("app-update-daily"); manager.cancelUniqueWork("app-update-now"); return }
        val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED).setRequiresStorageNotLow(true).build()
        manager.enqueueUniquePeriodicWork("app-update-daily", ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<AppUpdateWorker>(24, TimeUnit.HOURS).setConstraints(constraints).build())
        manager.enqueueUniqueWork("app-update-now", ExistingWorkPolicy.KEEP, OneTimeWorkRequestBuilder<AppUpdateWorker>().setConstraints(constraints).build())
    }
    fun automatic(context: Context, enabled: Boolean) { preferences(context).edit().putBoolean("automatic", enabled).apply(); schedule(context) }
    fun check(): AppRelease = client.newCall(Request.Builder().url(FEED).build()).execute().use { response ->
        check(response.isSuccessful) { "Update feed unavailable" }
        AppRelease.parse(JSONObject(String(response.body!!.byteStream().use { boundedRead(it) }, Charsets.UTF_8)))
    }
    private fun signatures(info: android.content.pm.PackageInfo): Set<String> = requireNotNull(info.signingInfo).apkContentsSigners.map {
        MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).joinToString("") { b -> "%02x".format(b) }
    }.toSet()
    @Synchronized fun download(context: Context, release: AppRelease): File {
        require(release.versionCode > BuildConfig.VERSION_CODE)
        val directory = File(context.cacheDir, "updates").apply { mkdirs() }
        val target = File(directory, "update-${release.versionCode}.apk")
        if (target.exists()) { try { verify(context, target, release); return target } catch (_: Exception) { check(target.delete()) } }
        val partial = File(directory, "download.tmp")
        try {
            var url = release.url
            var downloaded = false
            repeat(5) {
                if (!downloaded) client.newCall(Request.Builder().url(url).build()).execute().use { response ->
                    if (response.code in listOf(301,302,303,307,308)) {
                        val next = requireNotNull(response.header("Location")); val uri = Uri.parse(next)
                        require(uri.scheme == "https" && uri.userInfo == null && uri.host in setOf("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"))
                        url = next
                    } else {
                        check(response.isSuccessful) { "Update download unavailable" }
                        val body = requireNotNull(response.body); require(body.contentLength() == -1L || body.contentLength() == release.size)
                        body.byteStream().use { input -> partial.outputStream().use { output ->
                            val bytes = ByteArray(65536); var size = 0L
                            while (true) { val n = input.read(bytes); if (n < 0) break; size += n; require(size <= release.size); output.write(bytes,0,n) }
                            require(size == release.size)
                        } }; downloaded = true
                    }
                }
            }
            check(downloaded); verify(context, partial, release); check(partial.renameTo(target))
            preferences(context).edit().putString("readyName", release.versionName).putLong("readyVersion", release.versionCode).putString("readyMetadata", JSONObject().put("packageName",context.packageName).put("versionCode",release.versionCode).put("versionName",release.versionName).put("url",release.url).put("sha256",release.sha256).put("size",release.size).toString()).apply()
            directory.listFiles()?.filter { it != target && it.name.startsWith("update-") }?.forEach { it.delete() }
            return target
        } finally { partial.delete() }
    }
    private fun verify(context: Context, file: File, release: AppRelease) {
        require(file.length() == release.size)
        val digest = MessageDigest.getInstance("SHA-256"); file.inputStream().use { input -> val buffer=ByteArray(65536); while(true){val n=input.read(buffer);if(n<0)break;digest.update(buffer,0,n)} }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }; require(actual == release.sha256)
        val current = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val candidate = requireNotNull(context.packageManager.getPackageArchiveInfo(file.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES))
        require(candidate.packageName == context.packageName && candidate.longVersionCode == release.versionCode && candidate.longVersionCode > current.longVersionCode && signatures(current) == signatures(candidate) && signatures(current).isNotEmpty())
    }
    fun ready(context: Context): String? {
        val p=preferences(context); val version=p.getLong("readyVersion",0)
        return if(version>BuildConfig.VERSION_CODE && File(context.cacheDir,"updates/update-$version.apk").isFile) p.getString("readyName",null) else null
    }
    fun installIntent(context: Context): Intent {
        if (!context.packageManager.canRequestPackageInstalls()) {
            return Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
        }
        val metadata = AppRelease.parse(JSONObject(requireNotNull(preferences(context).getString("readyMetadata", null))))
        val file=File(context.cacheDir,"updates/update-${metadata.versionCode}.apk"); verify(context,file,metadata)
        val uri=FileProvider.getUriForFile(context,"${context.packageName}.updates",file)
        return Intent(Intent.ACTION_VIEW).setDataAndType(uri,"application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    fun notifyReady(context: Context) {
        val version=ready(context)?:return
        val manager=context.getSystemService(NotificationManager::class.java)
        if(!manager.areNotificationsEnabled())return
        manager.createNotificationChannel(NotificationChannel("app_updates","App updates",NotificationManager.IMPORTANCE_DEFAULT))
        val open=PendingIntent.getActivity(context,732,Intent(context,MainActivity::class.java).putExtra("showUpdates",true),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        try { manager.notify(732,NotificationCompat.Builder(context,"app_updates").setSmallIcon(R.drawable.ic_notification).setContentTitle("WINDOWS-UNLOCK $version ready")
            .setContentText("Tap to install the verified update. Your pairing stays saved.").setContentIntent(open).setAutoCancel(true).build()) } catch (_: SecurityException) { }
    }
}

class AppUpdateWorker(context: Context, parameters: WorkerParameters): CoroutineWorker(context,parameters) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try { if(AppUpdates.automatic(applicationContext)){val release=AppUpdates.check();if(release.versionCode>BuildConfig.VERSION_CODE){AppUpdates.download(applicationContext,release);AppUpdates.notifyReady(applicationContext)}};Result.success() }
        catch (_: Exception) { if(runAttemptCount<3)Result.retry() else Result.failure() }
    }
}
