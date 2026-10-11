package dev.windowsunlock.phone

import android.content.Context
import androidx.work.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MediaStopWorker(context: Context, parameters: WorkerParameters): CoroutineWorker(context,parameters) {
    companion object {
        fun request(context: Context, id: String) {
            WorkManager.getInstance(context).enqueueUniqueWork("stop-media-$id", ExistingWorkPolicy.KEEP,
                OneTimeWorkRequestBuilder<MediaStopWorker>().setInputData(workDataOf("mediaId" to id))
                    .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()).build())
        }
    }
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val config=Keys.load(applicationContext)?:return@withContext Result.success()
            val id=inputData.getString("mediaId")?:return@withContext Result.failure()
            Relay(config,config.getString("transportToken")).call("POST","/v1/media/$id/stop",JSONObject())
            Result.success()
        } catch (_: Exception) { if(runAttemptCount<2)Result.retry() else Result.failure() }
    }
}
