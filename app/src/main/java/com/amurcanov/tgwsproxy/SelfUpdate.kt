package com.amurcanov.tgwsproxy

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Собственный канал обновлений, не зависящий от публичных релизов апстрима.
 *
 * Манифест — обычный JSON по HTTPS:
 * ```
 * {"versionCode":1106,"versionName":"1.1.6",
 *  "apk":"https://host/app.apk","sha256":"<64 hex>"}
 * ```
 *
 * APK скачивается в кэш, проверяется по SHA-256 и отдаётся системному
 * установщику. Подпись у всех наших сборок одна, поэтому обновление ставится
 * поверх и настройки сохраняются.
 */
object SelfUpdate {
    private const val TAG = "TgWsProxy"
    private const val CHANNEL_ID = "tgws_self_updates"
    private const val NOTIFICATION_ID = 7301
    private const val MAX_MANIFEST_BYTES = 64 * 1024
    private const val MAX_APK_BYTES = 200L * 1024 * 1024

    data class Manifest(
        val versionCode: Long,
        val versionName: String,
        val apkUrl: String,
        val sha256: String
    )

    enum class CheckResult { NO_URL, UP_TO_DATE, FAILED, READY }

    /** Проверяет манифест и, если версия новее, скачивает APK в кэш. */
    suspend fun checkAndPrepare(context: Context): CheckResult = withContext(Dispatchers.IO) {
        try {
            val url = SettingsStore(context.applicationContext).updateManifestUrl.first().trim()
            if (url.isEmpty()) return@withContext CheckResult.NO_URL
            val manifest = fetchManifest(url) ?: return@withContext CheckResult.FAILED
            if (manifest.versionCode <= BuildConfig.VERSION_CODE.toLong()) return@withContext CheckResult.UP_TO_DATE

            val dir = File(context.cacheDir, "updates").apply { mkdirs() }
            val apk = File(dir, "tgwsproxy-${manifest.versionName}.apk")
            val expected = manifest.sha256.lowercase()
            if (!apk.isFile || sha256(apk) != expected) {
                apk.delete()
                if (!download(manifest.apkUrl, apk)) {
                    apk.delete()
                    return@withContext CheckResult.FAILED
                }
            }
            if (sha256(apk) != expected) {
                apk.delete()
                Log.w(TAG, "Self-update: checksum mismatch")
                return@withContext CheckResult.FAILED
            }
            notifyReady(context, apk, manifest.versionName)
            CheckResult.READY
        } catch (e: Exception) {
            Log.w(TAG, "Self-update failed: ${e.javaClass.simpleName}")
            CheckResult.FAILED
        }
    }

    /** Открыть системный установщик для уже скачанного APK. */
    fun install(context: Context, apk: File): Boolean = try {
        context.startActivity(installIntent(context, apk).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (e: Exception) {
        Log.w(TAG, "Self-update: installer unavailable: ${e.javaClass.simpleName}")
        false
    }

    fun cachedApk(context: Context): File? =
        File(context.cacheDir, "updates")
            .listFiles()
            ?.filter { it.isFile && it.extension == "apk" }
            ?.maxByOrNull { it.lastModified() }

    private fun installIntent(context: Context, apk: File): Intent {
        val uri: Uri = FileProvider.getUriForFile(context, "${context.packageName}.logs", apk)
        return Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }

    private fun notifyReady(context: Context, apk: File, versionName: String) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.self_update_channel),
                    NotificationManager.IMPORTANCE_DEFAULT
                )
            )
        }
        val pending = PendingIntent.getActivity(
            context,
            0,
            installIntent(context, apk).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle(context.getString(R.string.self_update_ready_title, versionName))
            .setContentText(context.getString(R.string.self_update_ready_text))
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .build()
        manager.notify(NOTIFICATION_ID, notification)
    }

    private fun fetchManifest(url: String): Manifest? {
        val text = readText(url, MAX_MANIFEST_BYTES) ?: return null
        val json = JSONObject(text)
        val apkUrl = json.optString("apk").trim()
        val sha = json.optString("sha256").trim()
        val versionName = json.optString("versionName").trim()
        if (apkUrl.isEmpty() || versionName.isEmpty()) return null
        if (!sha.matches(Regex("[0-9a-fA-F]{64}"))) return null
        if (!apkUrl.startsWith("https://")) return null
        return Manifest(json.getLong("versionCode"), versionName, apkUrl, sha)
    }

    private fun readText(url: String, limit: Int): String? {
        val connection = open(url) ?: return null
        return try {
            if (connection.responseCode !in 200..299) return null
            val buffer = ByteArray(8 * 1024)
            val output = ByteArrayOutputStream()
            connection.inputStream.use { stream ->
                while (true) {
                    val size = stream.read(buffer)
                    if (size < 0) break
                    if (output.size() + size > limit) return null
                    output.write(buffer, 0, size)
                }
            }
            output.toByteArray().toString(Charsets.UTF_8)
        } finally {
            connection.disconnect()
        }
    }

    private fun download(url: String, target: File): Boolean {
        val connection = open(url) ?: return false
        val temp = File(target.parentFile, target.name + ".part")
        return try {
            if (connection.responseCode !in 200..299) return false
            if (connection.contentLengthLong > MAX_APK_BYTES) return false
            FileOutputStream(temp).use { file ->
                connection.inputStream.use { stream ->
                    val buffer = ByteArray(64 * 1024)
                    var written = 0L
                    while (true) {
                        val size = stream.read(buffer)
                        if (size < 0) break
                        written += size
                        if (written > MAX_APK_BYTES) return false
                        file.write(buffer, 0, size)
                    }
                }
            }
            temp.renameTo(target)
        } finally {
            connection.disconnect()
            if (temp.isFile && !target.isFile) temp.delete()
        }
    }

    private fun open(url: String): HttpURLConnection? = try {
        val parsed = URL(url)
        if (parsed.protocol != "https") null else {
            (parsed.openConnection() as HttpURLConnection).apply {
                connectTimeout = 20_000
                readTimeout = 60_000
                useCaches = false
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "TGWSProxy/${BuildConfig.VERSION_NAME}")
                setRequestProperty("Cache-Control", "no-cache")
            }
        }
    } catch (e: Exception) {
        null
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { stream ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val size = stream.read(buffer)
                if (size < 0) break
                digest.update(buffer, 0, size)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
