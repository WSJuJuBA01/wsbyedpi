package com.ws.byedpi

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class TgProxyService : Service() {

    companion object {
        @Volatile
        var isRunning = false

        @Volatile
        var lastError: String? = null

        @Volatile
        var onStateChanged: (() -> Unit)? = null

        private val logBuf = ArrayDeque<String>()
        private const val CHANNEL_ID = "ws_tg"
        private const val NOTIF_ID = 11

        fun log(msg: String) {
            Log.i("WSTg", msg)
            val time = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
            synchronized(logBuf) {
                logBuf.addLast("$time $msg")
                while (logBuf.size > 120) logBuf.removeFirst()
            }
        }

        fun logText(): String = synchronized(logBuf) { logBuf.joinToString("\n") }
    }

    private var engine: TgProxyEngine? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "START" -> {
                enterForeground("Запуск…")
                Thread { startEngine() }.start()
            }
            "STOP" -> Thread {
                stopEngine()
                leaveForeground()
                stopSelf()
                notifyState()
            }.start()
        }
        return START_NOT_STICKY
    }

    @Synchronized
    private fun startEngine() {
        stopEngine()
        lastError = null
        val host = TgConfig.host(this)
        val port = TgConfig.port(this)
        val hex = TgConfig.secret(this)
        val bytes = ByteArray(16) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        val e = TgProxyEngine(
            host,
            port,
            bytes,
            TgConfig.cf(this),
            TgConfig.parseDomains(TgConfig.cfDomains(this))
        ) { log(it) }
        try {
            e.start()
            engine = e
            isRunning = true
            log("Прокси запущен на $host:$port")
            updateNotification("Работает на $host:$port")
        } catch (t: Throwable) {
            lastError = "Не удалось занять $host:$port (порт занят?)"
            log("Ошибка запуска: $t")
            try {
                e.stop()
            } catch (_: Throwable) {
            }
            isRunning = false
            leaveForeground()
            stopSelf()
        }
        notifyState()
    }

    @Synchronized
    private fun stopEngine() {
        try {
            engine?.stop()
        } catch (_: Throwable) {
        }
        if (engine != null) log("Прокси остановлен")
        engine = null
        isRunning = false
    }

    private fun notifyState() {
        Handler(Looper.getMainLooper()).post { onStateChanged?.invoke() }
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID, "Прокси для Telegram", NotificationManager.IMPORTANCE_LOW
                    )
                )
            }
        }
    }

    private fun buildNotification(text: String): Notification {
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, TelegramActivity::class.java), flags
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, TgProxyService::class.java).setAction("STOP"),
            flags
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_tile)
            .setContentTitle("WSByeDPI · Для Telegram")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(0, "Остановить", stop)
            .build()
    }

    private fun enterForeground(text: String) {
        ensureChannel()
        val n = buildNotification(text)
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIF_ID, n)
            }
        } catch (t: Throwable) {
            log("startForeground: $t")
        }
    }

    private fun leaveForeground() {
        try {
            stopForeground(Service.STOP_FOREGROUND_REMOVE)
        } catch (_: Throwable) {
        }
    }

    private fun updateNotification(text: String) {
        try {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIF_ID, buildNotification(text))
        } catch (_: Throwable) {
        }
    }

    override fun onDestroy() {
        stopEngine()
        notifyState()
        super.onDestroy()
    }
}
