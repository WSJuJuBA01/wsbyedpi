package com.ws.byedpi

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
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

        /** Сколько раз Telegram подключился с неверным ключом за этот запуск */
        @Volatile
        var badSecretHits = 0

        @Volatile
        private var engineRef: TgProxyEngine? = null

        private val logBuf = ArrayDeque<String>()
        private const val CHANNEL_ID = "ws_tg"
        private const val NOTIF_ID = 11
        private const val WAKE_MS = 6 * 60 * 60 * 1000L

        fun log(msg: String) {
            Log.i("WSTg", msg)
            val time = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
            synchronized(logBuf) {
                logBuf.addLast("$time $msg")
                while (logBuf.size > 150) logBuf.removeFirst()
            }
        }

        fun logText(): String = synchronized(logBuf) { logBuf.joinToString("\n") }

        fun stats(): String = engineRef?.statsLine() ?: ""
    }

    private val handler = Handler(Looper.getMainLooper())
    private var engine: TgProxyEngine? = null
    private var wakeLock: PowerManager.WakeLock? = null

    private val wakeRefresh = object : Runnable {
        override fun run() {
            if (isRunning) {
                try {
                    wakeLock?.acquire(WAKE_MS)
                } catch (_: Throwable) {
                }
                handler.postDelayed(this, WAKE_MS - 3_600_000L)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        when {
            action == "START" -> {
                TgConfig.setWantRunning(this, true)
                enterForeground("Запуск…")
                Thread { startEngine() }.start()
            }
            action == "STOP" -> {
                TgConfig.setWantRunning(this, false)
                Thread {
                    stopEngine()
                    leaveForeground()
                    stopSelf()
                    notifyState()
                }.start()
            }
            intent == null -> {
                // Систему убила службу, и она вернула её: поднимаем прокси снова
                if (TgConfig.wantRunning(this)) {
                    log("Служба возвращена системой, перезапускаю прокси")
                    enterForeground("Перезапуск…")
                    Thread { startEngine() }.start()
                } else {
                    stopSelf()
                }
            }
        }
        return START_STICKY
    }

    @Synchronized
    private fun startEngine() {
        stopEngine()
        lastError = null
        badSecretHits = 0
        val host = TgConfig.host(this)
        val port = TgConfig.port(this)
        val hex = TgConfig.secret(this)
        val bytes = ByteArray(16) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        val e = TgProxyEngine(
            host,
            port,
            bytes,
            TgConfig.cf(this),
            TgConfig.parseDomains(TgConfig.cfDomains(this)),
            TgConfig.poolSize(this)
        ) { log(it) }
        e.onBadSecret = { badSecretHits++ }

        // порт мог ещё не освободиться после перезапуска: пробуем несколько раз
        var started = false
        var lastErr: Throwable? = null
        for (attempt in 1..3) {
            try {
                e.start()
                started = true
                break
            } catch (t: Throwable) {
                lastErr = t
                try {
                    Thread.sleep(700)
                } catch (_: InterruptedException) {
                }
            }
        }

        if (started) {
            engine = e
            engineRef = e
            isRunning = true
            acquireWake()
            log("Прокси запущен на $host:$port")
            updateNotification("Работает на $host:$port")
        } else {
            lastError = "Не удалось занять $host:$port. Порт занят другим приложением? Смени порт."
            log("Ошибка запуска: $lastErr")
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
        releaseWake()
        try {
            engine?.stop()
        } catch (_: Throwable) {
        }
        if (engine != null) log("Прокси остановлен")
        engine = null
        engineRef = null
        isRunning = false
    }

    private fun acquireWake() {
        if (!TgConfig.wakeLock(this)) return
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            val wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "WSByeDPI:tgproxy")
            wl.setReferenceCounted(false)
            wl.acquire(WAKE_MS)
            wakeLock = wl
            handler.removeCallbacks(wakeRefresh)
            handler.postDelayed(wakeRefresh, WAKE_MS - 3_600_000L)
        } catch (t: Throwable) {
            log("WakeLock: $t")
        }
    }

    private fun releaseWake() {
        handler.removeCallbacks(wakeRefresh)
        try {
            wakeLock?.let { if (it.isHeld) it.release() }
        } catch (_: Throwable) {
        }
        wakeLock = null
    }

    private fun notifyState() {
        handler.post { onStateChanged?.invoke() }
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
