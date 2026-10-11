package com.ws.byedpi

import android.Manifest
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.PagerSnapHelper
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton

class MainActivity : AppCompatActivity() {

    // Цвета кнопки: фон и иконка в выключенном и включённом состоянии
    private val colorOffBg = Color.parseColor("#CBB8FF")
    private val colorOffIcon = Color.parseColor("#2A0F66")
    private val colorOnBg = Color.parseColor("#9FE0A0")
    private val colorOnIcon = Color.parseColor("#0B3D13")

    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var btnStart: FloatingActionButton
    private lateinit var tvStatus: TextView
    private lateinit var tvAppsInfo: TextView
    private lateinit var tvModeInfo: TextView
    private lateinit var rvModes: RecyclerView
    private lateinit var modeAdapter: ModeAdapter

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            doStart()
        } else {
            Toast.makeText(this, "Нужно разрешение VPN", Toast.LENGTH_SHORT).show()
        }
    }

    private val notifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnStart = findViewById(R.id.btnStart)
        tvStatus = findViewById(R.id.tvStatus)
        tvAppsInfo = findViewById(R.id.tvAppsInfo)
        tvModeInfo = findViewById(R.id.tvModeInfo)
        rvModes = findViewById(R.id.rvModes)

        val crashed = logLastExitReason()

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setupModes()

        findViewById<Button>(R.id.btnSettings).setOnClickListener { openSettings() }
        tvAppsInfo.setOnClickListener { openSettings() }
        findViewById<Button>(R.id.btnLog).setOnClickListener { UiUtil.showLog(this) }
        findViewById<Button>(R.id.btnTelegram).setOnClickListener {
            startActivity(Intent(this, TelegramActivity::class.java))
                }
        findViewById<Button>(R.id.btnTest).setOnClickListener {
            startActivity(Intent(this, TestActivity::class.java))
                }
        btnStart.setOnClickListener { onStartClick() }

        if (crashed) {
            Thread {
                DebugLog.dumpLogcat(this)
                mainHandler.post { UiUtil.showLog(this) }
            }.start()
        }
    }

    override fun onStart() {
        super.onStart()
        MyDpiVpnService.onStateChanged = { refresh() }
    }

    override fun onStop() {
        MyDpiVpnService.onStateChanged = null
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        refresh()
        updateInfo()
    }

    private fun openSettings() {
        startActivity(Intent(this, SettingsActivity::class.java))
    }

    // ---------- Режимы обхода (листание вверх и вниз) ----------

    private fun setupModes() {
        val lm = LinearLayoutManager(this, LinearLayoutManager.VERTICAL, false)
        rvModes.layoutManager = lm
        modeAdapter = ModeAdapter { i -> selectMode(i) }
        modeAdapter.select(Config.mode(this))
        rvModes.adapter = modeAdapter
        PagerSnapHelper().attachToRecyclerView(rvModes)

        rvModes.post {
            val itemH = (92 * resources.displayMetrics.density).toInt()
            val side = ((rvModes.height - itemH) / 2).coerceAtLeast(0)
            rvModes.setPadding(0, side, 0, side)
            rvModes.clipToPadding = false
            lm.scrollToPositionWithOffset(Config.mode(this), 0)
        }
        updateModeInfo()
    }

    private fun selectMode(i: Int) {
        Config.setMode(this, i)
        modeAdapter.select(i)
        rvModes.smoothScrollToPosition(i)
        updateModeInfo()
        if (MyDpiVpnService.isRunning) {
            Toast.makeText(this, "Применится после перезапуска", Toast.LENGTH_SHORT).show()
        }
    }

    private fun updateModeInfo() {
        val s = Config.strategies[Config.mode(this)]
        tvModeInfo.text = "Выбран: ${s.title} · листай ↑ ↓, тап чтобы выбрать"
    }

    // ---------- Запуск / остановка ----------

    private fun onStartClick() {
        if (MyDpiVpnService.isRunning) {
            Config.stopVpn(this)
            mainHandler.postDelayed({ refresh() }, 700)
            return
        }
        if (!Config.allApps(this) && Config.apps(this).isEmpty()) {
            AlertDialog.Builder(this)
                .setTitle("Не выбраны приложения")
                .setMessage(
                    "Лучше выбрать только нужные приложения (YouTube, Discord и т.п.): " +
                        "так меньше нагрузка и ничего лишнего не ломается.\n\n" +
                        "Можно запустить и для всех приложений, но это не рекомендуется."
                )
                .setPositiveButton("Выбрать приложения") { _, _ ->
                    startActivity(Intent(this, AppsActivity::class.java))
                }
                .setNegativeButton("Для всех") { _, _ ->
                    Config.setAllApps(this, true)
                    updateInfo()
                    proceedStart()
                }
                .setNeutralButton("Отмена", null)
                .show()
            return
        }
        proceedStart()
    }

    private fun proceedStart() {
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnPermission.launch(prepare) else doStart()
    }

    private fun doStart() {
        if (!Config.startVpn(this)) {
            Toast.makeText(this, "Выбери приложения в настройках", Toast.LENGTH_SHORT).show()
            return
        }
        mainHandler.postDelayed({
            refresh()
            MyDpiVpnService.lastError?.let {
                Toast.makeText(this, it, Toast.LENGTH_LONG).show()
            }
        }, 1800)
    }

    private fun runTest() {
        if (!MyDpiVpnService.isRunning) {
            Toast.makeText(this, "Сначала включи VPN", Toast.LENGTH_SHORT).show()
            return
        }
        Toast.makeText(this, "Проверяю, до 15 сек…", Toast.LENGTH_SHORT).show()
        Thread {
            val res = Diagnostics.run()
            DebugLog.log(this, "TEST >>>\n$res")
            mainHandler.post { UiUtil.showLog(this) }
        }.start()
    }

    // ---------- Отображение ----------

    private fun refresh() {
        val on = MyDpiVpnService.isRunning
        btnStart.backgroundTintList = ColorStateList.valueOf(if (on) colorOnBg else colorOffBg)
        btnStart.imageTintList = ColorStateList.valueOf(if (on) colorOnIcon else colorOffIcon)
        btnStart.contentDescription = if (on) "Отключить" else "Подключить"
        tvStatus.text = if (on) "Подключено (VPN)" else "Отключено (VPN)"
        tvStatus.setTextColor(if (on) Color.parseColor("#81C784") else Color.GRAY)
    }

    private fun updateInfo() {
        val base = if (Config.allApps(this)) {
            "Приложения: все (не рекомендуется)"
        } else {
            "Приложения: выбрано ${Config.apps(this).size}"
        }
        val extra = if (Config.customOn(this)) {
            "\nВключены свои аргументы: режимы выше не используются"
        } else ""
        tvAppsInfo.text = "$base$extra\nИзменить: ⚙ Настройки"
    }

    private fun logLastExitReason(): Boolean {
        if (Build.VERSION.SDK_INT < 30) return false
        return try {
            val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val info = am.getHistoricalProcessExitReasons(packageName, 0, 1).firstOrNull()
                ?: return false
            val prefs = getSharedPreferences(Config.PREFS, Context.MODE_PRIVATE)
            if (prefs.getLong("LAST_EXIT_TS", 0L) == info.timestamp) return false
            prefs.edit().putLong("LAST_EXIT_TS", info.timestamp).apply()
            val name = when (info.reason) {
                1 -> "EXIT_SELF"
                2 -> "SIGNALED"
                3 -> "LOW_MEMORY"
                4 -> "CRASH"
                5 -> "CRASH_NATIVE"
                6 -> "ANR"
                10 -> "USER_REQUESTED"
                else -> "OTHER(${info.reason})"
            }
            DebugLog.log(this, "EXIT reason=$name status=${info.status} desc=${info.description}")
            info.reason == 4 || info.reason == 5
        } catch (_: Exception) {
            false
        }
    }
}
