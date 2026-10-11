package com.ws.byedpi

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.button.MaterialButtonToggleGroup
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.switchmaterial.SwitchMaterial

class TelegramActivity : AppCompatActivity() {

    private val colorOffBg = Color.parseColor("#CBB8FF")
    private val colorOffIcon = Color.parseColor("#2A0F66")
    private val colorOnBg = Color.parseColor("#9FE0A0")
    private val colorOnIcon = Color.parseColor("#0B3D13")

    private val handler = Handler(Looper.getMainLooper())
    private lateinit var fab: FloatingActionButton
    private lateinit var tvState: TextView
    private lateinit var tvLink: TextView
    private lateinit var tvSecret: TextView
    private lateinit var etHost: EditText
    private lateinit var etPort: EditText
    private lateinit var tgPool: MaterialButtonToggleGroup
    private lateinit var swCf: SwitchMaterial
    private lateinit var etCf: EditText
    private lateinit var swAuto: SwitchMaterial
    private lateinit var tvLog: TextView
    private var loading = true

    private val tick = object : Runnable {
        override fun run() {
            tvLog.text = TgProxyService.logText().ifBlank { "Лог пуст" }
            refresh()
            handler.postDelayed(this, 1500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_telegram)

        fab = findViewById(R.id.fab)
        tvState = findViewById(R.id.tvState)
        tvLink = findViewById(R.id.tvLink)
        tvSecret = findViewById(R.id.tvSecret)
        etHost = findViewById(R.id.etHost)
        etPort = findViewById(R.id.etPort)
        tgPool = findViewById(R.id.tgPool)
        swCf = findViewById(R.id.swCf)
        etCf = findViewById(R.id.etCf)
        swAuto = findViewById(R.id.swAuto)
        tvLog = findViewById(R.id.tvLog)

        findViewById<Button>(R.id.btnBack).setOnClickListener { finish() }

        etHost.setText(TgConfig.host(this))
        etPort.setText(TgConfig.port(this).toString())
        tvSecret.text = TgConfig.secret(this)
        swCf.isChecked = TgConfig.cf(this)
        etCf.setText(TgConfig.cfDomains(this))
        swAuto.isChecked = TgConfig.autostart(this)
        tgPool.check(
            when (TgConfig.poolSize(this)) {
                2 -> R.id.btnPool2
                6 -> R.id.btnPool6
                else -> R.id.btnPool4
            }
        )
        updateLink()
        updateCfVisibility()

        etHost.doAfterTextChanged {
            if (!loading) {
                val v = it?.toString().orEmpty().trim()
                if (TgConfig.validHost(v)) TgConfig.setHost(this, v)
                updateLink()
            }
        }
        etPort.doAfterTextChanged {
            if (!loading) {
                val p = it?.toString()?.toIntOrNull()
                if (p != null && p in 1024..65535) TgConfig.setPort(this, p)
                updateLink()
            }
        }
        tgPool.addOnButtonCheckedListener { _, id, checked ->
            if (checked && !loading) {
                val size = when (id) {
                    R.id.btnPool2 -> 2
                    R.id.btnPool6 -> 6
                    else -> 4
                }
                TgConfig.setPoolSize(this, size)
            }
        }
        swCf.setOnCheckedChangeListener { _, on ->
            if (!loading) {
                TgConfig.setCf(this, on)
                updateCfVisibility()
            }
        }
        etCf.doAfterTextChanged {
            if (!loading) TgConfig.setCfDomains(this, it?.toString().orEmpty())
        }
        swAuto.setOnCheckedChangeListener { _, on ->
            if (!loading) TgConfig.setAutostart(this, on)
        }

        findViewById<Button>(R.id.btnRegen).setOnClickListener {
            tvSecret.text = TgConfig.regenSecret(this)
            updateLink()
            Toast.makeText(
                this,
                "Новый ключ. Перезапусти прокси и примени ссылку в Telegram заново",
                Toast.LENGTH_LONG
            ).show()
        }

        fab.setOnClickListener {
            if (TgProxyService.isRunning) {
                startService(Intent(this, TgProxyService::class.java).setAction("STOP"))
            } else {
                ContextCompat.startForegroundService(
                    this, Intent(this, TgProxyService::class.java).setAction("START")
                )
            }
            handler.postDelayed({
                refresh()
                TgProxyService.lastError?.let {
                    Toast.makeText(this, it, Toast.LENGTH_LONG).show()
                }
            }, 1500)
        }

        findViewById<Button>(R.id.btnApply).setOnClickListener {
            if (!TgProxyService.isRunning) {
                Toast.makeText(this, "Сначала включи прокси", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(TgConfig.link(this))))
            } catch (e: ActivityNotFoundException) {
                Toast.makeText(this, "Telegram не найден", Toast.LENGTH_SHORT).show()
            }
        }
        findViewById<Button>(R.id.btnCopy).setOnClickListener {
            copy("ws-tg-link", TgConfig.link(this))
        }
        findViewById<Button>(R.id.btnCopyLog).setOnClickListener {
            copy("ws-tg-log", TgProxyService.logText())
        }

        loading = false
    }

    override fun onResume() {
        super.onResume()
        handler.post(tick)
    }

    override fun onPause() {
        handler.removeCallbacks(tick)
        super.onPause()
    }

    private fun copy(label: String, text: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
        Toast.makeText(this, "Скопировано", Toast.LENGTH_SHORT).show()
    }

    private fun updateLink() {
        tvLink.text = TgConfig.link(this)
    }

    private fun updateCfVisibility() {
        etCf.visibility = if (swCf.isChecked) View.VISIBLE else View.GONE
    }

    private fun refresh() {
        val on = TgProxyService.isRunning
        fab.backgroundTintList = ColorStateList.valueOf(if (on) colorOnBg else colorOffBg)
        fab.imageTintList = ColorStateList.valueOf(if (on) colorOnIcon else colorOffIcon)
        tvState.text = if (on) {
            "Подключено · ${TgConfig.host(this)}:${TgConfig.port(this)}"
        } else {
            "Отключено"
        }
        tvState.setTextColor(if (on) Color.parseColor("#81C784") else Color.GRAY)
    }
}
