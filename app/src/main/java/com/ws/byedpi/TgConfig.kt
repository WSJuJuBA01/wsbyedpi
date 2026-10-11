package com.ws.byedpi

import android.content.Context
import java.security.SecureRandom

object TgConfig {
    private const val PREFS = "ws_tg_prefs"
    const val DEFAULT_HOST = "127.0.0.1"
    const val DEFAULT_PORT = 8080

    private val hostRegex = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val secretRegex = Regex("^[0-9a-f]{32}$")
    private val domainRegex =
        Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun validHost(v: String): Boolean = hostRegex.matches(v.trim())

    fun host(ctx: Context): String {
        val h = p(ctx).getString("HOST", DEFAULT_HOST)?.trim().orEmpty()
        return if (validHost(h)) h else DEFAULT_HOST
    }

    fun setHost(ctx: Context, v: String) {
        p(ctx).edit().putString("HOST", v.trim()).apply()
    }

    fun port(ctx: Context): Int {
        val v = p(ctx).getInt("PORT", DEFAULT_PORT)
        return if (v in 1024..65535) v else DEFAULT_PORT
    }

    fun setPort(ctx: Context, v: Int) {
        p(ctx).edit().putInt("PORT", v).apply()
    }

    fun secret(ctx: Context): String {
        val cur = p(ctx).getString("SECRET", null)
        if (cur != null && secretRegex.matches(cur)) return cur
        return regenSecret(ctx)
    }

    fun regenSecret(ctx: Context): String {
        val b = ByteArray(16)
        SecureRandom().nextBytes(b)
        val s = b.joinToString("") { "%02x".format(it) }
        p(ctx).edit().putString("SECRET", s).apply()
        return s
    }

    fun cf(ctx: Context): Boolean = p(ctx).getBoolean("CF", true)

    fun setCf(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("CF", v).apply()
    }

    fun cfDomains(ctx: Context): String = p(ctx).getString("CF_DOMAINS", "") ?: ""

    fun setCfDomains(ctx: Context, v: String) {
        p(ctx).edit().putString("CF_DOMAINS", v).apply()
    }

    fun parseDomains(raw: String): List<String> =
        raw.split(',', ' ', '\n', ';')
            .map { it.trim().lowercase() }
            .filter { domainRegex.matches(it) }

    fun autostart(ctx: Context): Boolean = p(ctx).getBoolean("AUTOSTART", false)

    fun setAutostart(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("AUTOSTART", v).apply()
    }

    fun link(ctx: Context): String =
        "tg://proxy?server=${host(ctx)}&port=${port(ctx)}&secret=dd${secret(ctx)}"
}
