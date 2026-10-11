package com.ws.byedpi

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

object Config {
    const val PREFS = "ws_byedpi_prefs"
    const val DEFAULT_SNI = "ads.x5.ru"

    private const val AUTO = "--auto=torst,ssl_err"

    private const val AGGRESSIVE =
        "--disorder 1 --split 2+s --tlsrec 2+s --auto=torst,ssl_err --timeout 3 " +
            "--disorder 1 --disorder 3+s --split 6+s --disorder 9+s --split 12+s " +
            "--disorder 15+s --split 20+s --disorder 25+s --split 30+s --disorder 35+s " +
            "--tlsrec 1+s --fake -40 --ttl 8 --md5sig --udp-fake 3"

    class Strategy(
        val title: String,
        val desc: String,
        val build: (String) -> String
    )

    private fun fake(ttl: Int, sni: String) =
        "-f350 -Qr -f-1+sh -t$ttl -Qr -a4 -m3 -n $sni"

    /** Цепочка групп: если одна не сработала (сброс, таймаут, ошибка SSL), берётся следующая */
    private fun mutant(sni: String): String {
        val groups = listOf(
            fake(6, sni),
            "--timeout 3 -s 1+s -d 3+s -r 1+s -M h,d",
            fake(8, sni),
            fake(4, sni),
            "--split 2+s --disorder 4+s --tlsrec 2+s",
            fake(6, "max.ru"),
            "--fake -1 --ttl 6 --md5sig --split 1+s --tlsrec 1+s",
            "--oob 3+s --tlsrec 1+s",
            "--disoob 1+s --tlsrec 1+s",
            "--split 1 --disorder 2 --tlsrec 1+s --mod-http=h,d,r",
            fake(10, sni) + " -s 1+s -d 3+s",
            AGGRESSIVE
        )
        return groups.joinToString(" $AUTO ")
    }

    val strategies: List<Strategy> = listOf(
        Strategy("Включил и забыл", "Все режимы по цепочке: сам подберёт рабочий вариант") { sni ->
            mutant(sni)
        },
        Strategy("Обход #1", "Режим с подменой SNI. Рекомендуется") { sni -> fake(6, sni) },
        Strategy("Обход #2", "Режим с много разбиений и fake.") { _ -> AGGRESSIVE },
        Strategy("Обход #3", "Режим если fake ломает сайты. А так можно просто так использовать") { _ ->
            "--split 1+s --disorder 3+s --tlsrec 3+h --mod-http=h,d --auto=torst"
        },
        Strategy("Обход #4", "Как #1, но TTL 4") { sni -> fake(4, sni) },
        Strategy("Обход #5", "Как #1, но TTL 5") { sni -> fake(5, sni) },
        Strategy("Обход #6", "Как #1, но TTL 7") { sni -> fake(7, sni) },
        Strategy("Обход #7", "Как #1, но TTL 8") { sni -> fake(8, sni) },
        Strategy("Обход #8", "Как #1, но TTL 10") { sni -> fake(10, sni) },
        Strategy("Обход #9", "Как #1, подмена SNI на max.ru") { _ -> fake(6, "max.ru") },
        Strategy("Обход #10", "Как #1, подмена SNI на ya.ru") { _ -> fake(6, "ya.ru") },
        Strategy("Обход #11", "Как #1, подмена SNI на vk.ru") { _ -> fake(6, "vk.ru") },
        Strategy("Обход #12", "Как #1, подмена SNI на gosuslugi.ru") { _ -> fake(6, "gosuslugi.ru") },
        Strategy("Обход #13", "Классика: split + disorder + tlsrec, без фейков") { _ ->
            "-s 1+s -d 3+s -r 1+s -M h,d"
        },
        Strategy("Обход #14", "Split и disorder с авто-переключением при сбое") { _ ->
            "--split 2+s --disorder 4+s --tlsrec 2+s --auto=torst,ssl_err"
        },
        Strategy("Обход #15", "OOB-вставка + tlsrec") { _ ->
            "--oob 3+s --tlsrec 1+s"
        },
        Strategy("Обход #16", "Disoob + tlsrec") { _ ->
            "--disoob 1+s --tlsrec 1+s"
        },
        Strategy("Обход #17", "Fake + md5sig + split") { _ ->
            "--fake -1 --ttl 6 --md5sig --split 1+s --tlsrec 1+s"
        },
        Strategy("Обход #18", "Split + правки HTTP-заголовков") { _ ->
            "--split 1 --disorder 2 --tlsrec 1+s --mod-http=h,d,r"
        },
        Strategy("Обход #19", "Комбо: #1 + split и disorder") { sni ->
            fake(6, sni) + " -s 1+s -d 3+s"
        },
        Strategy("Обход #20", "Максимальный: split + fake SNI + авто-переключение") { sni ->
            "--split 1+s --disorder 3+s --tlsrec 1+s --auto=torst,ssl_err --timeout 3 " +
                fake(6, sni)
        }
    )

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun mode(ctx: Context): Int =
        p(ctx).getInt("MODE_V2", 0).coerceIn(0, strategies.size - 1)

    fun setMode(ctx: Context, v: Int) {
        p(ctx).edit().putInt("MODE_V2", v).apply()
    }

    fun allApps(ctx: Context): Boolean = p(ctx).getBoolean("ALL_APPS", false)

    fun setAllApps(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("ALL_APPS", v).apply()
    }

    fun apps(ctx: Context): Set<String> =
        HashSet(p(ctx).getStringSet("TARGET_APPS", emptySet()) ?: emptySet())

    fun setApps(ctx: Context, v: Set<String>) {
        p(ctx).edit().putStringSet("TARGET_APPS", HashSet(v)).apply()
    }

    fun fakeSni(ctx: Context): String {
        val s = p(ctx).getString("FAKE_SNI", DEFAULT_SNI)?.trim().orEmpty()
        return if (s.isEmpty()) DEFAULT_SNI else s
    }

    fun setFakeSni(ctx: Context, v: String) {
        val clean = v.replace(Regex("[^A-Za-z0-9.-]"), "")
        p(ctx).edit().putString("FAKE_SNI", clean).apply()
    }

    fun customOn(ctx: Context): Boolean = p(ctx).getBoolean("CUSTOM_ON", false)

    fun setCustomOn(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("CUSTOM_ON", v).apply()
    }

    fun customArgs(ctx: Context): String = p(ctx).getString("CUSTOM_ARGS", "") ?: ""

    fun setCustomArgs(ctx: Context, v: String) {
        p(ctx).edit().putString("CUSTOM_ARGS", v).apply()
    }

    fun currentArgs(ctx: Context): String {
        val custom = customArgs(ctx).trim()
        return if (customOn(ctx) && custom.isNotEmpty()) {
            custom
        } else {
            strategies[mode(ctx)].build(fakeSni(ctx))
        }
    }

    /** false, если нечего запускать (не выбраны приложения и не включён режим «все») */
    fun startVpn(ctx: Context): Boolean {
        val all = allApps(ctx)
        val apps = apps(ctx)
        if (!all && apps.isEmpty()) return false
        val intent = Intent(ctx, MyDpiVpnService::class.java).apply {
            action = "START"
            putStringArrayListExtra("TARGET_APPS", ArrayList(apps))
            putExtra("ALL_APPS", all)
            putExtra("ARGS", currentArgs(ctx))
        }
        ContextCompat.startForegroundService(ctx, intent)
        return true
    }

    fun stopVpn(ctx: Context) {
        ctx.startService(Intent(ctx, MyDpiVpnService::class.java).setAction("STOP"))
    }
}
