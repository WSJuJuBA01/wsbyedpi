package com.ws.byedpi

import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

private const val TAG_ABRIDGED = 0xefefefefL
private const val TAG_INTERMEDIATE = 0xeeeeeeeeL
private const val TAG_PADDED = 0xddddddddL
private const val MAX_PACKET = 16 * 1024 * 1024
private const val POOL_MAX_AGE = 55_000L

// Прямой WebSocket есть только для DC 2 и 4 (как в оригинале Flowseal)
private const val WS_IP = "149.154.167.220"
private val WS_DCS = setOf(2, 4)
private val WEB_HOST = Regex("kws[1-5](-1)?\\.web\\.telegram\\.org")

// Адреса DC для запасного прямого TCP
private val DC_IPS = mapOf(
    1 to "149.154.175.50",
    2 to "149.154.167.51",
    3 to "149.154.175.100",
    4 to "149.154.167.91",
    5 to "149.154.171.5",
    203 to "91.105.192.100"
)

private const val DOMAINS_URL =
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/refs/heads/main/.github/cfproxy-domains.txt"

// Встроенный запасной список (в том же обфусцированном виде, что и в оригинале)
private val FALLBACK_ENCODED = listOf(
    "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com"
)

private val DOMAIN_RE = Regex("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")

private val FORBIDDEN_FIRST = setOf(
    0x44414548L, 0x54534f50L, 0x20544547L, 0x4954504fL,
    0xddddddddL, 0xeeeeeeeeL, 0x02010316L
)

private fun le32(b: ByteArray, o: Int): Int =
    (b[o].toInt() and 0xff) or
        ((b[o + 1].toInt() and 0xff) shl 8) or
        ((b[o + 2].toInt() and 0xff) shl 16) or
        ((b[o + 3].toInt() and 0xff) shl 24)

private fun u32(b: ByteArray, o: Int): Long = le32(b, o).toLong() and 0xFFFFFFFFL

private fun s16(b: ByteArray, o: Int): Int =
    ((b[o + 1].toInt() shl 8) or (b[o].toInt() and 0xff)).toShort().toInt()

private fun putLe32(b: ByteArray, o: Int, v: Long) {
    b[o] = (v and 0xff).toByte()
    b[o + 1] = ((v shr 8) and 0xff).toByte()
    b[o + 2] = ((v shr 16) and 0xff).toByte()
    b[o + 3] = ((v shr 24) and 0xff).toByte()
}

private fun sha256(a: ByteArray, b: ByteArray): ByteArray {
    val m = MessageDigest.getInstance("SHA-256")
    m.update(a)
    m.update(b)
    return m.digest()
}

private fun readFully(input: InputStream, n: Int): ByteArray? {
    val b = ByteArray(n)
    var off = 0
    while (off < n) {
        val r = input.read(b, off, n - off)
        if (r < 0) return null
        off += r
    }
    return b
}

private fun closeQuiet(s: Socket) {
    try {
        s.close()
    } catch (_: Exception) {
    }
}

/** Деобфускация записи списка доменов (шифр Цезаря, как в оригинале). */
private fun deobfuscate(s: String): String? {
    val line = s.trim()
    if (!line.endsWith(".com")) return null
    val prefix = line.removeSuffix(".com")
    val n = prefix.count { it in 'a'..'z' || it in 'A'..'Z' }
    val sb = StringBuilder()
    for (c in prefix) {
        when (c) {
            in 'a'..'z' -> sb.append('a' + Math.floorMod(c - 'a' - n, 26))
            in 'A'..'Z' -> sb.append('A' + Math.floorMod(c - 'A' - n, 26))
            else -> sb.append(c)
        }
    }
    return sb.toString() + ".co.uk"
}

/**
 * Локальный MTProto-прокси для Telegram.
 * Маршруты: прямой WebSocket (DC 2 и 4, с пулом) -> Cloudflare-домены -> прямой TCP.
 */
class TgProxyEngine(
    private val host: String,
    private val port: Int,
    private val secret: ByteArray,
    private val cfEnabled: Boolean,
    private val extraDomains: List<String>,
    private val poolSize: Int,
    private val log: (String) -> Unit
) {
    /** Вызывается, когда Telegram подключается с неверным секретом */
    @Volatile
    var onBadSecret: (() -> Unit)? = null

    private val random = SecureRandom()
    private val executor = Executors.newCachedThreadPool()
    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    private val clients: MutableSet<Socket> = ConcurrentHashMap.newKeySet()

    private val active = AtomicInteger(0)
    private val routeWs = AtomicInteger(0)
    private val routeCf = AtomicInteger(0)
    private val routeTcp = AtomicInteger(0)
    private val badSecret = AtomicInteger(0)

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var running = false

    @Volatile
    private var defaultDomains: List<String> =
        FALLBACK_ENCODED.mapNotNull { deobfuscate(it) }

    private val cfRotate = AtomicInteger(0)
    private val stickyCf = ConcurrentHashMap<Int, String>()
    private val cfBad = ConcurrentHashMap<String, Long>()
    private val wsCooldown = ConcurrentHashMap<Int, Long>()
    private val cfCooldown = ConcurrentHashMap<Int, Long>()
    private val pools = ConcurrentHashMap<Int, ConcurrentLinkedQueue<WsConn>>()
    private val refilling = ConcurrentHashMap<Int, AtomicBoolean>()

    // Пинг раз в минуту держит соединения живыми, пока клиент молчит
    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .pingInterval(60, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .dns(object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                if (WEB_HOST.matches(hostname)) {
                    return listOf(InetAddress.getByName(WS_IP))
                }
                return Dns.SYSTEM.lookup(hostname)
            }
        })
        .build()

    fun statsLine(): String {
        val sb = StringBuilder("Активно: ${active.get()} · WS: ${routeWs.get()} · CF: ${routeCf.get()} · TCP: ${routeTcp.get()}")
        if (badSecret.get() > 0) sb.append(" · неверный ключ: ${badSecret.get()}")
        return sb.toString()
    }

    // ---------- Запуск и остановка ----------

    fun start() {
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(InetAddress.getByName(host), port))
        serverSocket = ss
        running = true
        executor.execute { acceptLoop(ss) }
        if (cfEnabled) executor.execute { fetchDefaultDomains() }
        if (poolSize > 0) {
            warmPools()
            scheduler.scheduleWithFixedDelay({ if (running) warmPools() }, 20, 20, TimeUnit.SECONDS)
        }
    }

    fun stop() {
        running = false
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        clients.forEach { closeQuiet(it) }
        clients.clear()
        pools.values.forEach { q ->
            while (true) {
                val c = q.poll() ?: break
                c.close()
            }
        }
        scheduler.shutdownNow()
        executor.shutdownNow()
        http.dispatcher.executorService.shutdown()
        http.connectionPool.evictAll()
    }

    private fun acceptLoop(ss: ServerSocket) {
        while (!ss.isClosed) {
            try {
                val s = ss.accept()
                s.tcpNoDelay = true
                s.keepAlive = true
                clients.add(s)
                executor.execute { handle(s) }
            } catch (e: Exception) {
                if (!ss.isClosed) log("accept: ${e.message}")
            }
        }
    }

    // ---------- Список Cloudflare-доменов ----------

    private fun cfDomainList(): List<String> = (extraDomains + defaultDomains).distinct()

    private fun fetchDefaultDomains() {
        try {
            val client = http.newBuilder().callTimeout(10, TimeUnit.SECONDS).build()
            client.newCall(Request.Builder().url(DOMAINS_URL).build()).execute().use { resp ->
                if (!resp.isSuccessful) {
                    log("Список CF-доменов: HTTP ${resp.code}, беру встроенный")
                    return
                }
                val text = resp.body?.string().orEmpty()
                val list = text.lines()
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .mapNotNull { deobfuscate(it) }
                    .filter { DOMAIN_RE.matches(it) }
                    .distinct()
                if (list.isNotEmpty()) {
                    defaultDomains = list
                    log("CF-домены загружены: ${list.size}")
                }
            }
        } catch (e: Exception) {
            log("Список CF-доменов не загружен (${e.javaClass.simpleName}), беру встроенный")
        }
    }

    // ---------- Шифрование ----------

    private class Crypt(key: ByteArray, iv: ByteArray) {
        private val cipher: Cipher = Cipher.getInstance("AES/CTR/NoPadding").also {
            it.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        }

        fun crypt(data: ByteArray, off: Int = 0, len: Int = data.size): ByteArray =
            cipher.update(data, off, len) ?: ByteArray(0)
    }

    private class ClientSession(
        val tag: Long,
        val dc: Int,
        val decFromClient: Crypt,
        val encToClient: Crypt
    )

    private class ServerSession(
        val init: ByteArray,
        val encToDc: Crypt,
        val decFromDc: Crypt
    )

    private fun parseClientInit(init: ByteArray): ClientSession? {
        val rev = init.reversedArray()
        val dec = Crypt(sha256(init.copyOfRange(8, 40), secret), init.copyOfRange(40, 56))
        val enc = Crypt(sha256(rev.copyOfRange(8, 40), secret), rev.copyOfRange(40, 56))
        val plain = dec.crypt(init)
        val tag = u32(plain, 56)
        if (tag != TAG_ABRIDGED && tag != TAG_INTERMEDIATE && tag != TAG_PADDED) return null
        return ClientSession(tag, s16(plain, 60), dec, enc)
    }

    private fun buildServerInit(tag: Long, dcField: Int): ServerSession {
        val b = ByteArray(64)
        while (true) {
            random.nextBytes(b)
            if ((b[0].toInt() and 0xff) == 0xef) continue
            if (u32(b, 0) in FORBIDDEN_FIRST) continue
            if (le32(b, 4) == 0) continue
            break
        }
        putLe32(b, 56, tag)
        b[60] = (dcField and 0xff).toByte()
        b[61] = ((dcField shr 8) and 0xff).toByte()
        val rev = b.reversedArray()
        val encToDc = Crypt(b.copyOfRange(8, 40), b.copyOfRange(40, 56))
        val decFromDc = Crypt(rev.copyOfRange(8, 40), rev.copyOfRange(40, 56))
        val encInit = encToDc.crypt(b)
        val out = b.copyOf()
        System.arraycopy(encInit, 56, out, 56, 8)
        return ServerSession(out, encToDc, decFromDc)
    }

    // ---------- Нарезка потока на пакеты MTProto ----------

    private class PacketSplitter(private val tag: Long) {
        private var buf = ByteArray(0)

        fun push(data: ByteArray): List<ByteArray> {
            buf = if (buf.isEmpty()) data else buf + data
            val out = ArrayList<ByteArray>()
            var pos = 0
            while (pos < buf.size) {
                val total = packetSize(pos) ?: break
                if (total <= 0 || total > MAX_PACKET) throw IOException("bad packet size")
                if (pos + total > buf.size) break
                out.add(buf.copyOfRange(pos, pos + total))
                pos += total
            }
            buf = if (pos >= buf.size) ByteArray(0) else buf.copyOfRange(pos, buf.size)
            return out
        }

        private fun packetSize(pos: Int): Int? {
            val avail = buf.size - pos
            if (tag == TAG_ABRIDGED) {
                val l = (buf[pos].toInt() and 0xff) and 0x7f
                if (l == 0x7f) {
                    if (avail < 4) return null
                    val words = (buf[pos + 1].toInt() and 0xff) or
                        ((buf[pos + 2].toInt() and 0xff) shl 8) or
                        ((buf[pos + 3].toInt() and 0xff) shl 16)
                    return 4 + words * 4
                }
                return 1 + l * 4
            }
            if (avail < 4) return null
            return 4 + (le32(buf, pos) and 0x7fffffff)
        }
    }

    // ---------- Соединения с Telegram ----------

    private interface Upstream {
        fun send(data: ByteArray): Boolean
        fun close()
    }

    /** WebSocket, который можно держать в пуле и привязать к клиенту позже. */
    private class WsConn : Upstream {
        val created: Long = System.currentTimeMillis()

        @Volatile
        var ws: WebSocket? = null

        @Volatile
        var onData: ((ByteArray) -> Unit)? = null

        @Volatile
        var onDone: (() -> Unit)? = null

        @Volatile
        var closed = false

        override fun send(data: ByteArray): Boolean {
            val w = ws ?: return false
            // Если очередь на отправку разрослась (большая загрузка), даём ей разгрузиться
            var waited = 0
            while (!closed && w.queueSize() > 2_000_000L && waited < 3000) {
                try {
                    Thread.sleep(10)
                } catch (e: InterruptedException) {
                    return false
                }
                waited += 10
            }
            return !closed && w.send(data.toByteString())
        }

        override fun close() {
            closed = true
            try {
                ws?.close(1000, null)
            } catch (_: Exception) {
            }
        }

        fun attach(init: ByteArray, data: (ByteArray) -> Unit, done: () -> Unit): Boolean {
            onData = data
            onDone = done
            if (closed) return false
            return ws?.send(init.toByteString()) == true
        }
    }

    private class TcpUpstream(private val socket: Socket) : Upstream {
        private val out = socket.getOutputStream()

        override fun send(data: ByteArray): Boolean = try {
            synchronized(out) {
                out.write(data)
                out.flush()
            }
            true
        } catch (e: IOException) {
            false
        }

        override fun close() {
            closeQuiet(socket)
        }
    }

    private class WsOutcome(val conn: WsConn?, val code: Int, val error: String?)

    private fun openWs(url: String, waitSec: Long): WsOutcome {
        val conn = WsConn()
        val opened = CountDownLatch(1)
        val ok = AtomicBoolean(false)
        val code = AtomicInteger(0)
        val err = AtomicReference<String?>(null)
        val req = Request.Builder()
            .url(url)
            .header("Sec-WebSocket-Protocol", "binary")
            .header("Origin", "https://web.telegram.org")
            .header(
                "User-Agent",
                "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) " +
                    "Chrome/120.0 Mobile Safari/537.36"
            )
            .build()
        val ws = http.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                ok.set(true)
                opened.countDown()
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                conn.onData?.invoke(bytes.toByteArray())
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                conn.closed = true
                conn.onDone?.invoke()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                conn.closed = true
                conn.onDone?.invoke()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                code.set(response?.code ?: 0)
                err.set(t.javaClass.simpleName)
                conn.closed = true
                opened.countDown()
                conn.onDone?.invoke()
            }
        })
        conn.ws = ws
        opened.await(waitSec, TimeUnit.SECONDS)
        if (!ok.get()) {
            conn.closed = true
            ws.cancel()
            return WsOutcome(null, code.get(), err.get() ?: "таймаут")
        }
        return WsOutcome(conn, 101, null)
    }

    private fun wsHosts(dc: Int, media: Boolean): List<String> {
        val base = "kws$dc.web.telegram.org"
        val one = "kws$dc-1.web.telegram.org"
        return if (media) listOf(one, base) else listOf(base, one)
    }

    private fun poolKey(dc: Int, media: Boolean): Int = dc * 2 + if (media) 1 else 0

    /** Прямой WebSocket: пробуем оба имени, при сбое ставим паузу для этого DC. */
    private fun connectDirectWs(dc: Int, media: Boolean): WsConn? {
        var redirects = 0
        var tried = 0
        for (h in wsHosts(dc, media)) {
            tried++
            val r = openWs("wss://$h/apiws", 6)
            if (r.conn != null) {
                wsCooldown.remove(dc)
                return r.conn
            }
            if (r.code in 300..399) redirects++
            log("WS $h: ${if (r.code != 0) "HTTP ${r.code}" else r.error}")
        }
        val pause = if (redirects == tried) 300_000L else 20_000L
        wsCooldown[dc] = System.currentTimeMillis() + pause
        return null
    }

    /** WebSocket через Cloudflare-домены (kwsN.домен). Плохие записи ставим на паузу (429: на минуту). */
    private fun connectCf(dc: Int, media: Boolean): WsConn? {
        val domains = cfDomainList()
        if (domains.isEmpty()) return null
        val key = poolKey(dc, media)
        val now = System.currentTimeMillis()
        val order = ArrayList<String>()
        stickyCf[key]?.let { if ((cfBad[it] ?: 0L) <= now) order.add(it) }
        val start = cfRotate.getAndIncrement()
        for (i in 0 until minOf(2, domains.size)) {
            val d = domains[(start + i) % domains.size]
            val records = if (media) {
                listOf("kws$dc-1.$d", "kws$dc.$d")
            } else {
                listOf("kws$dc.$d", "kws$dc-1.$d")
            }
            for (r in records) {
                if (r !in order && (cfBad[r] ?: 0L) <= now) order.add(r)
            }
        }
        if (order.isEmpty()) {
            log("CF: все записи на паузе")
            return null
        }
        for (rec in order) {
            val r = openWs("wss://$rec/apiws", 5)
            if (r.conn != null) {
                stickyCf[key] = rec
                cfBad.remove(rec)
                cfCooldown.remove(dc)
                return r.conn
            }
            cfBad[rec] = System.currentTimeMillis() + if (r.code == 429) 60_000L else 20_000L
            log("CF $rec: ${if (r.code != 0) "HTTP ${r.code}" else r.error}")
        }
        cfCooldown[dc] = System.currentTimeMillis() + 15_000L
        return null
    }

    // ---------- Пул прямых WebSocket ----------

    private fun warmPools() {
        for (dc in WS_DCS) {
            refillAsync(dc, false)
            refillAsync(dc, true)
        }
    }

    private fun takePooled(dc: Int, media: Boolean): WsConn? {
        val q = pools[poolKey(dc, media)] ?: return null
        while (true) {
            val c = q.poll() ?: return null
            if (!c.closed && System.currentTimeMillis() - c.created < POOL_MAX_AGE) return c
            c.close()
        }
    }

    private fun refillAsync(dc: Int, media: Boolean) {
        if (poolSize <= 0 || !running) return
        val flag = refilling.getOrPut(poolKey(dc, media)) { AtomicBoolean(false) }
        if (!flag.compareAndSet(false, true)) return
        try {
            executor.execute {
                try {
                    refill(dc, media)
                } finally {
                    flag.set(false)
                }
            }
        } catch (e: Exception) {
            flag.set(false)
        }
    }

    private fun refill(dc: Int, media: Boolean) {
        val q = pools.getOrPut(poolKey(dc, media)) { ConcurrentLinkedQueue() }
        val now = System.currentTimeMillis()
        q.removeIf { c ->
            val stale = c.closed || now - c.created > POOL_MAX_AGE
            if (stale) c.close()
            stale
        }
        while (running && q.size < poolSize) {
            if ((wsCooldown[dc] ?: 0L) > System.currentTimeMillis()) break
            val c = connectDirectWs(dc, media) ?: break
            q.add(c)
        }
    }

    // ---------- Выбор маршрута ----------

    private fun openUpstream(
        tag: Long,
        dcRaw: Int,
        ref: AtomicReference<ServerSession?>,
        onData: (ByteArray) -> Unit,
        onDone: () -> Unit
    ): Upstream? {
        val media = dcRaw < 0
        val dcAbs = abs(dcRaw)
        val wsDc = if (dcAbs == 203) 2 else dcAbs
        val label = "DC$wsDc" + if (media) "m" else ""
        val cfOn = cfEnabled && cfDomainList().isNotEmpty()

        fun attach(conn: WsConn, how: String, viaCf: Boolean): Upstream? {
            val su = buildServerInit(tag, if (media) -wsDc else wsDc)
            ref.set(su)
            if (conn.attach(su.init, onData, onDone)) {
                if (viaCf) routeCf.incrementAndGet() else routeWs.incrementAndGet()
                log("$label: $how")
                return conn
            }
            conn.close()
            return null
        }

        // 1. Прямой WebSocket (только DC 2 и 4): сначала пул, потом новое соединение
        if (wsDc in WS_DCS) {
            val cooling = (wsCooldown[wsDc] ?: 0L) > System.currentTimeMillis()
            if (!cooling || !cfOn) {
                var how = "WebSocket из пула"
                var conn = takePooled(wsDc, media)
                if (conn == null) {
                    how = "WebSocket напрямую"
                    conn = connectDirectWs(wsDc, media)
                }
                if (conn != null) {
                    refillAsync(wsDc, media)
                    attach(conn, how, false)?.let { return it }
                }
            }
        }

        // 2. Cloudflare
        if (cfOn && (cfCooldown[wsDc] ?: 0L) <= System.currentTimeMillis()) {
            connectCf(wsDc, media)?.let { c ->
                attach(c, "WebSocket через Cloudflare", true)?.let { return it }
            }
        }

        // 3. Прямой TCP (последний шанс)
        return connectTcp(tag, dcRaw, ref, onData, onDone, label)
    }

    private fun connectTcp(
        tag: Long,
        dcRaw: Int,
        ref: AtomicReference<ServerSession?>,
        onData: (ByteArray) -> Unit,
        onDone: () -> Unit,
        label: String
    ): Upstream? {
        val ip = DC_IPS[abs(dcRaw)] ?: return null
        val s = Socket()
        try {
            s.connect(InetSocketAddress(ip, 443), 5000)
            s.tcpNoDelay = true
            s.keepAlive = true
            val su = buildServerInit(tag, dcRaw)
            ref.set(su)
            val up = TcpUpstream(s)
            if (!up.send(su.init)) {
                up.close()
                return null
            }
            executor.execute {
                try {
                    val inp = s.getInputStream()
                    val b = ByteArray(32768)
                    while (true) {
                        val n = inp.read(b)
                        if (n < 0) break
                        onData(b.copyOf(n))
                    }
                } catch (_: Exception) {
                } finally {
                    onDone()
                }
            }
            routeTcp.incrementAndGet()
            log("$label: прямой TCP")
            return up
        } catch (e: Exception) {
            closeQuiet(s)
            log("$label: TCP не удался (${e.javaClass.simpleName})")
            return null
        }
    }

    // ---------- Проверка маршрутов ----------

    private fun timeIt(block: () -> WsConn?): String {
        val t0 = System.currentTimeMillis()
        val c = block()
        val ms = System.currentTimeMillis() - t0
        return if (c != null) {
            c.close()
            "✓ $ms мс"
        } else {
            "✗ нет ответа"
        }
    }

    /** Параллельно проверяет прямой WS (DC 2, 4) и Cloudflare (DC 1-5). Не требует запущенного прокси. */
    fun selfCheck(): String {
        if (cfEnabled) fetchDefaultDomains()
        val jobs = ArrayList<Pair<String, Callable<String>>>()
        for (dc in listOf(2, 4)) {
            jobs.add("DC$dc прямой WS" to Callable { timeIt { connectDirectWs(dc, false) } })
        }
        if (cfEnabled) {
            for (dc in listOf(1, 2, 3, 4, 5)) {
                jobs.add("DC$dc через Cloudflare" to Callable { timeIt { connectCf(dc, false) } })
            }
        }
        val futures = executor.invokeAll(jobs.map { it.second }, 28, TimeUnit.SECONDS)
        val sb = StringBuilder()
        sb.append(
            if (cfEnabled) "Cloudflare-доменов: ${cfDomainList().size}\n\n"
            else "Cloudflare выключен\n\n"
        )
        jobs.forEachIndexed { i, job ->
            val f = futures[i]
            val res = try {
                if (f.isCancelled) "⏱ таймаут" else f.get()
            } catch (e: Exception) {
                "✗ ошибка"
            }
            sb.append("${job.first}: $res\n")
        }
        sb.append(
            "\nЕсли везде ✗: нет интернета или сеть режет эти адреса. " +
                "Если ✓ только у части: часть DC пойдёт по запасным маршрутам."
        )
        return sb.toString().trim()
    }

    // ---------- Обработка одного клиента ----------

    private fun handle(client: Socket) {
        var upstream: Upstream? = null
        var counted = false
        try {
            client.soTimeout = 10000
            val input = client.getInputStream()
            val output = client.getOutputStream()

            val first = readFully(input, 64) ?: return
            val cs = parseClientInit(first)
            if (cs == null) {
                val n = badSecret.incrementAndGet()
                if (n == 1 || n % 10 == 0) {
                    log("Клиент: неверный ключ или не MTProto (раз: $n). Нажми «Применить в Telegram»")
                }
                onBadSecret?.invoke()
                return
            }
            client.soTimeout = 0
            active.incrementAndGet()
            counted = true

            val dcAbs = abs(cs.dc)
            if (dcAbs !in 1..5 && dcAbs != 203) {
                log("Неизвестный DC: ${cs.dc}")
                return
            }

            val ref = AtomicReference<ServerSession?>(null)
            val outLock = Any()

            val onData: (ByteArray) -> Unit = { data ->
                val su = ref.get()
                if (su != null) {
                    synchronized(outLock) {
                        val plain = su.decFromDc.crypt(data)
                        val enc = cs.encToClient.crypt(plain)
                        try {
                            output.write(enc)
                            output.flush()
                        } catch (e: IOException) {
                            closeQuiet(client)
                        }
                    }
                }
            }
            val onDone: () -> Unit = { closeQuiet(client) }

            val up = openUpstream(cs.tag, cs.dc, ref, onData, onDone)
            if (up == null) {
                log("DC$dcAbs: нет доступного маршрута")
                return
            }
            upstream = up
            val su = ref.get() ?: return

            val splitter = PacketSplitter(cs.tag)
            val buf = ByteArray(32768)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                val plain = cs.decFromClient.crypt(buf, 0, n)
                for (pkt in splitter.push(plain)) {
                    if (!up.send(su.encToDc.crypt(pkt))) throw IOException("upstream closed")
                }
            }
        } catch (e: Exception) {
            // обрыв соединения — обычная ситуация
        } finally {
            if (counted) active.decrementAndGet()
            try {
                upstream?.close()
            } catch (_: Exception) {
            }
            closeQuiet(client)
            clients.remove(client)
        }
    }
}
