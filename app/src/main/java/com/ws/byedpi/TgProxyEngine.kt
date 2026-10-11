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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

private const val TAG_ABRIDGED = 0xefefefefL
private const val TAG_INTERMEDIATE = 0xeeeeeeeeL
private const val TAG_PADDED = 0xddddddddL
private const val MAX_PACKET = 16 * 1024 * 1024
private const val WEB_IP = "149.154.167.220"

private val WEB_HOST = Regex("kws[24](-1)?\\.web\\.telegram\\.org")

private val DC_IPS = mapOf(
    1 to "149.154.175.53",
    2 to "149.154.167.51",
    3 to "149.154.175.100",
    4 to "149.154.167.91",
    5 to "91.108.56.130"
)

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

/**
 * Локальный MTProto-прокси для Telegram: принимает подключение клиента (с секретом),
 * определяет DC и пересылает трафик на сервер Telegram через WebSocket
 * (прямой, через Cloudflare-домены) или обычным TCP.
 */
class TgProxyEngine(
    private val host: String,
    private val port: Int,
    private val secret: ByteArray,
    private val cfEnabled: Boolean,
    private val cfDomains: List<String>,
    private val log: (String) -> Unit
) {
    private val random = SecureRandom()
    private val executor = Executors.newCachedThreadPool()
    private val clients: MutableSet<Socket> = ConcurrentHashMap.newKeySet()

    @Volatile
    private var serverSocket: ServerSocket? = null

    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .pingInterval(25, TimeUnit.SECONDS)
        .dns(object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                if (WEB_HOST.matches(hostname)) {
                    return listOf(InetAddress.getByName(WEB_IP))
                }
                return Dns.SYSTEM.lookup(hostname)
            }
        })
        .build()

    // ---------- Запуск и остановка ----------

    fun start() {
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(InetAddress.getByName(host), port))
        serverSocket = ss
        executor.execute {
            while (!ss.isClosed) {
                try {
                    val s = ss.accept()
                    s.tcpNoDelay = true
                    clients.add(s)
                    executor.execute { handle(s) }
                } catch (e: Exception) {
                    if (!ss.isClosed) log("accept: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        clients.forEach { closeQuiet(it) }
        clients.clear()
        executor.shutdownNow()
        http.dispatcher.executorService.shutdown()
        http.connectionPool.evictAll()
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

    private fun buildServerInit(tag: Long, dc: Int): ServerSession {
        val b = ByteArray(64)
        while (true) {
            random.nextBytes(b)
            if ((b[0].toInt() and 0xff) == 0xef) continue
            if (u32(b, 0) in FORBIDDEN_FIRST) continue
            if (le32(b, 4) == 0) continue
            break
        }
        putLe32(b, 56, tag)
        b[60] = (dc and 0xff).toByte()
        b[61] = ((dc shr 8) and 0xff).toByte()
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

    // ---------- Маршруты до Telegram ----------

    private interface Upstream {
        fun send(data: ByteArray): Boolean
        fun close()
    }

    private class WsUpstream(private val ws: WebSocket) : Upstream {
        override fun send(data: ByteArray): Boolean = ws.send(data.toByteString())
        override fun close() {
            ws.close(1000, null)
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

    private fun openUpstream(
        dc: Int,
        media: Boolean,
        init: ByteArray,
        onData: (ByteArray) -> Unit,
        onDone: () -> Unit
    ): Upstream? {
        val label = "kws$dc" + if (media) "-1" else ""
        val tagDc = "DC$dc" + if (media) "m" else ""

        connectWs("wss://$label.web.telegram.org/apiws", init, onData, onDone)?.let {
            log("$tagDc: WebSocket напрямую")
            return it
        }
        if (cfEnabled) {
            if (cfDomains.isEmpty()) {
                log("CF включён, но домены не заданы")
            }
            for (d in cfDomains) {
                connectWs("wss://$label.$d/apiws", init, onData, onDone)?.let {
                    log("$tagDc: WebSocket через CF ($d)")
                    return it
                }
            }
        }
        connectTcp(dc, init, onData, onDone)?.let {
            log("$tagDc: прямой TCP")
            return it
        }
        return null
    }

    private fun connectWs(
        url: String,
        init: ByteArray,
        onData: (ByteArray) -> Unit,
        onDone: () -> Unit
    ): Upstream? {
        val opened = CountDownLatch(1)
        val ok = AtomicBoolean(false)
        val active = AtomicBoolean(false)
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
                if (active.get()) onData(bytes.toByteArray())
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                if (active.get()) onDone()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (active.get()) onDone()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (!ok.get()) log("WS ${req.url.host}: ${t.javaClass.simpleName}")
                opened.countDown()
                if (active.get()) onDone()
            }
        })
        opened.await(8, TimeUnit.SECONDS)
        if (!ok.get()) {
            ws.cancel()
            return null
        }
        active.set(true)
        if (!ws.send(init.toByteString())) {
            ws.cancel()
            return null
        }
        return WsUpstream(ws)
    }

    private fun connectTcp(
        dc: Int,
        init: ByteArray,
        onData: (ByteArray) -> Unit,
        onDone: () -> Unit
    ): Upstream? {
        val ip = DC_IPS[dc] ?: return null
        val s = Socket()
        try {
            s.connect(InetSocketAddress(ip, 443), 6000)
            s.tcpNoDelay = true
            val up = TcpUpstream(s)
            if (!up.send(init)) {
                up.close()
                return null
            }
            executor.execute {
                try {
                    val inp = s.getInputStream()
                    val b = ByteArray(16384)
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
            return up
        } catch (e: Exception) {
            closeQuiet(s)
            return null
        }
    }

    // ---------- Обработка одного клиента ----------

    private fun handle(client: Socket) {
        var upstream: Upstream? = null
        try {
            client.soTimeout = 15000
            val input = client.getInputStream()
            val output = client.getOutputStream()

            val first = readFully(input, 64) ?: return
            val cs = parseClientInit(first)
            if (cs == null) {
                log("Клиент: неверный секрет или протокол")
                return
            }
            client.soTimeout = 0

            val dc = abs(cs.dc)
            val media = cs.dc < 0
            if (dc !in 1..5) {
                log("Неизвестный DC: ${cs.dc}")
                return
            }

            val su = buildServerInit(cs.tag, cs.dc)
            val outLock = Any()

            val onData: (ByteArray) -> Unit = { data ->
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
            val onDone: () -> Unit = { closeQuiet(client) }

            val up = openUpstream(dc, media, su.init, onData, onDone)
            if (up == null) {
                log("DC$dc: нет доступного маршрута")
                return
            }
            upstream = up

            val splitter = PacketSplitter(cs.tag)
            val buf = ByteArray(16384)
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
            try {
                upstream?.close()
            } catch (_: Exception) {
            }
            closeQuiet(client)
            clients.remove(client)
        }
    }
}
