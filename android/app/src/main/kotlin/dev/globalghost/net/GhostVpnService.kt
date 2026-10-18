package dev.globalghost.net

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.nio.channels.DatagramChannel

/**
 * The Android VPN service. Wires the Rust core (GhostCore) to VpnService:
 * configures the TUN, creates + protects the outer UDP socket, and restarts
 * the pumps on network changes (Wi-Fi â†’ LTE handover) without dropping the
 * tunnel state â€” the hub-side re-anchor ladder makes the 5-tuple change
 * invisible to the session.
 */
class GhostVpnService : VpnService() {

    private var ptr: Long = 0
    private var tun: ParcelFileDescriptor? = null
    private var channel: DatagramChannel? = null
    private var pumpThread: Thread? = null
    private var drainThread: Thread? = null
    private var bootstrapThread: Thread? = null
    @Volatile private var running = false
    private var hubFp: String = ""
    private var hubAddr: SocketAddress? = null
    private var dnsServer: String = "10.66.0.1"
    private var searchDomain: String? = null
    private var activeNetwork: Network? = null
    private val tunnelLock = Any()

    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }

    override fun onCreate() {
        super.onCreate()
        startForegroundServiceNotification()
        // Handover: listen ONLY for real underlying physical networks (Wi-Fi, Cellular) - NOT VPN.
        try {
            val req = android.net.NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(req, handoverCallback)
        } catch (_: Throwable) {}
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null || intent.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }

        hubFp = intent.getStringExtra(EXTRA_HUB_FP)?.trim() ?: hubFp
        intent.getStringExtra(EXTRA_HUB_ADDR)?.trim()?.let {
            val s = it.replace(" ", "")
            if (s.isNotEmpty() && !s.equals("auto", ignoreCase = true)) {
                val host: String
                val port: Int
                if (s.contains(':')) {
                    host = s.substringBeforeLast(':')
                    port = s.substringAfterLast(':').toIntOrNull() ?: 55225
                } else if (s.count { c -> c == '.' } == 4) {
                    host = s.substringBeforeLast('.')
                    port = s.substringAfterLast('.').toIntOrNull() ?: 55225
                } else {
                    host = s
                    port = 55225
                }
                if (port in 1..65535 && host.isNotEmpty()) {
                    // createUnresolved avoids blocking DNS lookups on the main thread (prevents NetworkOnMainThreadException)
                    hubAddr = InetSocketAddress.createUnresolved(host, port)
                }
            } else {
                hubAddr = null
            }
        }
        dnsServer = intent.getStringExtra(EXTRA_DNS) ?: dnsServer
        searchDomain = intent.getStringExtra(EXTRA_SEARCH_DOMAIN)
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
        if (hubFp.isEmpty()) {
            hubFp = "auto"
        }
        if (ptr == 0L) {
            ptr = GhostCore.init(hubFp)
            if (ptr == 0L) { shutdown(); stopSelf(); return START_NOT_STICKY }
            activePtr = ptr
        }
        Thread {
            startTunnel()
        }.start()
        return START_NOT_STICKY
    }

    @Synchronized
    private fun startTunnel(network: Network? = null) {
        val targetNetwork = network ?: activeNetwork ?: if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) cm.activeNetwork else null
        activeNetwork = targetNetwork

        stopPumps()
        try { channel?.close() } catch (_: Throwable) {}
        try { tun?.close() } catch (_: Throwable) {}
        channel = null; tun = null

        val fpHex = try { GhostCore.getFingerprint(ptr) } catch (_: Throwable) { "" }
        val hostByte = ((fpHex.take(4).toIntOrNull(16) ?: 10) % 240) + 10

        // 1. TUN: IPv4 overlay IP (10.66.0.x/24) + Default Route (0.0.0.0/0) + Dynamic/Mesh DNS.
        // Do NOT assign an IPv6 address to tun0: VpnHub is an IPv4 NAT/netstack, and assigning
        // fd00:66::10 causes Android netd to prefer AAAA (IPv6) lookups and blackhole traffic.
        val builder = Builder()
            .setSession("Vantablack Mesh")
            .addAddress("10.66.0.$hostByte", 24)
            .addRoute("0.0.0.0", 0)        // Encapsulate ALL IPv4 internet traffic into mesh tunnel
            .addRoute("10.66.0.0", 24)     // Mesh overlay network
            .setMtu(1280)
            .setBlocking(true)

        // IPv6 Leak Prevention: Trap all IPv6 traffic inside the TUN interface
        // Combined with the Hub's AAAA NODATA responder, this ensures dual-stack clients never leak IPv6
        try {
            builder.addAddress("fd00:66::1", 128)
            builder.addRoute("::", 0)
        } catch (_: Throwable) {}

        val customDns = dnsServer.trim()
        val addedCustomDns = ArrayList<String>()
        if (customDns.isNotEmpty() && !customDns.equals("auto", ignoreCase = true)) {
            for (part in customDns.split(",", " ", ";")) {
                val candidate = part.trim()
                if (candidate.isNotEmpty()) {
                    try {
                        builder.addDnsServer(candidate)
                        addedCustomDns.add(candidate)
                    } catch (_: Throwable) {}
                }
            }
        }
        if (addedCustomDns.isEmpty()) {
            // Strictly tunnel all DNS lookups to the Mesh Exit Node overlay resolver (10.66.0.1)
            // No direct external DNS IPs are passed to Android netd, ensuring zero ISP leaks
            builder.addDnsServer("10.66.0.1")
            activeDnsDisplay = "Auto (Mesh 10.66.0.1)"
        } else {
            if (!addedCustomDns.contains("10.66.0.1")) {
                try { builder.addDnsServer("10.66.0.1") } catch (_: Throwable) {}
            }
            activeDnsDisplay = addedCustomDns.joinToString(", ")
        }

        searchDomain?.let { builder.addSearchDomain(it) }

        tun = builder.establish()
        val tunFd = tun?.fd ?: run { stopSelf(); return }

        // 2. Outer UDP socket: bind to standard mesh port 55225 (with fallback), enable broadcast, and PROTECT.
        // Do NOT call network.bindSocket(ch.socket()) — on dual-SIM/cellular+Wi-Fi devices, explicit
        // netId fwmark binding bypasses Android's local_network table (rule 20000) and forces LAN
        // packets out cellular (ccmni). VpnService.protect() alone sets fwmark 0x20000 so both LAN
        // (wlan0) and default WAN routes work seamlessly.
        val ch = DatagramChannel.open()
        ch.configureBlocking(true)
        ch.socket().broadcast = true
        ch.socket().reuseAddress = true
        try {
            ch.socket().receiveBufferSize = 4 * 1024 * 1024
            ch.socket().sendBufferSize = 4 * 1024 * 1024
        } catch (_: Throwable) {}
        try {
            ch.socket().bind(InetSocketAddress(java.net.InetAddress.getByName("0.0.0.0"), 55225))
        } catch (_: Throwable) {
            try {
                ch.socket().bind(InetSocketAddress("0.0.0.0", 55225))
            } catch (_: Throwable) {
                ch.socket().bind(null)
            }
        }
        protect(ch.socket()) // protect BEFORE send: no packet may ever leave unprotected
        val sockFd = ParcelFileDescriptor.fromDatagramSocket(ch.socket()).detachFd()
        protect(sockFd)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            setUnderlyingNetworks(if (targetNetwork != null) arrayOf(targetNetwork) else null)
        }
        channel = ch

        // 3. Native core takes both fds.
        val hubAddrStr = if (hubAddr != null) {
            val h = hubAddr as InetSocketAddress
            if (h.isUnresolved) {
                "${h.hostName}:${h.port}"
            } else {
                "${h.address?.hostAddress ?: h.hostName}:${h.port}"
            }
        } else {
            "auto"
        }
        currentHubAddr = hubAddrStr
        if (!GhostCore.start(ptr, tunFd, sockFd, hubAddrStr)) {
            stopSelf(); return
        }
        try {
            val active = GhostCore.getActiveHub(ptr)
            if (active.isNotEmpty()) currentHubAddr = active
        } catch (_: Throwable) {}

        // 4. Pumps: TUN→mesh and mesh→TUN (map the desktop binary's pumps).
        running = true
        isRunning = true
        activeNetwork = targetNetwork
        pumpThread = Thread {
            while (running) {
                try { GhostCore.pump(ptr) } catch (_: Throwable) { break }
            }
        }.apply { name = "ggn-pump"; start() }
        drainThread = Thread {
            while (running) {
                try { GhostCore.drain(ptr) } catch (_: Throwable) { break }
            }
        }.apply { name = "ggn-drain"; start() }

        // 5. Bootstrap sync: continuously register with Cloudflare Worker tracker, sweep LAN, and connect to known peers
        bootstrapThread = Thread {
            while (running) {
                try {
                    // 1. Run local Wi-Fi LAN discovery sweep whenever tunnel is not healthy
                    try {
                        GhostCore.scanLan(ptr)
                    } catch (_: Throwable) {}

                    // 2. Sync with Cloudflare Worker tracker
                    val fp = try { GhostCore.getFingerprint(ptr) } catch (_: Throwable) { "" }
                    val lanIp = getLocalIpAddress()
                    val selfEndpoint = if (lanIp.isNotEmpty() && lanIp != "127.0.0.1") "$lanIp:55225" else ""
                    val peers = fetchBootstrapPeers(activeNetwork, fp, lanIp)
                    for (peer in peers) {
                        if (!running) break
                        if (peer == selfEndpoint) continue
                        try {
                            GhostCore.connectPeer(ptr, peer)
                        } catch (_: Throwable) {}
                    }
                    try {
                        val active = GhostCore.getActiveHub(ptr)
                        currentHubAddr = if (active.isNotEmpty()) active else "auto"
                        val known = GhostCore.getKnownPeers(ptr)
                            .split(",")
                            .map { it.trim() }
                            .filter { it.isNotEmpty() }
                        discoveredPeersList = known
                    } catch (_: Throwable) {}
                } catch (_: Throwable) {}

                // Sync and beacon every 15 seconds
                for (i in 0 until 15) {
                    if (!running) break
                    try { Thread.sleep(1000) } catch (_: Throwable) { break }
                }
            }
        }.apply { name = "ggn-bootstrap"; start() }
    }

    private val handoverCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val caps = cm.getNetworkCapabilities(network) ?: return
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return

            val currentCaps = activeNetwork?.let { cm.getNetworkCapabilities(it) }
            val currentIsWifi = currentCaps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            val newIsWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)

            // Do not let cellular onAvailable override an active Wi-Fi network
            if (activeNetwork != null && currentIsWifi && !newIsWifi) {
                return
            }

            if (activeNetwork != network) {
                activeNetwork = network
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    setUnderlyingNetworks(arrayOf(network))
                }
                channel?.socket()?.let { sock ->
                    protect(sock)
                }
            }
        }

        override fun onLost(network: Network) {
            if (activeNetwork == network) activeNetwork = null
        }
    }

    private fun stopPumps() {
        running = false
        // Close sockets and TUN file descriptor first so blocking native read/recv syscalls immediately unblock
        try { channel?.close() } catch (_: Throwable) {}
        try { tun?.close() } catch (_: Throwable) {}
        channel = null
        tun = null

        pumpThread?.interrupt()
        drainThread?.interrupt()
        bootstrapThread?.interrupt()
        pumpThread?.join(300)
        drainThread?.join(300)
        bootstrapThread?.join(300)
        pumpThread = null
        drainThread = null
        bootstrapThread = null
    }

    override fun onRevoke() {
        shutdown()
        stopSelf()
    }

    private fun startForegroundServiceNotification() {
        val channelId = "ggn-vpn"
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(channelId, "Vantablack VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val disconnectIntent = Intent(this, GhostVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingDisconnect = android.app.PendingIntent.getService(
            this, 1, disconnectIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
            else
                android.app.PendingIntent.FLAG_UPDATE_CURRENT
        )
        val openAppIntent = Intent(this, MainActivity::class.java)
        val pendingOpenApp = android.app.PendingIntent.getActivity(
            this, 0, openAppIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
            else
                android.app.PendingIntent.FLAG_UPDATE_CURRENT
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val notification = builder
            .setContentTitle("Vantablack")
            .setContentText("Secure mesh tunnel active")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentIntent(pendingOpenApp)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", pendingDisconnect)
            .setOngoing(true)
            .build()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(2270, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(2270, notification)
            }
        } catch (_: Throwable) {
            try { startForeground(2270, notification) } catch (_: Throwable) {}
        }
    }

    private fun shutdown() {
        running = false
        isRunning = false
        activeNetwork = null
        discoveredPeersList = emptyList()
        currentHubAddr = "auto"
        val p = activePtr
        activePtr = 0L
        ptr = 0L

        stopPumps()

        if (p != 0L) {
            try { GhostCore.destroy(p) } catch (_: Throwable) {}
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        } catch (_: Throwable) {}
    }

    override fun onDestroy() {
        try { cm.unregisterNetworkCallback(handoverCallback) } catch (_: Throwable) {}
        shutdown()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "dev.globalghost.net.START"
        const val ACTION_STOP = "dev.globalghost.net.STOP"
        const val EXTRA_HUB_FP = "hub_fp"
        const val EXTRA_HUB_ADDR = "hub_addr"
        const val EXTRA_DNS = "dns_server"
        const val EXTRA_SEARCH_DOMAIN = "search_domain"
        const val DEFAULT_BOOTSTRAP_URL =
            "https://red-star-512e.papababg02.workers.dev/peers?port=55225"
        @Volatile var isRunning = false
        @Volatile var activePtr: Long = 0L
        @Volatile var currentHubAddr: String = "auto"
        @Volatile var activeDnsDisplay: String = "Auto (Hub 10.66.0.1)"
        @Volatile var discoveredPeersList: List<String> = emptyList()

        fun isVpnActive(context: android.content.Context): Boolean {
            if (isRunning && activePtr != 0L) return true
            try {
                val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
                val activeNet = cm.activeNetwork ?: return false
                val caps = cm.getNetworkCapabilities(activeNet) ?: return false
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return isRunning || activePtr != 0L
                }
            } catch (_: Throwable) {}
            return false
        }

        fun getStats(): LongArray {
            val p = activePtr
            return if (p != 0L) {
                try { GhostCore.stats(p) } catch (_: Throwable) { LongArray(4) }
            } else LongArray(4)
        }

        fun getActiveExitNode(): String {
            val p = activePtr
            if (p != 0L) {
                try {
                    val nativeHub = GhostCore.getActiveHub(p)
                    if (nativeHub.isNotEmpty()) {
                        currentHubAddr = nativeHub
                        return nativeHub
                    } else {
                        currentHubAddr = "auto"
                    }
                } catch (_: Throwable) {}
            }
            return if (currentHubAddr.isNotEmpty() && currentHubAddr != "auto") currentHubAddr else {
                discoveredPeersList.firstOrNull() ?: "Auto-Discovering..."
            }
        }

        fun getDiscoveredPeers(): List<String> {
            val p = activePtr
            if (p != 0L) {
                try {
                    val known = GhostCore.getKnownPeers(p)
                        .split(",")
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                    discoveredPeersList = known
                } catch (_: Throwable) {}
            }
            return discoveredPeersList
        }

        fun selectExitNode(peerAddr: String, onResult: ((Boolean) -> Unit)? = null) {
            val p = activePtr
            if (p != 0L) {
                Thread {
                    val ok = try {
                        GhostCore.selectHub(p, peerAddr)
                    } catch (_: Throwable) {
                        false
                    }
                    if (ok) {
                        currentHubAddr = peerAddr
                    }
                    onResult?.invoke(ok)
                }.start()
            } else {
                onResult?.invoke(false)
            }
        }

        fun getLocalIpAddress(): String {
            var fallback: String? = null
            try {
                val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
                while (interfaces.hasMoreElements()) {
                    val iface = interfaces.nextElement()
                    val name = iface.name?.lowercase(java.util.Locale.US) ?: ""
                    if (iface.isLoopback || !iface.isUp || iface.isPointToPoint || iface.isVirtual) continue
                    if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("ccmni") ||
                        name.startsWith("rmnet") || name.startsWith("dummy") || name.startsWith("clat") ||
                        name.startsWith("v4-")) continue
                    val addrs = iface.inetAddresses
                    while (addrs.hasMoreElements()) {
                        val addr = addrs.nextElement()
                        if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                            val host = addr.hostAddress ?: continue
                            if (host.startsWith("127.") || host.startsWith("169.254.") || host.startsWith("10.66.0.")) continue
                            if (name.startsWith("wlan") || name.startsWith("eth") || name.startsWith("ap") || name.startsWith("rndis")) {
                                return host
                            }
                            if (fallback == null) fallback = host
                        }
                    }
                }
            } catch (_: Throwable) {}
            return fallback ?: "127.0.0.1"
        }

        fun fetchBootstrapPeers(network: Network? = null, fp: String = "", lanIp: String = ""): List<String> {
            return try {
                val sb = java.lang.StringBuilder(DEFAULT_BOOTSTRAP_URL)
                if (fp.isNotEmpty()) {
                    sb.append("&id=").append(fp)
                }
                if (lanIp.isNotEmpty() && lanIp != "127.0.0.1") {
                    sb.append("&lan=").append(lanIp).append(":55225")
                }
                val url = java.net.URL(sb.toString())
                val conn = (network?.openConnection(url) ?: url.openConnection()) as java.net.HttpURLConnection
                conn.connectTimeout = 4000
                conn.readTimeout = 4000
                conn.requestMethod = "GET"
                conn.setRequestProperty("User-Agent", "Vantablack-Android")
                if (conn.responseCode in 200..299) {
                    val text = conn.inputStream.bufferedReader().readText()
                    val regex = Regex("\"([^\"]+)\"")
                    regex.findAll(text).map { it.groupValues[1] }.toList()
                } else {
                    emptyList()
                }
            } catch (_: Throwable) {
                emptyList()
            }
        }

        fun triggerScan(onComplete: ((Int) -> Unit)? = null) {
            val p = activePtr
            if (p != 0L) {
                Thread {
                    // 1. Run local Wi-Fi LAN discovery
                    val count = try {
                        GhostCore.scanLan(p)
                    } catch (_: Throwable) {
                        0
                    }

                    // 2. Sync with Cloudflare Worker bootstrap tracker
                    try {
                        val fp = try { GhostCore.getFingerprint(p) } catch (_: Throwable) { "" }
                        val lanIp = getLocalIpAddress()
                        val selfEndpoint = if (lanIp.isNotEmpty() && lanIp != "127.0.0.1") "$lanIp:55225" else ""
                        val peers = fetchBootstrapPeers(null, fp, lanIp)
                        for (peer in peers) {
                            if (peer == selfEndpoint) continue
                            try {
                                GhostCore.connectPeer(p, peer)
                            } catch (_: Throwable) {}
                        }
                        val active = GhostCore.getActiveHub(p)
                        if (active.isNotEmpty()) currentHubAddr = active
                    } catch (_: Throwable) {}

                    val totalPeers = try { getDiscoveredPeers().size.coerceAtLeast(count) } catch (_: Throwable) { count }
                    onComplete?.invoke(totalPeers)
                }.start()
            } else {
                onComplete?.invoke(0)
            }
        }

        fun getFingerprint(): String {
            val p = activePtr
            return if (p != 0L) GhostCore.getFingerprint(p) else ""
        }

        fun getPeersCount(): Int {
            val p = activePtr
            return if (p != 0L) GhostCore.getPeersCount(p) else 0
        }
    }
}
