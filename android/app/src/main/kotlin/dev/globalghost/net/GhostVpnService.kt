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
        hubFp = intent?.getStringExtra(EXTRA_HUB_FP)?.trim() ?: hubFp
        intent?.getStringExtra(EXTRA_HUB_ADDR)?.trim()?.let {
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
        dnsServer = intent?.getStringExtra(EXTRA_DNS) ?: dnsServer
        searchDomain = intent?.getStringExtra(EXTRA_SEARCH_DOMAIN)
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
        if (hubFp.isEmpty()) {
            hubFp = "auto"
        }
        if (ptr == 0L) {
            ptr = GhostCore.init(hubFp)
            if (ptr == 0L) { stopSelf(); return START_NOT_STICKY }
            activePtr = ptr
        }
        if (!running) {
            Thread {
                startTunnel()
            }.start()
        }
        return START_STICKY
    }

    @Synchronized
    private fun startTunnel(network: Network? = null) {
        val targetNetwork = network ?: activeNetwork ?: if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) cm.activeNetwork else null
        activeNetwork = targetNetwork

        stopPumps()
        try { channel?.close() } catch (_: Throwable) {}
        try { tun?.close() } catch (_: Throwable) {}
        channel = null; tun = null

        // 1. TUN: overlay IP (10.66.0.0/24) + Default Route (0.0.0.0/0) + Zero-Leak Encrypted DNS
        val builder = Builder()
            .setSession("Vantablack Mesh")
            .addAddress("10.66.0.10", 24)
            .addRoute("0.0.0.0", 0)        // Encapsulate ALL IPv4 internet traffic into mesh tunnel
            .addRoute("10.66.0.0", 24)     // Mesh overlay network
            .addDnsServer("1.1.1.1")       // Cloudflare Privacy-Preserving DNS
            .addDnsServer("9.9.9.9")       // Quad9 Encapsulated Privacy DNS
            .addDnsServer("10.66.0.1")     // Mesh Exit Node Resolver
            .setMtu(1280)
            .setBlocking(true)

        // Block IPv6 leakage through local ISP router
        try {
            builder.addAddress("fd00:66::10", 64)
            builder.addRoute("::", 0)
        } catch (_: Throwable) {
            // IPv6 route fallback if unsupported on host
        }

        if (dnsServer.isNotEmpty() && dnsServer != "10.66.0.1" && dnsServer != "1.1.1.1" && dnsServer != "9.9.9.9") {
            try {
                builder.addDnsServer(dnsServer)
            } catch (_: Throwable) {}
        }
        searchDomain?.let { builder.addSearchDomain(it) }

        tun = builder.establish()
        val tunFd = tun?.fd ?: run { stopSelf(); return }

        // 2. Outer UDP socket: bind to standard mesh port 55225 (with fallback), enable broadcast, and PROTECT.
        val ch = DatagramChannel.open()
        ch.configureBlocking(true)
        ch.socket().broadcast = true
        ch.socket().reuseAddress = true
        try {
            ch.socket().bind(InetSocketAddress(java.net.InetAddress.getByName("0.0.0.0"), 55225))
        } catch (_: Throwable) {
            try {
                ch.socket().bind(InetSocketAddress("0.0.0.0", 55225))
            } catch (_: Throwable) {
                ch.socket().bind(null)
            }
        }
        targetNetwork?.let {
            try { it.bindSocket(ch.socket()) } catch (_: Throwable) { /* best effort on older OEMs */ }
        }
        protect(ch.socket()) // protect BEFORE send: no packet may ever leave unprotected
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            setUnderlyingNetworks(if (targetNetwork != null) arrayOf(targetNetwork) else null)
        }
        val sockFd = ParcelFileDescriptor.fromDatagramSocket(ch.socket()).detachFd()
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

        // 4. Pumps: TUN→mesh and mesh→TUN (map the desktop binary's pumps).
        running = true
        isRunning = true
        activeNetwork = network
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
                    // 1. Run local Wi-Fi LAN discovery sweep only if no designated hub is configured
                    if (currentHubAddr == "auto" || currentHubAddr.isEmpty()) {
                        try {
                            GhostCore.scanLan(ptr)
                        } catch (_: Throwable) {}
                    }

                    // 2. Sync with Cloudflare Worker tracker
                    val fp = try { GhostCore.getFingerprint(ptr) } catch (_: Throwable) { "" }
                    val lanIp = getLocalIpAddress()
                    val peers = fetchBootstrapPeers(activeNetwork, fp, lanIp)
                    val activeList = ArrayList<String>()
                    for (peer in peers) {
                        if (!running) break
                        activeList.add(peer)
                        // Only auto-connect to tracker peers if we don't have a designated hub
                        if (peer != currentHubAddr && (currentHubAddr == "auto" || currentHubAddr.isEmpty())) {
                            try {
                                GhostCore.connectPeer(ptr, peer)
                            } catch (_: Throwable) {}
                        }
                    }
                    if (activeList.isNotEmpty()) {
                        discoveredPeersList = activeList
                        if (currentHubAddr == "auto" || currentHubAddr.isEmpty()) {
                            currentHubAddr = activeList.first()
                        }
                    }
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

            if (activeNetwork == null) {
                activeNetwork = network
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    setUnderlyingNetworks(arrayOf(network))
                }
                return
            }

            // Real physical interface handover (e.g. Wi-Fi <-> Cellular transition).
            // Re-bind and protect the existing UDP socket to the new physical interface.
            // Do NOT tear down the TUN or reset the session keys.
            if (running && activeNetwork != network) {
                activeNetwork = network
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    setUnderlyingNetworks(arrayOf(network))
                }
                channel?.socket()?.let { sock ->
                    try { network.bindSocket(sock) } catch (_: Throwable) {}
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
        pumpThread?.interrupt()
        drainThread?.interrupt()
        bootstrapThread?.interrupt()
        pumpThread?.join(500)
        drainThread?.join(500)
        bootstrapThread?.join(500)
        pumpThread = null
        drainThread = null
        bootstrapThread = null
    }

    override fun onRevoke() { shutdown(); stopSelf() }

    private fun startForegroundServiceNotification() {
        val channelId = "ggn-vpn"
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(channelId, "Vantablack VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val notification = Notification.Builder(this, channelId)
            .setContentTitle("Vantablack")
            .setContentText("Secure mesh tunnel active")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
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
        stopPumps()
        running = false
        isRunning = false
        activeNetwork = null
        try { channel?.close() } catch (_: Throwable) {}
        try { tun?.close() } catch (_: Throwable) {}
        if (ptr != 0L) { GhostCore.destroy(ptr); ptr = 0 }
        activePtr = 0L
    }

    override fun onDestroy() {
        try { cm.unregisterNetworkCallback(handoverCallback) } catch (_: Throwable) {}
        shutdown()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_HUB_FP = "hub_fp"
        const val EXTRA_HUB_ADDR = "hub_addr"
        const val EXTRA_DNS = "dns_server"
        const val EXTRA_SEARCH_DOMAIN = "search_domain"
        const val DEFAULT_BOOTSTRAP_URL =
            "https://red-star-512e.papababg02.workers.dev/peers?port=55225"
        @Volatile var isRunning = false
        @Volatile var activePtr: Long = 0L
        @Volatile var currentHubAddr: String = "auto"
        @Volatile var discoveredPeersList: List<String> = emptyList()

        fun getStats(): LongArray {
            val p = activePtr
            return if (p != 0L) {
                try { GhostCore.stats(p) } catch (_: Throwable) { LongArray(4) }
            } else LongArray(4)
        }

        fun getActiveExitNode(): String {
            return if (currentHubAddr.isNotEmpty() && currentHubAddr != "auto") currentHubAddr else {
                discoveredPeersList.firstOrNull() ?: "Auto-Discovering..."
            }
        }

        fun getDiscoveredPeers(): List<String> {
            return discoveredPeersList
        }

        fun getLocalIpAddress(): String {
            try {
                val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
                while (interfaces.hasMoreElements()) {
                    val iface = interfaces.nextElement()
                    if (iface.isLoopback || !iface.isUp) continue
                    val addrs = iface.inetAddresses
                    while (addrs.hasMoreElements()) {
                        val addr = addrs.nextElement()
                        if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                            val host = addr.hostAddress
                            if (host != null && !host.startsWith("127.") && !host.startsWith("169.254.")) {
                                return host
                            }
                        }
                    }
                }
            } catch (_: Throwable) {}
            return "127.0.0.1"
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
                        val peers = fetchBootstrapPeers(null, fp, lanIp)
                        for (peer in peers) {
                            try {
                                GhostCore.connectPeer(p, peer)
                            } catch (_: Throwable) {}
                        }
                    } catch (_: Throwable) {}

                    onComplete?.invoke(count)
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
