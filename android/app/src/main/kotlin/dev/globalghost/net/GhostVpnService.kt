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
        // Handover: re-bind + re-protect on any network change. The Rust core
        // is untouched; only startTunnel runs again with the new socket fd.
        cm.registerNetworkCallback(
            android.net.NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build(),
            handoverCallback
        )
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
    private fun startTunnel(network: Network? = activeNetwork) {
        stopPumps()
        try { channel?.close() } catch (_: Throwable) {}
        try { tun?.close() } catch (_: Throwable) {}
        channel = null; tun = null

        // 1. TUN: overlay IP (10.66.0.0/24) + DNS.
        // We do NOT add 192.168.x.x routes to the TUN so local Wi-Fi LAN traffic remains native and unhijacked.
        val builder = Builder()
            .setSession("Vantablack Mesh")
            .addAddress("10.66.0.10", 24)
            .addRoute("10.66.0.0", 24)     // the overlay itself
            .setMtu(1280)

        // Only register a DNS server if an explicit, valid non-overlay DNS was specified.
        if (dnsServer.isNotEmpty() && dnsServer != "10.66.0.1") {
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
            ch.socket().bind(InetSocketAddress(55225))
        } catch (_: Throwable) {
            ch.socket().bind(null)
        }
        network?.let {
            try { it.bindSocket(ch.socket()) } catch (_: Throwable) { /* best effort on older OEMs */ }
        }
        protect(ch.socket()) // protect BEFORE send: no packet may ever leave unprotected
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
    }

    private val handoverCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            // Prefer the newly available validated network. Rebuild only once
            // the callback supplies a different network; the TUN, epoch, lease,
            // and pumps remain alive while the Rust core re-anchors on the first
            // authenticated window-advancing packet.
            if (running && activeNetwork != network) startTunnel(network)
        }

        override fun onLost(network: Network) {
            if (activeNetwork == network) activeNetwork = null
        }
    }

    private fun stopPumps() {
        running = false
        pumpThread?.interrupt()
        drainThread?.interrupt()
        pumpThread?.join(500)
        drainThread?.join(500)
        pumpThread = null
        drainThread = null
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
        @Volatile var isRunning = false
        @Volatile var activePtr: Long = 0L

        fun triggerScan(onComplete: ((Int) -> Unit)? = null) {
            val p = activePtr
            if (p != 0L) {
                Thread {
                    val count = try {
                        GhostCore.scanLan(p)
                    } catch (_: Throwable) {
                        0
                    }
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
