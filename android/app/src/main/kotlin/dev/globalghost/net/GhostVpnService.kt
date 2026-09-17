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
    private var hubAddr: SocketAddress = InetSocketAddress("192.0.2.1", 0)
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
        hubFp = intent?.getStringExtra(EXTRA_HUB_FP) ?: hubFp
        intent?.getStringExtra(EXTRA_HUB_ADDR)?.let {
            val host = it.substringBeforeLast(':')
            val port = it.substringAfterLast(':').toIntOrNull() ?: 0
            if (port in 1..65535) hubAddr = InetSocketAddress(host, port)
        }
        dnsServer = intent?.getStringExtra(EXTRA_DNS) ?: dnsServer
        searchDomain = intent?.getStringExtra(EXTRA_SEARCH_DOMAIN)
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
        if (hubFp.isEmpty()) { stopSelf(); return START_NOT_STICKY }
        if (ptr == 0L) {
            ptr = GhostCore.init(hubFp)
            if (ptr == 0L) { stopSelf(); return START_NOT_STICKY }
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

        // 1. TUN: overlay IP + routes for the home LAN + DNS. MTU 1280 must
        //    match AndroidTun::mtu() in the Rust core.
        tun = Builder()
            .setSession("GGN LAN-over-WAN")
            .addAddress("10.66.0.10", 24)
            .addRoute("192.168.1.0", 24)   // the home LAN
            .addRoute("10.66.0.0", 24)     // the overlay itself
            .addDnsServer(dnsServer)
            .apply { searchDomain?.let { addSearchDomain(it) } }
            .setMtu(1280)
            .establish()
        val tunFd = tun?.fd ?: run { stopSelf(); return }

        // 2. Outer socket: create, PROTECT (mandatory â€” without it the mesh
        //    traffic loops back into the TUN), connect to the hub.
        val ch = DatagramChannel.open()
        ch.configureBlocking(true)
        ch.socket().bind(null)
        // Bind to the callback's network before protect/connect. This prevents
        // Android from silently moving the protected socket back to Wi-Fi after
        // a Wi-Fi -> LTE transition.
        network?.let {
            try { it.bindSocket(ch.socket()) } catch (_: Throwable) { /* best effort on older OEMs */ }
        }
        protect(ch.socket()) // protect BEFORE connect: no packet may ever leave unprotected
        ch.connect(hubAddr)
        val sockFd = ParcelFileDescriptor.fromDatagramSocket(ch.socket()).detachFd()
        channel = ch

        // 3. Native core takes both fds.
        val hubAddrStr = (hubAddr as InetSocketAddress).let {
            "${it.address?.hostAddress ?: it.hostName}:${it.port}"
        }
        if (!GhostCore.start(ptr, tunFd, sockFd, hubAddrStr)) {
            stopSelf(); return
        }

        // 4. Pumps: TUNâ†’mesh and meshâ†’TUN (map the desktop binary's pumps).
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
                NotificationChannel(channelId, "Global Ghost Net VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val notification = Notification.Builder(this, channelId)
            .setContentTitle("Global Ghost Net")
            .setContentText("Secure mesh tunnel active")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .build()
        startForeground(2270, notification)
    }

    private fun shutdown() {
        stopPumps()
        isRunning = false
        activeNetwork = null
        try { channel?.close() } catch (_: Throwable) {}
        try { tun?.close() } catch (_: Throwable) {}
        if (ptr != 0L) { GhostCore.destroy(ptr); ptr = 0 }
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
    }
}
