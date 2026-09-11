package dev.globalghost.net

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.nio.channels.DatagramChannel

/**
 * The Android VPN service. Wires the Rust core (GhostCore) to VpnService:
 * configures the TUN, creates + protects the outer UDP socket, and restarts
 * the pumps on network changes (Wi-Fi → LTE handover) without dropping the
 * tunnel state — the hub-side re-anchor ladder makes the 5-tuple change
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

    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }

    override fun onCreate() {
        super.onCreate()
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
            hubAddr = InetSocketAddress(it.substringBeforeLast(':'), it.substringAfterLast(':').toInt())
        }
        if (hubFp.isEmpty()) { stopSelf(); return START_NOT_STICKY }
        if (ptr == 0L) {
            ptr = GhostCore.init(hubFp)
            if (ptr == 0L) { stopSelf(); return START_NOT_STICKY }
        }
        if (!running) startTunnel()
        return START_STICKY
    }

    private fun startTunnel() {
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
            .addDnsServer("192.168.1.1")
            .addSearchDomain("fritz.box")
            .setMtu(1280)
            .establish()
        val tunFd = tun?.fd ?: run { stopSelf(); return }

        // 2. Outer socket: create, PROTECT (mandatory — without it the mesh
        //    traffic loops back into the TUN), connect to the hub.
        val ch = DatagramChannel.open()
        ch.configureBlocking(true)
        ch.socket().bind(null)
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

        // 4. Pumps: TUN→mesh and mesh→TUN (map the desktop binary's pumps).
        running = true
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
            // New network: rebuild the socket + re-protect. TUN fd, epoch,
            // lease and pump state survive; the Rust core re-anchors the hub
            // endpoint from the first authenticated packet (window advance).
            if (running) startTunnel()
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

    override fun onRevoke() { shutdown() }

    private fun shutdown() {
        stopPumps()
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
    }
}
