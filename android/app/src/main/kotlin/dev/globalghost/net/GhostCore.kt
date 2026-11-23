package dev.globalghost.net

/**
 * JNI binding to the Vantablack Rust core (libvantablack.so, built with
 * cargo-ndk --features vpn). One instance per VPN session; the ptr returned by
 * init() must be passed to every other call and released with destroy().
 *
 * Threading: call pump() from one dedicated thread and drain() from another —
 * they map to the desktop binary's TUN-pump and egress pumps. pump() blocks
 * on the TUN read; drain() blocks on the socket recv.
 */
object GhostCore {
    init {
        System.loadLibrary("vantablack")
    }

    /** Allocate the native core. Returns a raw pointer (0 on failure). */
    external fun init(hubFingerprint: String, storageDir: String): Long

    /** Adopt the hybrid session key (32 bytes) negotiated by the handshake. */
    external fun setSessionKey(ptr: Long, key: ByteArray)

    /**
     * Attach the TUN and the outer mesh socket.
     * @param tunFd  fd from VpnService.Builder.establish()
     * @param sockFd fd of a DatagramChannel/socket ALREADY protected via
     *               VpnService.protect() — without it the mesh traffic loops
     *               back into the TUN and dies instantly.
     * @param hubAddr hub endpoint "ip:port" (current, post-STUN)
     */
    external fun start(ptr: Long, tunFd: Int, sockFd: Int, hubAddr: String): Boolean

    /** [rxPackets, txPackets, epoch, txCounter] */
    external fun stats(ptr: Long): LongArray

    /** One TUN→mesh step (blocking TUN read). Loop on a pump thread. */
    external fun pump(ptr: Long)

    /** One mesh→TUN step (blocking socket recv). Loop on a drain thread. */
    external fun drain(ptr: Long): Boolean

    /** Free the native core. The fds remain owned by the JVM objects. */
    external fun destroy(ptr: Long)

    /** Retrieve this node's 8-byte hexadecimal identity fingerprint */
    external fun getFingerprint(ptr: Long): String

    /** Returns count of active authenticated peers (0 or 1) */
    external fun getPeersCount(ptr: Long): Int

    /** Triggers autonomous Wi-Fi broadcast discovery sweep */
    external fun scanLan(ptr: Long): Int

    /** Connect to an external peer endpoint (from bootstrap tracker or manual). */
    external fun connectPeer(ptr: Long, peerAddr: String): Boolean

    /** Explicitly switch the active exit hub to peerAddr. */
    external fun selectHub(ptr: Long, peerAddr: String): Boolean

    /** Return the currently active exit hub endpoint ("ip:port"), or "" if none. */
    external fun getActiveHub(ptr: Long): String

    /** Return comma-separated list of all authenticated peer endpoints ("ip:port,..."). */
    external fun getKnownPeers(ptr: Long): String

    /** Import a vb-net:// or vb://2. invite/descriptor via Rust PeerDescriptorV2 / BlindRendezvous. */
    external fun importInvite(ptr: Long, invite: String): String

    /** Configure the BlindRendezvous URL (GHOST_RENDEZVOUS_URL). */
    external fun setRendezvousUrl(ptr: Long, url: String)

    /** Return the active connection path: "Wi-Fi Direct LAN", "5G Direct ICE", or "5G via DERP Relay". */
    external fun getConnectionPath(ptr: Long): String

    /** Return live RTT in milliseconds to the active hub, or -1 if unknown. */
    external fun getRttMs(ptr: Long): Long

    /** Return the number of seamless network handovers (Wi-Fi <-> 5G) in this session. */
    external fun getHandoverCount(ptr: Long): Long

    /** Record a network handover event in native telemetry. */
    external fun recordHandover(ptr: Long)

    /** Swap the TUN file descriptor when upgrading from Local Ad-Shield to Full Tunnel. */
    external fun updateTun(ptr: Long, tunFd: Int)

    /** Enable or disable built-in DNS ad & tracker blocking. */
    external fun setAdblockEnabled(enabled: Boolean)

    /** Return total number of ad/tracker DNS queries blocked in this session. */
    external fun getAdsBlocked(): Long
}
