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
    external fun init(hubFingerprint: String): Long

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
}
