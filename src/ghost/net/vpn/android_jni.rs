//! Android (M3): fd-based TUN + the JNI surface for the Kotlin VpnService.
//!
//! Compiled only on `target_os = "android"` — desktop builds never see this
//! module, so the v0.4.0/`vpn` surface is untouched. The Rust core (ClientState,
//! VpnIngress, pump logic) is the exact same code the desktop binary runs.
//!
//! Ownership model (mirrors WireGuard/Android conventions):
//! - **Kotlin owns the sockets it must protect.** `VpnService.protect(fd)` can
//!   only be called from the Java process, so the Kotlin layer creates the
//!   outer UDP DatagramChannel, protects it, and hands its fd to `start()`.
//!   Rust wraps that fd with `FromRawFd` and uses it for all mesh traffic.
//! - **Kotlin owns the TUN fd.** `VpnService.Builder.establish()` returns a
//!   `ParcelFileDescriptor`; its fd is handed to `start()` and wrapped in
//!   `AndroidTun` (a `TunDevice`).
//! - `destroy()` frees the native core. The fds themselves are closed by the
//!   JVM when the `ParcelFileDescriptor`/channel are closed on the Java side;
//!   Rust intentionally does not `close()` them (double-close hazards).

#![cfg(target_os = "android")]

use super::client::{seal_from_tun, ClientState};
use super::tun::TunDevice;
use super::VpnIngress;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

// ── TUN over a VpnService fd ─────────────────────────────────────────

extern "C" {
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
}

/// TUN device backed by the fd returned by `VpnService.Builder.establish()`.
/// The interface address/routes/DNS were configured by the Kotlin `Builder`
/// before `establish()` — nothing to set up here, unlike `/dev/net/tun`.
pub struct AndroidTun {
    fd: i32,
    running: Arc<AtomicBool>,
}

unsafe impl Send for AndroidTun {}
unsafe impl Sync for AndroidTun {}

impl AndroidTun {
    /// Wrap an fd obtained from `establish()`. Not closable from Rust by
    /// design (the JVM owns the descriptor).
    pub fn from_fd(fd: i32) -> Self {
        Self { fd, running: Arc::new(AtomicBool::new(true)) }
    }
}

impl TunDevice for AndroidTun {
    fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { read(self.fd, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { write(self.fd, buf.as_ptr(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn mtu(&self) -> u16 {
        1280 // must match VpnService.Builder.setMtu()
    }

    fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn name(&self) -> &str {
        "ggn0"
    }
}

// ── Native core handle ───────────────────────────────────────────────

/// Everything the JNI surface needs. Lives behind a `destroy()`-freed raw
/// pointer for the Java object's lifetime.
pub struct AndroidCore {
    pub state: Arc<ClientState>,
    pub ingress: Arc<VpnIngress>,
    pub tun: Option<AndroidTun>,
    pub sock: Option<Arc<UdpSocket>>,
    pub hub_addr: Option<std::net::SocketAddr>,
    pub hub_fp: String,
    pub stop: Arc<AtomicBool>,
    pub rx_ctr: Arc<AtomicU32>,
    pub tx_ctr: Arc<AtomicU32>,
}

unsafe impl Send for AndroidCore {}

/// One TUN→mesh step: read a packet from the TUN, seal it, send via the
/// protected socket. Unreliable datagrams (no ACK, no retransmit) — rule 1.
/// The JNI pump thread calls this in a loop.
pub fn pump_once(core: &mut AndroidCore, buf: &mut [u8]) {
    let (Some(tun), Some(sock), Some(hub)) =
        (core.tun.as_mut(), core.sock.as_ref(), core.hub_addr)
    else {
        return;
    };
    match TunDevice::read_packet(tun, buf) {
        Ok(n) if n > 0 => {
            if let Some(wire) = seal_from_tun(&core.state, &buf[..n]) {
                core.tx_ctr.fetch_add(1, Ordering::Relaxed);
                let _ = sock.send_to(&wire, hub);
            }
        }
        _ => {}
    }
}

/// One mesh→TUN step: recv a datagram, open it, write the IP packet into the
/// TUN. A rejected TUN write (kernel buffer full) drops the packet — inner
/// TCP retransmits; we never grow a queue here (rule 3). Returns true when a
/// packet was delivered.
pub fn drain_once(core: &mut AndroidCore, buf: &mut [u8]) -> bool {
    let (Some(sock), Some(tun)) = (core.sock.as_ref(), core.tun.as_mut()) else {
        return false;
    };
    match sock.recv_from(buf) {
        Ok((n, src)) => {
            if Some(src) != core.hub_addr {
                return false; // only the hub speaks tunnel datagrams
            }
            match core.ingress.open(
                &core.state.key(),
                &core.hub_fp,
                core.state.current_epoch(),
                &buf[..n],
            ) {
                super::OpenOutcome::Accepted { ip_packet, .. } => {
                    core.rx_ctr.fetch_add(1, Ordering::Relaxed);
                    let _ = TunDevice::write_packet(tun, &ip_packet);
                    true
                }
                _ => false,
            }
        }
        Err(_) => false,
    }
}

impl Drop for AndroidCore {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.tun.as_ref() {
            t.shutdown();
        }
    }
}

// ── JNI surface ──────────────────────────────────────────────────────
// Kotlin: dev.globalghost.net.GhostCore binds these natives.

#[allow(unused_imports)]
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jint, jlong, jlongArray};
use jni::JNIEnv;

fn throw(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("java/lang/IllegalStateException", msg);
}

/// `fun init(hubFingerprint: String): Long`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_init(
    mut env: JNIEnv,
    _class: JClass,
    hub_fp: JString,
) -> jlong {
    let fp: String = match env.get_string(&hub_fp) {
        Ok(s) => s.into(),
        Err(_) => {
            throw(&mut env, "bad fingerprint");
            return 0;
        }
    };
    if fp.is_empty() {
        throw(&mut env, "hub fingerprint required");
        return 0;
    }
    let core = Box::new(AndroidCore {
        state: Arc::new(ClientState::new(fp.clone(), [0u8; 32])),
        ingress: Arc::new(VpnIngress::new()),
        tun: None,
        sock: None,
        hub_addr: None,
        hub_fp: fp,
        stop: Arc::new(AtomicBool::new(false)),
        rx_ctr: Arc::new(AtomicU32::new(0)),
        tx_ctr: Arc::new(AtomicU32::new(0)),
    });
    Box::into_raw(core) as jlong
}

/// `fun setSessionKey(ptr: Long, key: ByteArray)` — adopted on handshake.
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_setSessionKey(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    key: JByteArray,
) {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_ref() }) else { return };
    let Ok(k) = env.convert_byte_array(&key) else { return };
    if k.len() != 32 {
        throw(&mut env, "session key must be 32 bytes");
        return;
    }
    core.state.set_key(k.try_into().unwrap());
}

/// `fun start(ptr: Long, tunFd: Int, sockFd: Int, hubAddr: String): Boolean`
/// Kotlin MUST have called `protect(sockFd)`. On network change: create a NEW
/// protected socket, call `stopPumps`, then `start` again with the new fd.
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_start(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    tun_fd: jint,
    sock_fd: jint,
    hub_addr: JString,
) -> jboolean {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_mut() }) else {
        throw(&mut env, "core not initialized");
        return 0;
    };
    let addr: String = match env.get_string(&hub_addr) {
        Ok(s) => s.into(),
        Err(_) => {
            throw(&mut env, "bad hub address");
            return 0;
        }
    };
    let Ok(hub) = addr.parse::<std::net::SocketAddr>() else {
        throw(&mut env, "hub address must be ip:port");
        return 0;
    };
    core.hub_addr = Some(hub);
    core.tun = Some(AndroidTun::from_fd(tun_fd));
    use std::os::fd::FromRawFd;
    core.sock = Some(Arc::new(unsafe { UdpSocket::from_raw_fd(sock_fd) }));
    1
}

/// `fun stats(ptr: Long): LongArray` — [rxPackets, txPackets, epoch, txCounter]
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_stats(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jlongArray {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_ref() }) else {
        return std::ptr::null_mut();
    };
    let vals: [jlong; 4] = [
        core.rx_ctr.load(Ordering::Relaxed) as jlong,
        core.tx_ctr.load(Ordering::Relaxed) as jlong,
        core.state.current_epoch() as jlong,
        core.state.tx_counter() as jlong,
    ];
    match env.new_long_array(4) {
        Ok(arr) => {
            let _ = env.set_long_array_region(&arr, 0, &vals);
            arr.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// `fun pump(ptr: Long)` — one TUN→mesh step (pump thread loop).
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_pump(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_mut() }) else { return };
    if core.stop.load(Ordering::Relaxed) {
        return;
    }
    let mut buf = vec![0u8; 2048];
    pump_once(core, &mut buf);
}

/// `fun drain(ptr: Long): Boolean` — one mesh→TUN step (drain thread loop).
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_drain(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jboolean {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_mut() }) else { return 0 };
    if core.stop.load(Ordering::Relaxed) {
        return 0;
    }
    let mut buf = vec![0u8; 2048];
    drain_once(core, &mut buf) as jboolean
}

/// `fun destroy(ptr: Long)`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_destroy(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    if ptr != 0 {
        drop(unsafe { Box::from_raw(ptr as *mut AndroidCore) });
    }
}
