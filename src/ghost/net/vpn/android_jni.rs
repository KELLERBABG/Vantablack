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

use super::client::{open_to_tun, seal_from_tun, ClientState};
use super::tun::TunDevice;
use super::VpnIngress;
use crate::ghost::layers::l0_identity::GhostIdentity;
use crate::ghost::layers::l1_kem::{
    build_handshake_pdu, compute_session_hash, derive_hybrid_master_key, generate_kyber_keypair,
    generate_x25519_keypair, parse_response_pdu, RESPONSE_BLOB_LEN,
};
use crate::ghost::layers::l2_aead::{
    decrypt_in_place_with_context, encrypt_in_place_with_context, NonceDirection,
};
use crate::ghost::layers::l4_rs;
use crate::ghost::net::{
    build_gtf_frame, frame_shard, parse_flags, parse_packet_counter, unframe,
    BULK_OFFSET_AUTH_TAG_START, BULK_OFFSET_PAYLOAD_START, MIN_FRAME_SIZE, OFFSET_AUTH_TAG_START,
    OFFSET_FLAGS, OFFSET_PAYLOAD_START, OFFSET_SHARD_INDEX,
};
use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, MlKem512};
use parking_lot::Mutex;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use x25519_dalek::PublicKey;

// ── TUN over a VpnService fd ─────────────────────────────────────────

use std::ffi::c_void;

extern "C" {
    fn read(fd: i32, buf: *mut c_void, len: usize) -> isize;
    fn write(fd: i32, buf: *const c_void, len: usize) -> isize;
}

/// TUN device backed by the fd returned by `VpnService.Builder.establish()`.
pub struct AndroidTun {
    fd: i32,
    running: Arc<AtomicBool>,
}

unsafe impl Send for AndroidTun {}
unsafe impl Sync for AndroidTun {}

impl AndroidTun {
    pub fn from_fd(fd: i32) -> Self {
        Self {
            fd,
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl TunDevice for AndroidTun {
    fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { write(self.fd, buf.as_ptr() as *const c_void, buf.len()) };
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

// ── Framing Helpers ──────────────────────────────────────────────────

const MAGIC: &[u8; 5] = crate::ghost::net::vpn::hub::VPN_PAYLOAD_MAGIC;

// `frame_shard` / `unframe` come from `ghost::net` (canonical);
// this module used to carry its own byte-identical copies.

fn tunnel_frame(
    key: &[u8; 32],
    sh: [u8; 4],
    ctr: u32,
    dir: NonceDirection,
    wire: &[u8],
) -> Vec<u8> {
    let mut payload = MAGIC.to_vec();
    payload.extend_from_slice(wire);
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&payload);
    if framed.len() % 2 != 0 {
        framed.push(0);
    }
    encrypt_in_place_with_context(key, ctr, &sh, dir, &mut framed);
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
    let framed = frame_shard(&framed);
    let mut frame = build_gtf_frame(sh, ctr, 0, &framed, &tag, true);
    frame[OFFSET_FLAGS] |= 0x02; // tunnel bit — receiver-side bypass marker
    frame
}

fn receiver_open(
    frame: &[u8],
    amt: usize,
    key: &[u8; 32],
    sh: [u8; 4],
    ctr: u32,
) -> Option<Vec<u8>> {
    let pe = BULK_OFFSET_AUTH_TAG_START.min(amt);
    if pe <= BULK_OFFSET_PAYLOAD_START {
        return None;
    }
    let b = &frame[BULK_OFFSET_PAYLOAD_START..pe];
    if b.len() < 2 {
        return None;
    }
    let l = u16::from_be_bytes([b[0], b[1]]) as usize;
    if l == 0 || 2 + l > b.len() {
        return None;
    }
    let mut msg = b[2..2 + l].to_vec();
    let ok = decrypt_in_place_with_context(
        key,
        ctr,
        &sh,
        NonceDirection::InitiatorToResponder,
        &mut msg,
    )
    .is_ok()
        || decrypt_in_place_with_context(
            key,
            ctr,
            &sh,
            NonceDirection::ResponderToInitiator,
            &mut msg,
        )
        .is_ok();
    if !ok {
        return None;
    }
    let n = u16::from_be_bytes([msg[0], msg[1]]) as usize;
    let payload = msg.get(2..2 + n)?;
    if payload.len() > MAGIC.len() && &payload[..5] == MAGIC {
        Some(payload[5..].to_vec())
    } else {
        None
    }
}

// ── Native Core Handle ───────────────────────────────────────────────

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
    pub identity: GhostIdentity,
    pub session_key: Mutex<Option<[u8; 32]>>,
    pub session_hash: Mutex<[u8; 4]>,
    pub tx_seq: AtomicU32,
}

unsafe impl Send for AndroidCore {}

fn perform_handshake(
    sock: &UdpSocket,
    hub_addr: std::net::SocketAddr,
    identity: &GhostIdentity,
) -> Option<([u8; 32], [u8; 4])> {
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));

    for _attempt in 0..4 {
        let (xs, xp) = generate_x25519_keypair();
        let (kp, ks) = generate_kyber_keypair();
        let pdu = build_handshake_pdu(
            &identity.public_key_bytes(),
            |d| identity.sign(d).to_bytes(),
            &xp,
            &kp,
        );
        let mut c = pdu;
        let raw = l4_rs::encode(&mut c);
        let tag = [0u8; 16];
        for i in 0..3 {
            let framed = frame_shard(&raw[i]);
            let gtf = build_gtf_frame([0, 0, 0, 0], 0, i as u8, &framed, &tag, false);
            let _ = sock.send_to(&gtf, hub_addr).or_else(|_| sock.send(&gtf));
        }

        let mut shards: Vec<Option<Vec<u8>>> = vec![None; 3];
        let mut buf = vec![0u8; 2048];
        let start = std::time::Instant::now();

        while start.elapsed() < Duration::from_millis(1000) {
            if let Ok((amt, _src)) = sock.recv_from(&mut buf).or_else(|_| sock.recv(&mut buf).map(|n| (n, hub_addr))) {
                if amt >= MIN_FRAME_SIZE {
                    let ctr = parse_packet_counter(&buf[..amt]);
                    if ctr == 1 {
                        let si = buf[OFFSET_SHARD_INDEX] as usize;
                        if si < 3 {
                            let pe = OFFSET_AUTH_TAG_START.min(amt);
                            if pe > OFFSET_PAYLOAD_START {
                                if let Some(sd) = unframe(&buf[OFFSET_PAYLOAD_START..pe]) {
                                    shards[si] = Some(sd);
                                }
                            }
                        }
                    }
                }
            }

            if shards.iter().filter(|s| s.is_some()).count() >= 2 {
                let m = shards
                    .iter()
                    .filter_map(|x| x.as_ref().map(|v| v.len()))
                    .max()
                    .unwrap_or(0);
                for ref mut v in shards.iter_mut().flatten() {
                    while v.len() < m {
                        v.push(0);
                    }
                }
                let mut w: Vec<_> = (0..3)
                    .map(|i| shards.get(i).and_then(|x| x.clone()))
                    .collect();
                if l4_rs::reconstruct(&mut w).is_ok() {
                    if let (Some(a), Some(b)) = (w[0].as_ref(), w[1].as_ref()) {
                        let resp_data = [a.as_slice(), b.as_slice()].concat();
                        if resp_data.len() >= RESPONSE_BLOB_LEN
                            && resp_data.starts_with(b"GHOST_RESPONSE__")
                        {
                            let mut rd = resp_data;
                            rd.truncate(RESPONSE_BLOB_LEN);
                            if let Some(resp) = parse_response_pdu(&rd) {
                                let ct = Ciphertext::<MlKem512>::from(resp.kyber_ct);
                                let ky_ss = ks.decapsulate(&ct);
                                let xs = xs.diffie_hellman(&PublicKey::from(resp.x25519_pub));
                                let d = derive_hybrid_master_key(xs.as_bytes(), ky_ss.as_slice());
                                let sh = compute_session_hash(&d);
                                let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
                                return Some((d, sh));
                            }
                        }
                    }
                }
            }
        }
    }

    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    None
}

/// One TUN→mesh step: read a packet from the TUN, seal it, wrap in GTF bulk frame,
/// and send via the protected socket to the hub.
pub fn pump_once(core: &mut AndroidCore, buf: &mut [u8]) {
    let (Some(tun), Some(sock), Some(hub)) = (core.tun.as_mut(), core.sock.as_ref(), core.hub_addr)
    else {
        return;
    };
    let Some(session_key) = *core.session_key.lock() else {
        std::thread::sleep(Duration::from_millis(50));
        return;
    };
    let session_hash = *core.session_hash.lock();

    match TunDevice::read_packet(tun, buf) {
        Ok(n) if n > 0 => {
            if let Some(wire) = seal_from_tun(&core.state, &buf[..n]) {
                let ctr = core.tx_seq.fetch_add(1, Ordering::Relaxed);
                let frame = tunnel_frame(
                    &session_key,
                    session_hash,
                    ctr,
                    NonceDirection::InitiatorToResponder,
                    &wire,
                );
                core.tx_ctr.fetch_add(1, Ordering::Relaxed);
                let _ = sock.send_to(&frame, hub).or_else(|_| sock.send(&frame));
            }
        }
        _ => {}
    }
}

/// One mesh→TUN step: recv a GTF datagram from hub, open it, and write the inner
/// IP packet into the TUN.
pub fn drain_once(core: &mut AndroidCore, buf: &mut [u8]) -> bool {
    let (Some(sock), Some(tun)) = (core.sock.as_ref(), core.tun.as_mut()) else {
        return false;
    };
    let Some(session_key) = *core.session_key.lock() else {
        std::thread::sleep(Duration::from_millis(50));
        return false;
    };
    let session_hash = *core.session_hash.lock();

    match sock.recv_from(buf).or_else(|_| sock.recv(buf).map(|n| (n, hub))) {
        Ok((n, src)) => {
            if Some(src) != core.hub_addr {
                return false;
            }
            if n < MIN_FRAME_SIZE {
                return false;
            }
            let ctr = parse_packet_counter(&buf[..n]);
            let flags = parse_flags(&buf[..n]);
            if flags & 0x02 == 0 {
                return false;
            }
            if let Some(wire) = receiver_open(&buf[..n], n, &session_key, session_hash, ctr) {
                let (accepted, _adv) = open_to_tun(&core.state, &wire, tun);
                if accepted {
                    core.rx_ctr.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
            false
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

// ── JNI Surface ──────────────────────────────────────────────────────

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
    let identity = GhostIdentity::generate_fresh();
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
        identity,
        session_key: Mutex::new(None),
        session_hash: Mutex::new([0u8; 4]),
        tx_seq: AtomicU32::new(2),
    });
    Box::into_raw(core) as jlong
}

/// `fun setSessionKey(ptr: Long, key: ByteArray)`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_setSessionKey(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    key: JByteArray,
) {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_ref() }) else {
        return;
    };
    let Ok(k) = env.convert_byte_array(&key) else {
        return;
    };
    if k.len() != 32 {
        throw(&mut env, "session key must be 32 bytes");
        return;
    }
    let arr: [u8; 32] = k.try_into().unwrap();
    core.state.set_key(arr);
    *core.session_key.lock() = Some(arr);
    *core.session_hash.lock() = compute_session_hash(&arr);
}

/// `fun start(ptr: Long, tunFd: Int, sockFd: Int, hubAddr: String): Boolean`
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
    let sock = Arc::new(unsafe { UdpSocket::from_raw_fd(sock_fd) });

    // Perform the post-quantum hybrid handshake directly on the protected socket
    if let Some((key, sh)) = perform_handshake(&sock, hub, &core.identity) {
        core.state.rotate_epoch();
        core.state.set_key(key);
        *core.session_key.lock() = Some(key);
        *core.session_hash.lock() = sh;
        core.tx_seq.store(2, Ordering::Relaxed);
    } else {
        // Handshake failed or pending
    }

    core.sock = Some(sock);
    1
}

/// `fun stats(ptr: Long): LongArray` — [rxPackets, txPackets, epoch, txCounter]
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_stats(
    env: JNIEnv,
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
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_mut() }) else {
        return;
    };
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
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_mut() }) else {
        return 0;
    };
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
