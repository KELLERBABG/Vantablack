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
    fn __android_log_print(prio: i32, tag: *const u8, fmt: *const u8, ...) -> i32;
}

macro_rules! alog {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        let tag = b"GhostCore\0";
        let fmt = b"%s\0";
        let mut c_msg = msg.into_bytes();
        c_msg.push(0);
        unsafe {
            __android_log_print(4 /* INFO */, tag.as_ptr(), fmt.as_ptr(), c_msg.as_ptr());
        }
    };
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
    // 1. Support GTF v2 wire format from updated hubs
    if let Some(h) = crate::ghost::net::parse_gtf_v2_header(&frame[..amt]) {
        let tag_start = if h.bulk {
            amt.saturating_sub(16)
        } else {
            crate::ghost::net::V2_OFFSET_AUTH_TAG_START
        };
        if tag_start > crate::ghost::net::V2_OFFSET_PAYLOAD_START {
            let shard_bytes = &frame[crate::ghost::net::V2_OFFSET_PAYLOAD_START..tag_start];
            if let Some(msg) = unframe(shard_bytes) {
                let aad: &[u8] = if h.bulk { &[] } else { &h.tail };
                for dir in [
                    NonceDirection::ResponderToInitiator,
                    NonceDirection::InitiatorToResponder,
                ] {
                    let mut trial = msg.clone();
                    if crate::ghost::layers::l2_aead::xchacha_open_with_aad(
                        key, &h.nonce, h.epoch, dir, &mut trial, aad,
                    )
                    .is_ok()
                    {
                        if trial.len() >= 2 {
                            let n = u16::from_be_bytes([trial[0], trial[1]]) as usize;
                            if let Some(payload) = trial.get(2..2 + n) {
                                if payload.len() > MAGIC.len()
                                    && &payload[..MAGIC.len()] == MAGIC.as_slice()
                                {
                                    return Some(payload[MAGIC.len()..].to_vec());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. GTF v1 fallback
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
    let msg = b[2..2 + l].to_vec();
    let mut decrypted = None;
    for dir in [
        NonceDirection::ResponderToInitiator,
        NonceDirection::InitiatorToResponder,
    ] {
        let mut trial = msg.clone();
        if decrypt_in_place_with_context(key, ctr, &sh, dir, &mut trial).is_ok() {
            decrypted = Some(trial);
            break;
        }
    }
    let Some(decrypted_msg) = decrypted else {
        alog!(
            "receiver_open: GTF v1 decrypt failed (ctr={}, amt={})",
            ctr,
            amt
        );
        return None;
    };
    if decrypted_msg.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([decrypted_msg[0], decrypted_msg[1]]) as usize;
    let payload = decrypted_msg.get(2..2 + n)?;
    if payload.len() > MAGIC.len() && &payload[..MAGIC.len()] == MAGIC.as_slice() {
        alog!(
            "receiver_open: GTF v1 frame decrypted! wire_len={}",
            payload.len() - MAGIC.len()
        );
        Some(payload[MAGIC.len()..].to_vec())
    } else {
        alog!("receiver_open: bad magic prefix in decrypted payload");
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
    pub known_peers: Mutex<std::collections::HashMap<std::net::SocketAddr, ([u8; 32], [u8; 4])>>,
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
            if let Ok((amt, _src)) = sock
                .recv_from(&mut buf)
                .or_else(|_| sock.recv(&mut buf).map(|n| (n, hub_addr)))
            {
                if amt >= MIN_FRAME_SIZE {
                    let ctr = parse_packet_counter(&buf[..amt]);
                    if ctr == 1 {
                        let si = buf[OFFSET_SHARD_INDEX] as usize;
                        if si < 3 {
                            let is_bulk = buf[OFFSET_FLAGS] & 0x01 != 0;
                            let pe = if is_bulk {
                                BULK_OFFSET_AUTH_TAG_START.min(amt)
                            } else {
                                OFFSET_AUTH_TAG_START.min(amt)
                            };
                            let ps = if is_bulk {
                                BULK_OFFSET_PAYLOAD_START
                            } else {
                                OFFSET_PAYLOAD_START
                            };
                            if pe > ps {
                                if let Some(sd) = unframe(&buf[ps..pe]) {
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

fn perform_lan_discovery(
    sock: &UdpSocket,
    identity: &GhostIdentity,
) -> Vec<(std::net::SocketAddr, [u8; 32], [u8; 4])> {
    let _ = sock.set_broadcast(true);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(150)));

    let xs = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let xp = x25519_dalek::PublicKey::from(&xs);
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

    let mut subnets: Vec<[u8; 3]> = Vec::new();

    // Dynamically detect local LAN subnets
    for common in &[[192, 168, 178], [192, 168, 1], [192, 168, 0], [10, 0, 0]] {
        if let Ok(temp_sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if temp_sock
                .connect(format!("{}.{}.{}.1:80", common[0], common[1], common[2]))
                .is_ok()
            {
                if let Ok(la) = temp_sock.local_addr() {
                    if let std::net::IpAddr::V4(v4) = la.ip() {
                        let vo = v4.octets();
                        if vo[0] != 127 && vo[0] != 0 && !(vo[0] == 169 && vo[1] == 254) {
                            let sn = [vo[0], vo[1], vo[2]];
                            if !subnets.contains(&sn) {
                                subnets.push(sn);
                            }
                        }
                    }
                }
            }
        }
    }
    if subnets.is_empty() {
        subnets.push([192, 168, 178]);
    }

    // 1. Broadcast standard signed beacons (112B: prefix + pk + sig) to 2270 and 55225
    // so any PC running Global Ghost Net immediately auto-handshakes this device
    let mut broadcast_targets: Vec<std::net::SocketAddr> = vec![
        "255.255.255.255:55225".parse().unwrap(),
        "255.255.255.255:2270".parse().unwrap(),
    ];
    for sn in &subnets {
        if let Ok(sa) = format!("{}.{}.{}.255:55225", sn[0], sn[1], sn[2]).parse() {
            broadcast_targets.push(sa);
        }
        if let Ok(sa) = format!("{}.{}.{}.255:2270", sn[0], sn[1], sn[2]).parse() {
            broadcast_targets.push(sa);
        }
    }

    let pk_bytes = identity.public_key_bytes();
    let mut beacon_buf = vec![0u8; 112];
    beacon_buf[0..16].copy_from_slice(b"GHOST_BEACON_V1\0");
    beacon_buf[16..48].copy_from_slice(&pk_bytes);
    let sig_bytes = identity.sign(&beacon_buf[16..48]).to_bytes();
    beacon_buf[48..112].copy_from_slice(&sig_bytes);

    for target in &broadcast_targets {
        let _ = sock.send_to(&beacon_buf, *target);
    }

    // 2. Active subnet unicast probe: send handshake shards directly to hosts on LAN
    for sn in &subnets {
        for host in 1..=254 {
            if host % 16 == 0 {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let target_sa: std::net::SocketAddr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(sn[0], sn[1], sn[2], host)),
                55225,
            );
            for i in 0..3 {
                let framed = frame_shard(&raw[i]);
                let gtf = build_gtf_frame([0, 0, 0, 0], 0, i as u8, &framed, &tag, false);
                let _ = sock.send_to(&gtf, target_sa);
            }
        }
    }

    let mut discovered = Vec::new();
    let mut peer_shards: std::collections::HashMap<std::net::SocketAddr, Vec<Option<Vec<u8>>>> =
        std::collections::HashMap::new();
    let mut buf = vec![0u8; 2048];
    let start = std::time::Instant::now();

    while start.elapsed() < Duration::from_millis(2000) {
        if let Ok((amt, src)) = sock.recv_from(&mut buf) {
            if amt >= MIN_FRAME_SIZE {
                let ctr = parse_packet_counter(&buf[..amt]);
                if ctr == 1 {
                    let si = buf[OFFSET_SHARD_INDEX] as usize;
                    if si < 3 {
                        let is_bulk = buf[OFFSET_FLAGS] & 0x01 != 0;
                        let pe = if is_bulk {
                            BULK_OFFSET_AUTH_TAG_START.min(amt)
                        } else {
                            OFFSET_AUTH_TAG_START.min(amt)
                        };
                        let ps = if is_bulk {
                            BULK_OFFSET_PAYLOAD_START
                        } else {
                            OFFSET_PAYLOAD_START
                        };
                        if pe > ps {
                            if let Some(sd) = unframe(&buf[ps..pe]) {
                                let entry = peer_shards.entry(src).or_insert_with(|| vec![None; 3]);
                                entry[si] = Some(sd);
                            }
                        }
                    }
                }
            }
        }

        // Check if any peer has collected >= 2 shards
        let mut completed_peers = Vec::new();
        for (&src, shards) in peer_shards.iter_mut() {
            if shards.iter().filter(|s| s.is_some()).count() >= 2 {
                completed_peers.push(src);
            }
        }

        for src in completed_peers {
            if let Some(mut shards) = peer_shards.remove(&src) {
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
                                discovered.push((src, d, sh));
                            }
                        }
                    }
                }
            }
        }

        if !discovered.is_empty() && start.elapsed() > Duration::from_millis(800) {
            break;
        }
    }

    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    discovered
}

/// One TUN→mesh step: read a packet from the TUN, seal it, wrap in GTF bulk frame,
/// and send via the protected socket to the hub.
pub fn pump_once(core: &mut AndroidCore, buf: &mut [u8]) {
    let (Some(tun), Some(sock), Some(hub)) = (core.tun.as_mut(), core.sock.as_ref(), core.hub_addr)
    else {
        std::thread::sleep(Duration::from_millis(50));
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
/// IP packet into the TUN. Also processes incoming handshakes from LAN peers.
pub fn drain_once(core: &mut AndroidCore, buf: &mut [u8]) -> bool {
    let Some(sock) = core.sock.as_ref() else {
        std::thread::sleep(Duration::from_millis(50));
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(100)));

    let (n, src) = match sock.recv_from(buf) {
        Ok(res) => res,
        Err(_) => return false,
    };
    if n < MIN_FRAME_SIZE {
        return false;
    }
    let ctr = parse_packet_counter(&buf[..n]);

    // Inbound handshake initiation from a peer (counter == 0)
    if ctr == 0 {
        if !core.known_peers.lock().contains_key(&src) {
            if let Some((key, sh)) = perform_handshake(sock, src, &core.identity) {
                core.known_peers.lock().insert(src, (key, sh));
                if core.hub_addr.is_none()
                    || core.hub_addr == Some(src)
                    || core.hub_addr.map(|h| h.ip()) == Some(src.ip())
                {
                    core.hub_addr = Some(src);
                    core.state.rotate_epoch();
                    core.state.set_key(key);
                    *core.session_key.lock() = Some(key);
                    *core.session_hash.lock() = sh;
                    core.tx_seq.store(2, Ordering::Relaxed);
                    alog!(
                        "drain_once: peer handshake established new session with hub {:?}",
                        src
                    );
                }
            }
        }
        return false;
    }

    // Tunnel traffic from established hub
    let session_key_opt = *core.session_key.lock();
    let session_hash = *core.session_hash.lock();
    if let (Some(hub), Some(session_key), Some(tun)) =
        (core.hub_addr, session_key_opt, core.tun.as_mut())
    {
        if src == hub || src.ip() == hub.ip() {
            if src != hub {
                core.hub_addr = Some(src);
            }
            let flags = parse_flags(&buf[..n]);
            if flags & 0x02 != 0 {
                if let Some(wire) = receiver_open(&buf[..n], n, &session_key, session_hash, ctr) {
                    let (accepted, _adv) = open_to_tun(&core.state, &wire, tun);
                    if accepted {
                        let c = core.rx_ctr.fetch_add(1, Ordering::Relaxed) + 1;
                        if c % 50 == 1 {
                            alog!("drain_once: accepted from hub! total_rx={}", c);
                        }
                        return true;
                    } else {
                        alog!(
                            "drain_once: open_to_tun rejected wire datagram (epoch/auth mismatch)"
                        );
                    }
                }
            }
        }
    }
    false
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
use jni::sys::{jboolean, jint, jlong, jlongArray, jstring};
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
        Err(_) => "".to_string(),
    };
    let identity = GhostIdentity::generate_fresh();
    let effective_fp = if fp.is_empty() || fp == "auto" {
        hex::encode(&identity.public_key_bytes()[..8])
    } else {
        fp
    };
    let core = Box::new(AndroidCore {
        state: Arc::new(ClientState::new(effective_fp.clone(), [0u8; 32])),
        ingress: Arc::new(VpnIngress::new()),
        tun: None,
        sock: None,
        hub_addr: None,
        hub_fp: effective_fp,
        stop: Arc::new(AtomicBool::new(false)),
        rx_ctr: Arc::new(AtomicU32::new(0)),
        tx_ctr: Arc::new(AtomicU32::new(0)),
        identity,
        session_key: Mutex::new(None),
        session_hash: Mutex::new([0u8; 4]),
        tx_seq: AtomicU32::new(2),
        known_peers: Mutex::new(std::collections::HashMap::new()),
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
        Err(_) => "".to_string(),
    };
    core.tun = Some(AndroidTun::from_fd(tun_fd));
    use std::os::fd::FromRawFd;
    let sock = Arc::new(unsafe { UdpSocket::from_raw_fd(sock_fd) });
    let _ = sock.set_broadcast(true);

    if !addr.is_empty()
        && addr != "auto"
        && !addr.starts_with("0.0.0.0")
        && !addr.starts_with("192.0.2.1")
    {
        if let Ok(hub) = addr.parse::<std::net::SocketAddr>() {
            core.hub_addr = Some(hub);
            if let Some((key, sh)) = perform_handshake(&sock, hub, &core.identity) {
                core.known_peers.lock().insert(hub, (key, sh));
                core.state.rotate_epoch();
                core.state.set_key(key);
                *core.session_key.lock() = Some(key);
                *core.session_hash.lock() = sh;
                core.tx_seq.store(2, Ordering::Relaxed);
            }
        }
    } else {
        // Autonomous Wi-Fi Discovery
        let found = perform_lan_discovery(&sock, &core.identity);
        for (peer, key, sh) in found {
            core.known_peers.lock().insert(peer, (key, sh));
            if core.hub_addr.is_none() {
                core.hub_addr = Some(peer);
                core.state.rotate_epoch();
                core.state.set_key(key);
                *core.session_key.lock() = Some(key);
                *core.session_hash.lock() = sh;
                core.tx_seq.store(2, Ordering::Relaxed);
            }
        }
    }

    core.sock = Some(sock);
    1
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getFingerprint(
    env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jstring {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_ref() }) else {
        return env.new_string("").unwrap().into_raw();
    };
    let fp = hex::encode(&core.identity.public_key_bytes()[..8]);
    env.new_string(fp).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getPeersCount(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jint {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_ref() }) else {
        return 0;
    };
    let count = core.known_peers.lock().len();
    if count > 0 {
        count as jint
    } else if core.session_key.lock().is_some() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_scanLan(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jint {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_mut() }) else {
        return 0;
    };
    // If tunnel is already established to a designated hub, do not sweep the LAN over the active tunnel socket!
    if core.hub_addr.is_some() && core.session_key.lock().is_some() {
        return core.known_peers.lock().len() as jint;
    }
    let Some(sock) = core.sock.as_ref() else {
        return 0;
    };
    let found = perform_lan_discovery(sock, &core.identity);
    let count = found.len();
    for (peer, key, sh) in found {
        core.known_peers.lock().insert(peer, (key, sh));
        if core.hub_addr.is_none() || core.hub_addr == Some(peer) {
            core.hub_addr = Some(peer);
            core.state.rotate_epoch();
            core.state.set_key(key);
            *core.session_key.lock() = Some(key);
            *core.session_hash.lock() = sh;
            core.tx_seq.store(2, Ordering::Relaxed);
            alog!("scanLan: adopted hub peer {:?}", peer);
        }
    }
    let total = core.known_peers.lock().len();
    if total > 0 {
        total as jint
    } else {
        count as jint
    }
}

/// `fun connectPeer(ptr: Long, peerAddr: String): Boolean`
/// Connect to a specific peer endpoint discovered via Cloudflare Worker tracker or manual config.
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_connectPeer(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    peer_addr: JString,
) -> jboolean {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_mut() }) else {
        return 0;
    };
    let Some(sock) = core.sock.as_ref() else {
        return 0;
    };
    let addr_str: String = match env.get_string(&peer_addr) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let Ok(peer) = addr_str.parse::<std::net::SocketAddr>() else {
        return 0;
    };
    if core.hub_addr == Some(peer) && core.session_key.lock().is_some() {
        return 1;
    }
    if core.known_peers.lock().contains_key(&peer) {
        return 1;
    }
    if let Some((key, sh)) = perform_handshake(sock, peer, &core.identity) {
        core.known_peers.lock().insert(peer, (key, sh));
        if core.hub_addr.is_none() || core.hub_addr == Some(peer) {
            core.hub_addr = Some(peer);
            core.state.rotate_epoch();
            core.state.set_key(key);
            *core.session_key.lock() = Some(key);
            *core.session_hash.lock() = sh;
            core.tx_seq.store(2, Ordering::Relaxed);
            alog!("connectPeer: connected and adopted hub {:?}", peer);
        }
        tracing::info!(peer = %peer, "Connected to bootstrap peer");
        1
    } else {
        tracing::debug!(peer = %peer, "Handshake to bootstrap peer failed");
        0
    }
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
