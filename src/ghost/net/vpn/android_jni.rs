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
use crate::ghost::layers::l2_aead::{decrypt_in_place_with_context, NonceDirection};
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use x25519_dalek::PublicKey;

/// Normalize an address: if it's an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
/// produced by dual-stack sockets on Android/Linux, convert it to a standard IPv4 SocketAddr.
pub(crate) fn canonicalize_addr(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    match addr {
        std::net::SocketAddr::V6(v6) => {
            let oct = v6.ip().octets();
            if oct[0..10] == [0; 10] && oct[10] == 0xff && oct[11] == 0xff {
                let v4 = std::net::Ipv4Addr::new(oct[12], oct[13], oct[14], oct[15]);
                std::net::SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                addr
            }
        }
        std::net::SocketAddr::V4(_) => addr,
    }
}

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
            let err = std::io::Error::last_os_error();
            alog!(
                "AndroidTun::write_packet failed (fd={}, len={}): {}",
                self.fd,
                buf.len(),
                err
            );
            return Err(err);
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
const GHOST_BYE_MAGIC: &[u8] = crate::ghost::net::vpn::hub::GHOST_BYE_MAGIC;

// `frame_shard` / `unframe` come from `ghost::net` (canonical);
// this module used to carry its own byte-identical copies.

fn tunnel_frame(
    key: &[u8; 32],
    sh: [u8; 4],
    epoch: u64,
    ctr: u64,
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
    let nonce = crate::ghost::layers::l2_aead::random_xnonce();
    let _ =
        crate::ghost::layers::l2_aead::xchacha_seal_in_place(key, &nonce, epoch, dir, &mut framed);
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
    let shard = frame_shard(&framed);
    let meta = crate::ghost::net::GtfV2Header {
        session_hash: sh,
        counter: ctr,
        shard_index: 0,
        epoch,
        nonce,
        bulk: true,
        flags: crate::ghost::net::FLAG_TUNNEL,
        tail: [0u8; crate::ghost::net::JITTER_MAX],
    };
    crate::ghost::net::try_build_gtf_v2_frame(&meta, &shard, &tag).unwrap_or_default()
}

fn receiver_open(
    frame: &[u8],
    amt: usize,
    ratchet_lock: &Mutex<Option<crate::ghost::session::ratchet::SessionRatchet>>,
    key: &[u8; 32],
    sh: [u8; 4],
    ctr: u32,
) -> Option<Vec<u8>> {
    // 1. Support GTF v2 wire format from updated hubs (using SessionRatchet per-counter keys)
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
                let mut ratchet_guard = ratchet_lock.lock();
                if let Some(ratchet) = ratchet_guard.as_mut() {
                    for dir in [
                        NonceDirection::ResponderToInitiator,
                        NonceDirection::InitiatorToResponder,
                    ] {
                        let plan = ratchet.plan_open(h.epoch, dir, h.counter);
                        let open_key = match &plan {
                            crate::ghost::session::ratchet::OpenPlan::Forward { key, .. } => *key,
                            crate::ghost::session::ratchet::OpenPlan::Cached { key, .. } => *key,
                            crate::ghost::session::ratchet::OpenPlan::Refused => continue,
                        };
                        let mut trial = msg.clone();
                        if crate::ghost::layers::l2_aead::xchacha_open_with_aad(
                            &open_key, &h.nonce, h.epoch, dir, &mut trial, aad,
                        )
                        .is_ok()
                        {
                            ratchet.commit_open(h.epoch, dir, plan);
                            if trial.len() >= 2 {
                                let n = u16::from_be_bytes([trial[0], trial[1]]) as usize;
                                if let Some(payload) = trial.get(2..2 + n) {
                                    if payload.len() > MAGIC.len()
                                        && &payload[..MAGIC.len()] == MAGIC.as_slice()
                                    {
                                        return Some(payload[MAGIC.len()..].to_vec());
                                    } else if payload.starts_with(GHOST_BYE_MAGIC) {
                                        return Some(GHOST_BYE_MAGIC.to_vec());
                                    }
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
    } else if payload.starts_with(GHOST_BYE_MAGIC) {
        Some(GHOST_BYE_MAGIC.to_vec())
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
    pub rx_bytes: Arc<AtomicU64>,
    pub tx_bytes: Arc<AtomicU64>,
    pub identity: GhostIdentity,
    pub session_key: Mutex<Option<[u8; 32]>>,
    pub session_hash: Mutex<[u8; 4]>,
    pub ratchet: Mutex<Option<crate::ghost::session::ratchet::SessionRatchet>>,
    pub tx_seq: AtomicU32,
    pub known_peers: Mutex<std::collections::HashMap<std::net::SocketAddr, ([u8; 32], [u8; 4])>>,
    pub bye_sent: AtomicBool,
}

impl AndroidCore {
    fn install_session(&self, key: [u8; 32], sh: [u8; 4]) {
        *self.session_key.lock() = Some(key);
        *self.session_hash.lock() = sh;
        *self.ratchet.lock() = Some(crate::ghost::session::ratchet::SessionRatchet::new(key));
        self.tx_seq.store(0, Ordering::Relaxed);
    }

    fn clear_session(&self) {
        *self.session_key.lock() = None;
        *self.ratchet.lock() = None;
    }
}

unsafe impl Send for AndroidCore {}

fn send_goodbye(core: &AndroidCore) {
    if core.bye_sent.swap(true, Ordering::Relaxed) {
        return;
    }
    let Some(sock) = core.sock.as_ref() else {
        return;
    };
    let mut targets: Vec<(std::net::SocketAddr, [u8; 32], [u8; 4])> = core
        .known_peers
        .lock()
        .iter()
        .map(|(&addr, &(k, sh))| (addr, k, sh))
        .collect();
    if let (Some(hub), Some(k)) = (core.hub_addr, *core.session_key.lock()) {
        let sh = *core.session_hash.lock();
        if !targets.iter().any(|(a, _, _)| *a == hub) {
            targets.push((hub, k, sh));
        }
    }
    for (peer, key, sh) in targets {
        for _ in 0..2 {
            let ctr = core.tx_seq.fetch_add(1, Ordering::Relaxed) as u64;
            let frame = tunnel_frame(
                &key,
                sh,
                0,
                ctr,
                NonceDirection::InitiatorToResponder,
                GHOST_BYE_MAGIC,
            );
            let _ = sock.send_to(&frame, peer).or_else(|_| sock.send(&frame));
        }
        alog!("send_goodbye: sent GHOST_BYE to peer {:?}", peer);
    }
}

fn perform_handshake(
    sock: &UdpSocket,
    hub_addr: std::net::SocketAddr,
    identity: &GhostIdentity,
) -> Option<([u8; 32], [u8; 4])> {
    let hub_addr = canonicalize_addr(hub_addr);
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

fn detect_local_lan_subnets() -> (Vec<[u8; 3]>, std::collections::HashSet<std::net::Ipv4Addr>) {
    let mut subnets: Vec<[u8; 3]> = Vec::new();
    let mut local_ips: std::collections::HashSet<std::net::Ipv4Addr> =
        std::collections::HashSet::new();

    if let Ok(temp_sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // 1. Check all 192.168.X.0/24 subnets via fast kernel FIB lookup (no packets sent)
        for third in 0..=254u8 {
            let target = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, third, 1)),
                80,
            );
            if temp_sock.connect(target).is_ok() {
                if let Ok(la) = temp_sock.local_addr() {
                    if let std::net::IpAddr::V4(v4) = la.ip() {
                        local_ips.insert(v4);
                        let vo = v4.octets();
                        if [vo[0], vo[1], vo[2]] == [192, 168, third] {
                            let sn = [192, 168, third];
                            if !subnets.contains(&sn) {
                                subnets.push(sn);
                            }
                        }
                    }
                }
            }
        }
        // 2. Check common 10.X.Y.0/24 and 172.16..31.X.0/24 LAN/hotspot subnets
        let extra_prefixes: &[[u8; 3]] = &[
            [10, 0, 0],
            [10, 0, 1],
            [10, 1, 0],
            [10, 1, 1],
            [10, 10, 10],
            [172, 20, 10],
            [172, 16, 0],
            [172, 16, 1],
        ];
        for p in extra_prefixes {
            let target = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(p[0], p[1], p[2], 1)),
                80,
            );
            if temp_sock.connect(target).is_ok() {
                if let Ok(la) = temp_sock.local_addr() {
                    if let std::net::IpAddr::V4(v4) = la.ip() {
                        local_ips.insert(v4);
                        let vo = v4.octets();
                        if [vo[0], vo[1], vo[2]] == *p && !subnets.contains(p) {
                            subnets.push(*p);
                        }
                    }
                }
            }
        }
    }

    (subnets, local_ips)
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

    let (subnets, local_ips) = detect_local_lan_subnets();
    alog!(
        "perform_lan_discovery: detected LAN subnets {:?}, local IPs {:?}",
        subnets,
        local_ips
    );

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
            let target_ip = std::net::Ipv4Addr::new(sn[0], sn[1], sn[2], host);
            if local_ips.contains(&target_ip) {
                continue;
            }
            if host % 16 == 0 {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let target_sa: std::net::SocketAddr =
                std::net::SocketAddr::new(std::net::IpAddr::V4(target_ip), 55225);
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
        if let Ok((amt, raw_src)) = sock.recv_from(&mut buf) {
            let src = canonicalize_addr(raw_src);
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
    let Some(tun) = core.tun.as_mut() else {
        std::thread::sleep(Duration::from_millis(50));
        return;
    };

    let n = match TunDevice::read_packet(tun, buf) {
        Ok(n) if n >= 20 && (buf[0] >> 4) == 4 => n,
        _ => return,
    };

    // Intercept DNS queries (UDP dst port 53) for instant Ad/Tracker blocking
    // even when zero mesh peers are connected (Local Ad-Shield DNS mode).
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    let is_udp_dns = buf[9] == 17
        && ihl >= 20
        && n > ihl + 8
        && u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]) == 53;

    if is_udp_dns {
        let dns_payload = &buf[ihl + 8..n];
        if let Some(qname) = crate::ghost::net::adblock::extract_dns_qname(dns_payload) {
            if crate::ghost::net::adblock::is_shielded_target(&qname) {
                crate::ghost::net::adblock::record_blocked();
                if let Some(nx) =
                    crate::ghost::net::adblock::build_dns_nxdomain_response(dns_payload)
                {
                    if let Some(reply_pkt) =
                        crate::ghost::net::adblock::synthesize_ipv4_udp_reply(&buf[..n], &nx)
                    {
                        if let Some(t) = core.tun.as_ref() {
                            let _ = t.write_packet(&reply_pkt);
                        }
                        core.rx_ctr.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }

        // In Local Ad-Shield mode (no Exit Hub connected yet), tun0 only routes
        // 10.66.0.1/32, so direct UDP to 1.1.1.1:53 / 9.9.9.9:53 bypasses tun0
        // and keeps normal internet working while filtering ads/trackers!
        if core.hub_addr.is_none() || core.session_key.lock().is_none() {
            if let Ok(dns_sock) = UdpSocket::bind("0.0.0.0:0") {
                let _ = dns_sock.set_read_timeout(Some(Duration::from_millis(1200)));
                let _ = dns_sock.send_to(dns_payload, "1.1.1.1:53");
                let mut dns_buf = [0u8; 1500];
                let recv_res = dns_sock.recv_from(&mut dns_buf).or_else(|_| {
                    let _ = dns_sock.send_to(dns_payload, "9.9.9.9:53");
                    dns_sock.recv_from(&mut dns_buf)
                });
                if let Ok((rn, _)) = recv_res {
                    let filtered = crate::ghost::net::adblock::filter_dns_response(&dns_buf[..rn]);
                    let reply_dns = filtered.as_deref().unwrap_or(&dns_buf[..rn]);
                    if let Some(reply_pkt) =
                        crate::ghost::net::adblock::synthesize_ipv4_udp_reply(&buf[..n], reply_dns)
                    {
                        if let Some(t) = core.tun.as_ref() {
                            let _ = t.write_packet(&reply_pkt);
                        }
                        core.rx_ctr.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            return;
        }
    }

    let (Some(sock), Some(hub)) = (core.sock.as_ref(), core.hub_addr) else {
        return;
    };
    let Some(session_key) = *core.session_key.lock() else {
        return;
    };
    let session_hash = *core.session_hash.lock();

    if let Some(wire) = seal_from_tun(&core.state, &buf[..n]) {
        let (epoch, ctr, seal_key) = {
            let mut rg = core.ratchet.lock();
            if let Some(r) = rg.as_mut() {
                let (c, k) = r.advance_seal(NonceDirection::InitiatorToResponder);
                (r.epoch(), c, k)
            } else {
                (
                    0,
                    core.tx_seq.fetch_add(1, Ordering::Relaxed) as u64,
                    session_key,
                )
            }
        };
        let frame = tunnel_frame(
            &seal_key,
            session_hash,
            epoch,
            ctr,
            NonceDirection::InitiatorToResponder,
            &wire,
        );
        core.tx_ctr.fetch_add(1, Ordering::Relaxed);
        core.tx_bytes
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
        let _ = sock.send_to(&frame, hub).or_else(|_| sock.send(&frame));
    }
}

fn is_tunnel_healthy(core: &AndroidCore) -> bool {
    if core.session_key.lock().is_none() || core.hub_addr.is_none() {
        return false;
    }
    let tx_sent = core.tx_ctr.load(Ordering::Relaxed);
    if tx_sent < 6 {
        return true;
    }
    let last_in = core.state.last_inbound_ms();
    if last_in == 0 {
        return tx_sent < 30;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    now_ms.saturating_sub(last_in) < 30_000
}

/// One mesh→TUN step: recv a GTF datagram from hub, open it, and write the inner
/// IP packet into the TUN. Also processes incoming handshakes from LAN peers.
pub fn drain_once(core: &mut AndroidCore, buf: &mut [u8]) -> bool {
    let Some(sock) = core.sock.as_ref() else {
        std::thread::sleep(Duration::from_millis(50));
        return false;
    };

    let (n, raw_src) = match sock.recv_from(buf) {
        Ok(res) => res,
        Err(_) => return false,
    };
    let src = canonicalize_addr(raw_src);
    if crate::ghost::net::stun::is_stun_packet(&buf[..n]) {
        // Single-socket STUN/ICE demux: handle reflexive discovery or ICE connectivity checks
        return false;
    }
    if n > 5 && &buf[..5] == b"BLND!" {
        // DERP blind relay envelope demux
        return false;
    }
    if n < MIN_FRAME_SIZE {
        return false;
    }
    let ctr = crate::ghost::net::parse_packet_counter_u64(&buf[..n]) as u32;

    // Inbound handshake initiation from a peer (counter == 0)
    if ctr == 0 {
        let is_current_hub = core
            .hub_addr
            .map(|h| src == h || src.ip() == h.ip())
            .unwrap_or(false);
        let has_hub_session = core.hub_addr.is_some() && core.session_key.lock().is_some();
        let healthy = is_tunnel_healthy(core);

        // If from our current hub and tunnel is healthy, ignore redundant re-handshake probes
        if is_current_hub && healthy {
            return false;
        }

        // If we already have a hub session, do NOT let a non-hub peer hijack hub_addr!
        if has_hub_session && !is_current_hub {
            if !core.known_peers.lock().contains_key(&src) {
                if let Some((key, sh)) = perform_handshake(sock, src, &core.identity) {
                    core.known_peers.lock().insert(src, (key, sh));
                    alog!(
                        "drain_once: established P2P session with peer {:?} (hub remains {:?})",
                        src,
                        core.hub_addr
                    );
                }
            }
            return false;
        }

        // Hub handshake / initial adoption / explicit reconnect
        if !has_hub_session || !healthy || is_current_hub {
            if let Some((key, sh)) = perform_handshake(sock, src, &core.identity) {
                core.known_peers.lock().insert(src, (key, sh));
                if core.hub_addr.is_none() || is_current_hub || !healthy {
                    core.hub_addr = Some(src);
                    core.state.rotate_epoch();
                    core.state.set_key(key);
                    core.state.note_inbound();
                    core.install_session(key, sh);
                    alog!(
                        "drain_once: peer handshake established new session with hub {:?}",
                        src
                    );
                }
            }
        }
        return false;
    }

    // Check if a non-hub known peer sent GHOST_BYE_____
    let flags = parse_flags(&buf[..n]);
    if flags & 0x02 != 0 {
        let non_hub = core
            .hub_addr
            .map(|h| h != src && h.ip() != src.ip())
            .unwrap_or(true);
        if non_hub {
            let peer_sess = core.known_peers.lock().get(&src).copied();
            if let Some((peer_key, peer_sh)) = peer_sess {
                if let Some(wire) =
                    receiver_open(&buf[..n], n, &core.ratchet, &peer_key, peer_sh, ctr)
                {
                    if wire.starts_with(GHOST_BYE_MAGIC) {
                        core.known_peers
                            .lock()
                            .retain(|k, _| *k != src && k.ip() != src.ip());
                        alog!(
                            "drain_once: peer {:?} sent GHOST_BYE — evicted from known_peers",
                            src
                        );
                        return false;
                    }
                }
            }
        }
    }

    // Tunnel traffic from established hub
    let session_key_opt = *core.session_key.lock();
    let session_hash = *core.session_hash.lock();
    if let (Some(hub), Some(session_key)) = (core.hub_addr, session_key_opt) {
        if src == hub || src.ip() == hub.ip() {
            if src != hub {
                core.hub_addr = Some(src);
            }
            if flags & 0x02 != 0 {
                match receiver_open(&buf[..n], n, &core.ratchet, &session_key, session_hash, ctr) {
                    Some(wire) => {
                        if wire.starts_with(GHOST_BYE_MAGIC) {
                            let next_peer = {
                                let mut kp = core.known_peers.lock();
                                kp.retain(|k, _| *k != src && k.ip() != src.ip());
                                kp.iter().next().map(|(&a, &(k, s))| (a, k, s))
                            };
                            if let Some((next_addr, next_key, next_sh)) = next_peer {
                                core.hub_addr = Some(next_addr);
                                core.state.rotate_epoch();
                                core.state.set_key(next_key);
                                core.state.note_inbound();
                                core.install_session(next_key, next_sh);
                                alog!(
                                    "drain_once: hub {:?} sent GHOST_BYE — failed over to {:?}",
                                    src,
                                    next_addr
                                );
                            } else {
                                core.hub_addr = None;
                                core.clear_session();
                                alog!(
                                    "drain_once: hub {:?} sent GHOST_BYE — no remaining peers, awaiting discovery",
                                    src
                                );
                            }
                            return false;
                        }
                        if let Some(tun) = core.tun.as_mut() {
                            let (accepted, adv) = open_to_tun(&core.state, &wire, tun);
                            if accepted {
                                let c = core.rx_ctr.fetch_add(1, Ordering::Relaxed) + 1;
                                core.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                                if c % 10 == 1 || c <= 5 {
                                    alog!(
                                        "drain_once: ACCEPTED packet from hub (len={}, adv={})! total_rx={}",
                                        wire.len(),
                                        adv,
                                        c
                                    );
                                }
                                return true;
                            } else {
                                alog!(
                                    "drain_once: open_to_tun rejected wire datagram (cur_epoch={}, wire_len={})",
                                    core.state.current_epoch(),
                                    wire.len()
                                );
                            }
                        }
                    }
                    None => {
                        alog!(
                            "drain_once: receiver_open decrypt failed (ctr={}, amt={})",
                            ctr,
                            n
                        );
                    }
                }
            } else {
                // Control or gossip frame (e.g. PEX or beacon) without FLAG_TUNNEL — ignore quietly
            }
        }
    }
    false
}

impl Drop for AndroidCore {
    fn drop(&mut self) {
        send_goodbye(self);
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

/// `fun init(hubFingerprint: String, storageDir: String): Long`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_init(
    mut env: JNIEnv,
    _class: JClass,
    hub_fp: JString,
    storage_dir: JString,
) -> jlong {
    let fp: String = match env.get_string(&hub_fp) {
        Ok(s) => s.into(),
        Err(_) => "".to_string(),
    };
    let dir: String = match env.get_string(&storage_dir) {
        Ok(s) => s.into(),
        Err(_) => "".to_string(),
    };
    let identity = {
        let key_path = if !dir.is_empty() {
            std::path::PathBuf::from(dir).join("identity.key")
        } else {
            std::path::PathBuf::from("/data/data/dev.globalghost.net/files/identity.key")
        };
        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let p_str = key_path.to_str().unwrap_or("identity.key");
        GhostIdentity::load_or_generate(p_str)
    };
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
        rx_bytes: Arc::new(AtomicU64::new(0)),
        tx_bytes: Arc::new(AtomicU64::new(0)),
        identity,
        session_key: Mutex::new(None),
        session_hash: Mutex::new([0u8; 4]),
        ratchet: Mutex::new(None),
        tx_seq: AtomicU32::new(0),
        known_peers: Mutex::new(std::collections::HashMap::new()),
        bye_sent: AtomicBool::new(false),
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
    core.install_session(arr, compute_session_hash(&arr));
}

/// `fun updateTun(ptr: Long, tunFd: Int)`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_updateTun(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    tun_fd: jint,
) {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_mut() }) else {
        return;
    };
    core.tun = Some(AndroidTun::from_fd(tun_fd));
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_setAdblockEnabled(
    _env: JNIEnv,
    _class: JClass,
    enabled: jboolean,
) {
    crate::ghost::net::adblock::set_enabled(enabled != 0);
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getAdsBlocked(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    crate::ghost::net::adblock::blocked_count() as jlong
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_setThreatShieldEnabled(
    _env: JNIEnv,
    _class: JClass,
    enabled: jboolean,
) {
    crate::ghost::net::threat_shield::set_enabled(enabled != 0);
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getThreatShieldBlocked(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    crate::ghost::net::threat_shield::blocked_total() as jlong
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_allowThreatShieldDomain(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) {
    let raw: String = match env.get_string(&domain) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    let clean = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if !clean.is_empty() {
        crate::ghost::net::threat_shield::allow_domain(&clean);
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getThreatShieldJson<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let recent: Vec<serde_json::Value> = crate::ghost::net::threat_shield::recent_blocks(16)
        .into_iter()
        .map(|ev| {
            serde_json::json!({
                "target": ev.value,
                "kind": ev.kind.as_str(),
                "timestamp_secs": ev.at,
            })
        })
        .collect();
    let json = serde_json::json!({
        "enabled": crate::ghost::net::threat_shield::is_enabled(),
        "blocked_total": crate::ghost::net::threat_shield::blocked_total(),
        "recent": recent,
    })
    .to_string();
    env.new_string(json)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_setExperimentalFlag(
    mut env: JNIEnv,
    _class: JClass,
    key: JString,
    enabled: jboolean,
) {
    let key_str: String = match env.get_string(&key) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    let on = enabled != 0;
    match key_str.as_str() {
        "exp_pow_shield" => crate::ghost::net::pow::set_enabled(on),
        "exp_dtn_reconcile" => crate::ghost::net::dtn_reconcile::set_enabled(on),
        "exp_universal_tunnel" => crate::ghost::net::universal_tunnel::set_enabled(on),
        "exp_collective_defense" => crate::ghost::net::collective_defense::set_enabled(on),
        "exp_rendezvous" => crate::ghost::net::rendezvous::set_enabled(on),
        "exp_diffusion" => crate::ghost::net::diffusion::set_enabled(on),
        _ => {}
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_setRegime(
    mut env: JNIEnv,
    _class: JClass,
    regime: JString,
) {
    let raw: String = match env.get_string(&regime) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    if let Some(parsed) = crate::ghost::v2::regime::Regime::parse(&raw) {
        std::env::set_var(crate::ghost::v2::regime::REGIME_ENV, parsed.as_str());
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_setQelEnabled(
    _env: JNIEnv,
    _class: JClass,
    enabled: jboolean,
) {
    std::env::set_var("GHOST_QEL_ENABLED", if enabled != 0 { "1" } else { "0" });
}

#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getXrayJson<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    ptr: jlong,
) -> jstring {
    let (peers, connected, fp) = match unsafe { (ptr as *const AndroidCore).as_ref() } {
        Some(core) => {
            let peers = core.known_peers.lock().len();
            let connected = core.hub_addr.is_some() && core.session_key.lock().is_some();
            let fp = core.identity.fingerprint();
            (peers, connected, fp)
        }
        None => (0, false, String::new()),
    };
    let regime = std::env::var(crate::ghost::v2::regime::REGIME_ENV)
        .ok()
        .and_then(|s| crate::ghost::v2::regime::Regime::parse(&s))
        .unwrap_or(crate::ghost::v2::regime::Regime::Ghost);
    let state = crate::ghost::v2::api::ApiState {
        peers: if connected { peers.max(1) } else { peers },
        regime,
        socks_port: 1080,
        transport: connected.then(|| "gtf_v2".to_string()),
        exit_ip: None,
        node_fingerprint: fp,
    };
    let json = crate::ghost::v2::api::xray(&state).to_string();
    env.new_string(json)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
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
    let _ = sock.set_read_timeout(Some(Duration::from_millis(15)));

    if !addr.is_empty()
        && addr != "auto"
        && !addr.starts_with("0.0.0.0")
        && !addr.starts_with("192.0.2.1")
    {
        if let Ok(hub) = addr.parse::<std::net::SocketAddr>() {
            let hub = canonicalize_addr(hub);
            if let Some((key, sh)) = perform_handshake(&sock, hub, &core.identity) {
                core.hub_addr = Some(hub);
                core.known_peers.lock().insert(hub, (key, sh));
                core.state.rotate_epoch();
                core.state.set_key(key);
                core.state.note_inbound();
                core.install_session(key, sh);
            }
        }
    }

    // Always run LAN discovery if no active hub session was established yet
    if core.session_key.lock().is_none() {
        let found = perform_lan_discovery(&sock, &core.identity);
        for (peer, key, sh) in found {
            core.known_peers.lock().insert(peer, (key, sh));
            if core.session_key.lock().is_none() {
                core.hub_addr = Some(peer);
                core.state.rotate_epoch();
                core.state.set_key(key);
                core.state.note_inbound();
                core.install_session(key, sh);
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
    let has_hub_session = core.hub_addr.is_some() && core.session_key.lock().is_some();
    let healthy = is_tunnel_healthy(core);
    // If tunnel is already established and healthy, do not disturb hub session
    if has_hub_session && healthy {
        return core.known_peers.lock().len().max(1) as jint;
    }
    let Some(sock) = core.sock.as_ref() else {
        return 0;
    };
    if let Some(hub) = core.hub_addr {
        if let Some((key, sh)) = perform_handshake(sock, hub, &core.identity) {
            core.known_peers.lock().insert(hub, (key, sh));
            core.state.rotate_epoch();
            core.state.set_key(key);
            core.state.note_inbound();
            core.install_session(key, sh);
            alog!(
                "scanLan: re-established session with designated hub {:?}",
                hub
            );
            return core.known_peers.lock().len().max(1) as jint;
        }
    }
    let found = perform_lan_discovery(sock, &core.identity);
    let count = found.len();
    for (peer, key, sh) in found {
        core.known_peers.lock().insert(peer, (key, sh));
        if core.hub_addr.is_none() || core.session_key.lock().is_none() {
            core.hub_addr = Some(peer);
            core.state.rotate_epoch();
            core.state.set_key(key);
            core.state.note_inbound();
            core.install_session(key, sh);
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
    let peer = canonicalize_addr(peer);
    let (_, local_ips) = detect_local_lan_subnets();
    if let std::net::IpAddr::V4(v4) = peer.ip() {
        if local_ips.contains(&v4) || v4.is_loopback() {
            return 0;
        }
    }
    let healthy = is_tunnel_healthy(core);
    if core.hub_addr == Some(peer) && healthy {
        return 1;
    }
    if core.known_peers.lock().contains_key(&peer) && healthy {
        return 1;
    }
    if let Some((key, sh)) = perform_handshake(sock, peer, &core.identity) {
        core.known_peers.lock().insert(peer, (key, sh));
        if core.hub_addr.is_none() || core.session_key.lock().is_none() {
            core.hub_addr = Some(peer);
            core.state.rotate_epoch();
            core.state.set_key(key);
            core.state.note_inbound();
            core.install_session(key, sh);
            alog!("connectPeer: connected and adopted hub {:?}", peer);
        }
        tracing::info!(peer = %peer, "Connected to bootstrap peer");
        1
    } else {
        tracing::debug!(peer = %peer, "Handshake to bootstrap peer failed");
        0
    }
}

/// `fun selectHub(ptr: Long, peerAddr: String): Boolean`
/// Explicitly switch the active exit hub to `peerAddr`.
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_selectHub(
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
    let peer = canonicalize_addr(peer);
    let session = core
        .known_peers
        .lock()
        .get(&peer)
        .copied()
        .or_else(|| perform_handshake(sock, peer, &core.identity));
    if let Some((key, sh)) = session {
        core.known_peers.lock().insert(peer, (key, sh));
        core.hub_addr = Some(peer);
        core.state.rotate_epoch();
        core.state.set_key(key);
        core.state.note_inbound();
        core.install_session(key, sh);
        alog!("selectHub: switched active exit hub to {:?}", peer);
        1
    } else {
        0
    }
}

/// `fun getActiveHub(ptr: Long): String`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getActiveHub(
    env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jstring {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_ref() }) else {
        return std::ptr::null_mut();
    };
    let hub_str = if core.session_key.lock().is_some() {
        core.hub_addr.map(|a| a.to_string()).unwrap_or_default()
    } else {
        String::new()
    };
    match env.new_string(&hub_str) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `fun getKnownPeers(ptr: Long): String` (comma-separated list of ip:port)
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getKnownPeers(
    env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jstring {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_ref() }) else {
        return std::ptr::null_mut();
    };
    let mut list: Vec<String> = Vec::new();
    if let Some(hub) = core.hub_addr {
        if core.session_key.lock().is_some() {
            list.push(hub.to_string());
        }
    }
    for peer in core.known_peers.lock().keys() {
        let s = peer.to_string();
        if !list.contains(&s) {
            list.push(s);
        }
    }
    let joined = list.join(",");
    match env.new_string(&joined) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `fun stats(ptr: Long): LongArray` — [rxPackets, txPackets, epoch, txCounter, rxBytes, txBytes]
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_stats(
    env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jlongArray {
    let Some(core) = (unsafe { (ptr as *mut AndroidCore).as_ref() }) else {
        return std::ptr::null_mut();
    };
    let vals: [jlong; 6] = [
        core.rx_ctr.load(Ordering::Relaxed) as jlong,
        core.tx_ctr.load(Ordering::Relaxed) as jlong,
        core.state.current_epoch() as jlong,
        core.state.tx_counter() as jlong,
        core.rx_bytes.load(Ordering::Relaxed) as jlong,
        core.tx_bytes.load(Ordering::Relaxed) as jlong,
    ];
    match env.new_long_array(6) {
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
    let mut buf = [0u8; 2048];
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
    let mut buf = [0u8; 2048];
    let mut received = false;
    for _ in 0..16 {
        if drain_once(core, &mut buf) {
            received = true;
        } else {
            break;
        }
    }
    received as jboolean
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

static RENDEZVOUS_URL: Mutex<String> = Mutex::new(String::new());
static HANDOVER_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_RTT_MS: AtomicU64 = AtomicU64::new(u64::MAX);

/// `fun importInvite(ptr: Long, invite: String): String`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_importInvite(
    mut env: JNIEnv,
    _class: JClass,
    _ptr: jlong,
    invite: jni::objects::JString,
) -> jni::sys::jstring {
    let raw: String = match env.get_string(&invite) {
        Ok(s) => s.into(),
        Err(_) => {
            return env
                .new_string("err:invalid string")
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut());
        }
    };
    let trimmed = raw.trim();
    let res = if trimmed.starts_with("vb-net://") {
        match crate::ghost::net::discovery::NetworkInvite::from_uri(trimmed) {
            Some(inv) => {
                if let Some(url) = inv.rendezvous_url.as_ref() {
                    *RENDEZVOUS_URL.lock() = url.clone();
                }
                let ep = inv
                    .bootstrap_peer
                    .as_ref()
                    .map(|p| p.endpoint.to_string())
                    .unwrap_or_default();
                format!("ok:{ep}")
            }
            None => "err:invalid network invite".to_string(),
        }
    } else if trimmed.starts_with("vb://") {
        match crate::ghost::net::discovery::PeerDescriptorV2::from_uri(trimmed) {
            Some(desc) => {
                let ep = desc.endpoint.to_string();
                format!("ok:{ep}")
            }
            None => "err:invalid peer descriptor".to_string(),
        }
    } else {
        "err:unsupported invite scheme".to_string()
    };
    env.new_string(res)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// `fun setRendezvousUrl(ptr: Long, url: String)`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_setRendezvousUrl(
    mut env: JNIEnv,
    _class: JClass,
    _ptr: jlong,
    url: jni::objects::JString,
) {
    if let Ok(s) = env.get_string(&url) {
        let u: String = s.into();
        *RENDEZVOUS_URL.lock() = u.trim().to_string();
    }
}

/// `fun getConnectionPath(ptr: Long): String`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getConnectionPath(
    env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jni::sys::jstring {
    let path = if let Some(core) = unsafe { (ptr as *const AndroidCore).as_ref() } {
        if let Some(hub) = core.hub_addr {
            match hub.ip() {
                std::net::IpAddr::V4(v4) if v4.is_private() => "Wi-Fi Direct LAN",
                _ => "5G Direct ICE",
            }
        } else {
            "5G via DERP Relay"
        }
    } else {
        "Disconnected"
    };
    env.new_string(path)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// `fun getRttMs(ptr: Long): Long`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getRttMs(
    _env: JNIEnv,
    _class: JClass,
    _ptr: jlong,
) -> jlong {
    let v = LAST_RTT_MS.load(Ordering::Relaxed);
    if v == u64::MAX {
        -1
    } else {
        v as jlong
    }
}

/// `fun getHandoverCount(ptr: Long): Long`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_getHandoverCount(
    _env: JNIEnv,
    _class: JClass,
    _ptr: jlong,
) -> jlong {
    HANDOVER_COUNT.load(Ordering::Relaxed) as jlong
}

/// `fun recordHandover(ptr: Long)`
#[no_mangle]
pub extern "system" fn Java_dev_globalghost_net_GhostCore_recordHandover(
    _env: JNIEnv,
    _class: JClass,
    _ptr: jlong,
) {
    HANDOVER_COUNT.fetch_add(1, Ordering::Relaxed);
}
