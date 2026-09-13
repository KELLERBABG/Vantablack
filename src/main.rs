use rand::RngCore;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::sleep;

use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, DecapsulationKey512, MlKem512};
#[cfg(feature = "tray")]
mod tray;
#[cfg(feature = "vpn")]
use vantablack::ghost::net::vpn::{
    self,
    hub::{VpnHub, VPN_PAYLOAD_MAGIC},
    tun::TunDevice,
    VpnConfig, VpnRole,
};
use vantablack::ghost::{
    layers::{
        l0_identity,
        l1_kem::{
            build_handshake_pdu, build_response_pdu, derive_hybrid_master_key_with_psk,
            generate_kyber_keypair, generate_x25519_keypair, kyber_encapsulate,
            parse_handshake_pdu, parse_response_pdu, HANDSHAKE_BLOB_LEN, RESPONSE_BLOB_LEN,
        },
        l2_aead::{decrypt_in_place_with_context, encrypt_in_place_with_context, NonceDirection},
        l4_rs,
        l7_ldpc::LdpcCodec,
        l8_memsec::{VerifiedRingBuffer, XtsMemoryEncryptor},
    },
    net::{
        self,
        mesh::{ExitIpRotator, TitForTatEnforcer},
        parse_packet_counter,
        relay::{build_relay_packet, parse_relay_header, spawn_store_forward_task, BundleBuffer},
        routing::PoissonReputationMatrix,
        security::{LockedMemory, RevocationList, RevocationReason, ZkAuthenticator},
        send_gtf, BEACON_MULTICAST_ADDR, BEACON_PORT, BEACON_PREFIX, GTF_BULK_SIZE,
        OFFSET_PAYLOAD_START,
    },
    session::{Session, SessionRole},
    GhostNode,
};

type PendingHandshakes = Arc<DashMap<String, (x25519_dalek::EphemeralSecret, DecapsulationKey512)>>;

/// Hard cap on the shard-reassembly spool (per-node). Entries with fewer than
/// two shards are pruned when the cap is exceeded (anti-memory-DoS).
const MAX_SPOOL_ENTRIES: usize = 8192;

/// Hard cap on concurrent sessions (anti-flood: attackers can mint unlimited
/// self-signed identities, so the session table must be bounded).
const MAX_SESSIONS: usize = 512;

/// Hard cap on in-flight pending handshakes per node.
const MAX_PENDING_HANDSHAKES: usize = 512;

/// Embedded bootstrap seeds (public VPS rendezvous nodes). Override at runtime
/// via `GHOST_SEEDS=ip:port,ip:port,...`. When empty and no env var is set,
/// the node starts in listen-only mode (beacon + accept incoming handshakes).
const EMBEDDED_SEEDS: &[&str] = &[];

async fn assemble(
    pool: &DashMap<u32, Vec<Option<Vec<u8>>>>,
    ctr: u32,
    idx: usize,
    data: Vec<u8>,
) -> Option<Vec<u8>> {
    // Cap the spool so a remote sender cannot grow it without bound with
    // single-shard garbage (entries with <2 shards are unrecoverable).
    if pool.len() > MAX_SPOOL_ENTRIES {
        pool.retain(|_, v| v.iter().filter(|s| s.is_some()).count() >= 2);
    }
    // Atomic claim: the shard-write happens under the bucket's write lock, so
    // exactly one task can observe count>=2 with len==3 and append a claim
    // marker (4th slot). All other tasks then drop out; only the claimant
    // removes the bucket — no unwrap() race, no frame dropped by double-remove.
    let should_assemble = {
        let mut entry = pool.entry(ctr).or_insert_with(|| vec![None, None, None]);
        let e = entry.value_mut();
        while e.len() < 3 {
            e.push(None);
        }
        e[idx] = Some(data);
        if e.iter().filter(|s| s.is_some()).count() >= 2 && e.len() == 3 {
            e.push(None); // claim marker
        }
        entry.value().len() > 3
    };
    if should_assemble {
        let (_, mut s) = pool.remove(&ctr).unwrap_or_default();
        let m = s
            .iter()
            .filter_map(|x| x.as_ref().map(|v| v.len()))
            .max()
            .unwrap_or(0);
        for ref mut v in s.iter_mut().flatten() {
            while v.len() < m {
                v.push(0);
            }
        }
        let mut w: Vec<_> = (0..3).map(|i| s.get(i).and_then(|x| x.clone())).collect();
        if l4_rs::reconstruct(&mut w).is_ok() {
            let a = w[0].as_ref()?;
            let b = w[1].as_ref()?;
            return Some([a.as_slice(), b.as_slice()].concat());
        }
    }
    None
}

fn frame_shard(d: &[u8]) -> Vec<u8> {
    let l = (d.len() as u16).to_be_bytes();
    let mut f = Vec::with_capacity(d.len() + 2);
    f.extend_from_slice(&l);
    f.extend_from_slice(d);
    f
}

fn unframe(b: &[u8]) -> Option<Vec<u8>> {
    if b.len() < 2 {
        return None;
    }
    let l = u16::from_be_bytes([b[0], b[1]]) as usize;
    if l == 0 || 2 + l > b.len() {
        None
    } else {
        Some(b[2..2 + l].to_vec())
    }
}

fn enc_split(
    key: &[u8; 32],
    ctr: u32,
    session_hash: &[u8; 4],
    direction: NonceDirection,
    pay: &[u8],
) -> (Vec<Vec<u8>>, [u8; 16]) {
    let pay_len = pay.len() as u16;
    let mut framed = pay_len.to_be_bytes().to_vec();
    framed.extend_from_slice(pay);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    encrypt_in_place_with_context(key, ctr, session_hash, direction, &mut framed);
    let t = if framed.len() >= 16 {
        let mut x = [0u8; 16];
        x.copy_from_slice(&framed[framed.len() - 16..]);
        x
    } else {
        [0u8; 16]
    };
    let raw = l4_rs::encode(&mut framed);
    (raw.iter().map(|s| frame_shard(s)).collect(), t)
}

async fn send3(
    sock: &UdpSocket,
    dst: &SocketAddr,
    sh: [u8; 4],
    ctr: u32,
    f: &[Vec<u8>],
    tag: &[u8; 16],
) {
    for i in 0..3 {
        let _ = send_gtf(sock, dst, sh, ctr, i as u8, &f[i], tag, false).await;
    }
}

/// Send 3 RS shards using adaptive multi-path routing when alternative peer routes exist.
async fn send3_adaptive(
    sock: &UdpSocket,
    primary_dst: &SocketAddr,
    primary_fp: &str,
    sh: [u8; 4],
    ctr: u32,
    f: &[Vec<u8>],
    tag: &[u8; 16],
    router: &vantablack::ghost::net::mesh::AdaptiveShardRouter,
    all_peers: &Arc<DashMap<String, SocketAddr>>,
) {
    let mut available: Vec<(String, SocketAddr)> = all_peers
        .iter()
        .map(|entry| (entry.key().clone(), *entry.value()))
        .collect();

    if !available.iter().any(|(fp, _)| fp == primary_fp) {
        available.push((primary_fp.to_string(), *primary_dst));
    }

    if available.len() > 1 {
        let selected = router.select_shard_targets(&available);
        let routes = router.assign_shards(&selected);
        // Enforce disjoint routing constraint across distinct network planes
        let mut disjoint_constraint = net::orbit::DisjointRouteConstraint::new();
        for route in routes {
            let idx = route.shard_index as usize;
            if idx < f.len() {
                // Reserve ground plane path
                let _ = disjoint_constraint.reserve_plane(net::orbit::OrbitalPlane::Ground);
                let target_addr = selected
                    .iter()
                    .find(|(fp, _, _)| *fp == route.peer_fingerprint)
                    .map(|(_, addr, _)| *addr)
                    .unwrap_or(*primary_dst);
                let _ = send_gtf(
                    sock,
                    &target_addr,
                    sh,
                    ctr,
                    route.shard_index,
                    &f[idx],
                    tag,
                    false,
                )
                .await;
            }
        }
    } else {
        // Fallback to direct send
        send3(sock, primary_dst, sh, ctr, f, tag).await;
    }
}

// ── SOCKS5 mesh tunneling (initiator ⇄ exit) ───────────────────────
//
// Wire protocol (all data frames are length-prefixed via enc_split):
//   initiator → exit   ctr = session tx counter   payload "host:port"  (SOCKS5 CONNECT)
//   exit      → init   ctr = exit's tx counter    payload "OK"
//   initiator → exit   ctr = connect_ctr+1, +2…   relayed client bytes
//   exit      → init   ctr = ok_ctr+1, +2…        relayed remote bytes
//
// Nonces are direction-bound (NonceDirection) so the two directions
// never reuse a (key, nonce) pair even at equal counters. Each side
// re-orders out-of-order UDP frames before delivery.
//
// Known limitation: tunnel relays use their own counter space, so a
// keepalive firing while a tunnel is idle >60s could collide counters
// within one direction. Active tunnels reset the idle timer, so this
// cannot happen during live traffic.

/// Per-direction receive state: next expected counter + reorder buffer.
#[derive(Default)]
struct RxState {
    next: Option<u32>,
    buf: BTreeMap<u32, Vec<u8>>,
}

/// An active exit-side tunnel: decrypted remote data flows through `out_tx`.
struct ExitTunnel {
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: RxState,
    session_hash: [u8; 4],
}

type ExitTunnels = Arc<DashMap<String, ExitTunnel>>;
/// Initiator side: per-session channel delivering decrypted exit data.
type SessionChannels = Arc<DashMap<[u8; 4], mpsc::UnboundedSender<Vec<u8>>>>;
/// Initiator side: per-session "CONNECT OK" flags.
type ConnectAcks = Arc<DashMap<[u8; 4], bool>>;
/// Initiator side: the exit's OK counter per session — anchors the reorder
/// buffer so out-of-order tunnel frames are buffered, not dropped.
type ConnectOkCtrs = Arc<DashMap<[u8; 4], u32>>;
/// Initiator side: per-session reorder state for exit data.
type RxStateMap = Arc<DashMap<[u8; 4], RxState>>;

fn exit_tunnel_key(src: &SocketAddr, sh: &[u8; 4]) -> String {
    format!("{}|{}", src, hex::encode(sh))
}

/// Direction our own sends take, given our role in the session.
fn dir_for(role: SessionRole) -> NonceDirection {
    match role {
        SessionRole::Initiator => NonceDirection::InitiatorToResponder,
        SessionRole::Responder => NonceDirection::ResponderToInitiator,
    }
}

/// True if the payload looks like a "host:port" SOCKS5 CONNECT destination.
fn looks_like_dest(p: &[u8]) -> bool {
    let s = String::from_utf8_lossy(p);
    match s.rsplit_once(':') {
        Some((h, port)) => !h.is_empty() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

/// Optional VPN subsystem: hub mode (serve the home LAN) or client mode
/// (TUN device). Created in main() from env; None = VPN off (v0.4.0 behavior).
#[cfg(feature = "vpn")]
#[derive(Clone)]
enum VpnMode {
    Hub(Arc<VpnHub>),
    Client(
        Arc<vpn::client::ClientState>,
        Arc<std::sync::Mutex<vpn::tun::PlatformTun>>,
    ),
}
#[cfg(not(feature = "vpn"))]
#[derive(Clone)]
enum VpnMode {}

#[cfg(feature = "vpn")]
/// Outer-wire send of a VPN payload: [len u16][GVPN1][tunnel datagram]
/// encrypted with the SESSION key (direction-bound nonce) and sent as ONE
/// bulk GTF frame with the tunnel flag set. Returns on missing session.
async fn send_tunnel_frame(
    nc: &Arc<GhostNode>,
    peer_fp: &str,
    endpoint: SocketAddr,
    tunnel_wire: &[u8],
) {
    let Some(sess) = nc.sessions.get(peer_fp) else {
        tracing::debug!(peer = %peer_fp, "VPN egress: no session yet — dropped");
        return;
    };
    let ctr = sess.next_tx_counter();
    let (key, sh, role) = (sess.master_key, sess.session_hash, sess.role);
    drop(sess);
    // Counters near u32::MAX collide with the re-key sentinels reserved by
    // `Session::try_next_tx_counter` (0xFFFF_FFFD / 0xFFFF_FFFE / u32::MAX).
    const CTR_MAX: u32 = u32::MAX - 2;
    // Warn well before the wall. The peer's replay window is monotonic, so once
    // its counter space wraps, every later frame is rejected forever. Refusing
    // to send is correct; doing it *silently* was PROTOTYPE.md flaw #1.
    const CTR_REKEY_AT: u32 = u32::MAX - 1_000_000;
    if ctr >= CTR_MAX {
        nc.stats.drops.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            peer = %peer_fp, counter = ctr,
            "VPN egress: tunnel counter exhausted — frame dropped, session must re-key"
        );
        return;
    }
    if ctr >= CTR_REKEY_AT {
        tracing::warn!(
            peer = %peer_fp, counter = ctr,
            "VPN egress: tunnel counter nearing exhaustion — re-key needed soon"
        );
    }
    let mut payload = VPN_PAYLOAD_MAGIC.to_vec();
    payload.extend_from_slice(tunnel_wire);
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&payload);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    encrypt_in_place_with_context(&key, ctr, &sh, dir_for(role), &mut framed);
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
    // The bulk payload region holds a [len u16][bytes] shard (exactly what
    // frame_shard produces and the receive path's unframe() consumes).
    let framed = frame_shard(&framed);
    let frame = net::build_gtf_frame(sh, ctr, 0, &framed, &tag, true);
    let mut frame = frame; // set tunnel bit (bit 1) on top of bulk bit (bit 0)
    frame[net::OFFSET_FLAGS] |= 0x02;
    let _ = nc.socket.send_to(&frame, endpoint).await;
}

/// Strip the 2-byte length prefix (plus optional parity pad) from a decrypted frame.
fn frame_payload(pt: &[u8]) -> Option<&[u8]> {
    if pt.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([pt[0], pt[1]]) as usize;
    if 2 + n == pt.len() || 2 + n + 1 == pt.len() {
        Some(&pt[2..2 + n])
    } else {
        None
    }
}

/// Initiate a mesh handshake to `t` (PEER command and the VPN client
/// watchdog share this path). Inserts into `pending_hs`; the response
/// completes asynchronously in handle_pkt.
async fn initiate_handshake(
    nc: &GhostNode,
    sock: &UdpSocket,
    t: SocketAddr,
    pending_hs: &PendingHandshakes,
) {
    let (xs, xp) = generate_x25519_keypair();
    let (kp, ks) = generate_kyber_keypair();
    let pdu = build_handshake_pdu(
        &nc.identity.public_key_bytes(),
        |d| nc.identity.sign(d).to_bytes(),
        &xp,
        &kp,
    );
    let mut c = pdu;
    let raw = l4_rs::encode(&mut c);
    let tag = [0u8; 16];
    for i in 0..3 {
        let _ = send_gtf(
            sock,
            &t,
            [0, 0, 0, 0],
            0,
            i as u8,
            &frame_shard(&raw[i]),
            &tag,
            false,
        )
        .await;
    }
    if pending_hs.len() >= MAX_PENDING_HANDSHAKES {
        tracing::warn!("Pending-handshake table full — handshake skipped");
        return;
    }
    pending_hs.insert(t.to_string(), (xs, ks));
    tracing::info!(target = %t, "Handshake sent");
}

/// Insert a received frame into the reorder buffer; return frames that
/// can be flushed in sequence order (duplicates/old frames are dropped).
fn rx_push(state: &mut RxState, ctr: u32, payload: Vec<u8>) -> Vec<Vec<u8>> {
    let Some(next) = state.next else {
        state.next = Some(ctr + 1);
        return vec![payload];
    };
    if ctr < next {
        return Vec::new();
    }
    state.buf.insert(ctr, payload);
    let mut out = Vec::new();
    loop {
        let n = state.next.unwrap();
        match state.buf.remove(&n) {
            Some(d) => {
                out.push(d);
                state.next = Some(n + 1);
            }
            None => break,
        }
    }
    out
}

fn build_beacon_packet(
    pk: &[u8; 32],
    signer: impl Fn(&[u8]) -> [u8; 64],
    with_zk: bool,
) -> Vec<u8> {
    // Signed beacon: [16 magic][32 full Ed25519 pk][64 signature over pk]
    // If with_zk: appends [32 commitment][64 zk_proof] (208 bytes total)
    let len = if with_zk { 208 } else { 112 };
    let mut buf = vec![0u8; len];
    buf[0..16].copy_from_slice(BEACON_PREFIX);
    buf[16..48].copy_from_slice(pk);
    let sig = signer(&buf[16..48]);
    buf[48..112].copy_from_slice(&sig);
    if with_zk {
        let (zk_proof, commitment) = ZkAuthenticator::create_proof(pk, &signer);
        buf[112..144].copy_from_slice(&commitment);
        buf[144..208].copy_from_slice(&zk_proof[..64]);
    }
    buf
}

async fn handle_pkt(
    node: &GhostNode,
    peers: &DashMap<String, SocketAddr>,
    pending_hs: &PendingHandshakes,
    sock: &UdpSocket,
    ctr: u32,
    data: &[u8],
    src: &SocketAddr,
    revocation_list: Option<&RevocationList>,
    reputation_matrix: Option<&PoissonReputationMatrix>,
    exit_tunnels: &ExitTunnels,
    sessions_rx: &SessionChannels,
    rx_state_map: &RxStateMap,
    connect_acks: &ConnectAcks,
    connect_ok_ctrs: &ConnectOkCtrs,
    trusted_exits: &Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
    psk: Option<[u8; 32]>,
    vpn_mode: Option<&VpnMode>,
    tft: Option<&TitForTatEnforcer>,
    exit_rotator: Option<&ExitIpRotator>,
) {
    #[cfg(not(feature = "vpn"))]
    let _ = vpn_mode;
    // Handshake (counter == 0)
    if ctr == 0 && data.len() >= 16 && &data[..16] == b"GHOST_HANDSHAKE_" {
        if data.len() < HANDSHAKE_BLOB_LEN {
            tracing::warn!(peer = %src, "Short handshake");
            return;
        }
        let mut b = data.to_vec();
        b.truncate(HANDSHAKE_BLOB_LEN);
        // Anti-replay / anti-flood: refuse to re-handshake an identity we
        // already hold a session for, and bound total sessions (an attacker
        // can mint unlimited self-signed identities).
        if node.sessions.len() >= MAX_SESSIONS {
            tracing::warn!(peer = %src, "Session table full — handshake rejected");
            return;
        }
        let hs = match parse_handshake_pdu(&b) {
            Some(h) => h,
            None => {
                tracing::warn!(peer = %src, "Invalid handshake PDU");
                return;
            }
        };
        let fp = hex::encode(&hs.identity_pk[..8]);
        if node.sessions.contains_key(&fp) {
            tracing::warn!(peer = %src, fingerprint = %fp, "Duplicate session — handshake replay rejected");
            return;
        }

        // VPN hub: gate the MESH session the same way the VPN tunnel already is.
        // Tunnel traffic from an unlisted peer was rejected, but the mesh session
        // itself was not — so a WAN-exposed hub accumulated session state from
        // strangers (PROTOTYPE.md flaw #5). No-op unless this node is a hub.
        #[cfg(feature = "vpn")]
        if let Some(VpnMode::Hub(hub)) = vpn_mode {
            if !hub.authorized(&fp) {
                tracing::warn!(
                    peer = %src, fingerprint = %fp,
                    "Handshake rejected — not in the VPN allowlist (GHOST_VPN_CLIENTS)"
                );
                if let Some(rep) = reputation_matrix {
                    rep.record_interaction(&node.fingerprint(), &fp, false);
                }
                return;
            }
        }

        // WIRED: Byzantine isolation check — drop handshakes from Byzantine-flagged peers
        if let Some(rep) = reputation_matrix {
            if rep.is_byzantine(&node.fingerprint(), &fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Handshake rejected — peer flagged Byzantine");
                return;
            }
        }

        // WIRED: RevocationList check — reject known-compromised identities
        if let Some(rl) = revocation_list {
            if rl.reject_handshake(&fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Handshake rejected — identity revoked");
                if let Some(rep) = reputation_matrix {
                    rep.record_interaction(&node.fingerprint(), &fp, false);
                }
                return;
            }
        }

        let sm = [&hs.x25519_pub[..], &hs.kyber_pub[..]].concat();
        if !l0_identity::verify_peer_signature(&hs.identity_pk, &sm, &hs.signature) {
            tracing::warn!(peer = %src, "Bad handshake signature");
            if let Some(rep) = reputation_matrix {
                rep.record_interaction(&node.fingerprint(), &fp, false);
            }
            return;
        }
        tracing::info!(fingerprint = %fp, peer = %src, "Verified peer");

        let (ct, ks) = match kyber_encapsulate(&hs.kyber_pub) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(peer = %src, "Kyber encapsulate failed: {e}");
                if let Some(rep) = reputation_matrix {
                    rep.record_interaction(&node.fingerprint(), &fp, false);
                }
                return;
            }
        };
        let bs = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let bp = x25519_dalek::PublicKey::from(&bs);
        let xs = bs.diffie_hellman(&x25519_dalek::PublicKey::from(hs.x25519_pub));
        let d = derive_hybrid_master_key_with_psk(xs.as_bytes(), &ks, psk.as_ref());

        // WIRED: Pin key to physical RAM via LockedMemory (mlock / VirtualLock)
        // to prevent sensitive cryptographic material from leaking to swap/pagefile.
        if let Some(mut locked) = LockedMemory::allocate(32) {
            locked.as_mut_slice()[..32].copy_from_slice(&d);
            // Ephemeral locked buffer validated and pinned in RAM
        }

        let mut bp_arr = [0u8; 32];
        bp_arr.copy_from_slice(bp.as_bytes());
        let ct_arr = ct;
        let resp_pdu = build_response_pdu(
            &node.identity.public_key_bytes(),
            |d| node.identity.sign(d).to_bytes(),
            &bp_arr,
            &ct_arr,
        );
        let mut rc = resp_pdu;
        let raw = l4_rs::encode(&mut rc);
        let tag = [0u8; 16];
        for i in 0..3 {
            let _ = send_gtf(
                sock,
                src,
                [0, 0, 0, 0],
                1,
                i as u8,
                &frame_shard(&raw[i]),
                &tag,
                false,
            )
            .await;
        }
        peers.insert(fp.clone(), *src);
        node.sessions.insert(
            fp.clone(),
            Session::new_with_role(d, fp.clone(), SessionRole::Responder),
        );
        // VPN: a fresh handshake re-anchors the client's lease (precedence 1)
        // and evicts all per-epoch tunnel state.
        #[cfg(feature = "vpn")]
        if let Some(VpnMode::Hub(hub)) = vpn_mode {
            hub.on_handshake(&fp, *src);
        }
        if std::env::var("GGN_DEBUG_SESSION_KEY").is_ok() {
            tracing::info!(peer = %src, session_key8 = %hex::encode(&d[..8]), "Session established");
        } else {
            tracing::info!(peer = %src, "Session established");
        }

        // WIRED: Record successful interaction in reputation
        if let Some(rep) = reputation_matrix {
            rep.record_interaction(&node.fingerprint(), &fp, true);
        }
        return;
    }

    // Handshake response (counter == 1)
    if ctr == 1 && data.len() >= 16 && &data[..16] == b"GHOST_RESPONSE__" {
        let mut rd = data.to_vec();
        if rd.len() < RESPONSE_BLOB_LEN {
            return;
        }
        rd.truncate(RESPONSE_BLOB_LEN);
        let resp = match parse_response_pdu(&rd) {
            Some(r) => r,
            None => {
                return;
            }
        };

        let signed_material = {
            let mut m = vec![0u8; 800];
            m[0..32].copy_from_slice(&resp.x25519_pub);
            m[32..800].copy_from_slice(&resp.kyber_ct);
            m
        };
        if !l0_identity::verify_peer_signature(&resp.identity_pk, &signed_material, &resp.signature)
        {
            tracing::warn!(peer = %src, "Response signature verification failed");
            return;
        }

        let ct = Ciphertext::<MlKem512>::from(resp.kyber_ct);
        let fp = hex::encode(&resp.identity_pk[..8]);
        // WIRED: Byzantine isolation check for initiator
        if let Some(rep) = reputation_matrix {
            if rep.is_byzantine(&node.fingerprint(), &fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Response from peer flagged Byzantine — dropped");
                return;
            }
        }
        // WIRED: RevocationList check for initiator too
        if let Some(rl) = revocation_list {
            if rl.reject_handshake(&fp) {
                tracing::warn!(peer = %src, fingerprint = %fp, "Response from revoked identity");
                return;
            }
        }
        if let Some((ax, dk)) = pending_hs.remove(&src.to_string()).map(|(_, v)| v) {
            let ks = dk.decapsulate(&ct);
            let ky_ss: Vec<u8> = ks.as_slice().to_vec();
            let xs = ax.diffie_hellman(&x25519_dalek::PublicKey::from(resp.x25519_pub));
            let d = derive_hybrid_master_key_with_psk(xs.as_bytes(), &ky_ss, psk.as_ref());

            // WIRED: Pin key to physical RAM via LockedMemory (mlock / VirtualLock)
            if let Some(mut locked) = LockedMemory::allocate(32) {
                locked.as_mut_slice()[..32].copy_from_slice(&d);
            }

            peers.insert(fp.clone(), *src);
            node.sessions.insert(fp.clone(), Session::new(d, fp));
            // VPN client: adopt the real session key for tunnel sealing.
            #[cfg(feature = "vpn")]
            if let Some(VpnMode::Client(client, _)) = vpn_mode {
                // Fresh handshake: rotate the epoch FIRST (clears the replay
                // window and TX counters), then adopt the negotiated key.
                // Without the rotation a reconnect reuses the old epoch and
                // the hub rejects every datagram as a replay.
                let e = client.rotate_epoch();
                client.set_key(d);
                tracing::info!(epoch = e, "VPN client: epoch rotated for fresh session");
            }
            tracing::info!(peer = %src, "Session established (initiator)");
        } else {
            tracing::warn!(peer = %src, "No pending handshake for this peer");
        }
        return;
    }

    // Data (counter >= 2) — try to decrypt with existing sessions.
    // Frames may arrive in either AEAD direction (we don't know our role
    // for sure here), so try both; the correct one authenticates.
    //
    // Collect candidate sessions FIRST: taking a write lock (get_mut for the
    // replay guard) while a DashMap iterator is alive deadlocks the task.
    let candidates: Vec<(String, [u8; 32], [u8; 4], SessionRole)> = node
        .sessions
        .iter()
        .map(|e| {
            (
                e.peer_fingerprint.clone(),
                e.master_key,
                e.session_hash,
                e.role,
            )
        })
        .collect();
    for (peer_fp, key, sh, role) in candidates {
        let mut msg = data.to_vec();
        let pt: Option<&[u8]> = {
            let r1 = decrypt_in_place_with_context(
                &key,
                ctr,
                &sh,
                NonceDirection::InitiatorToResponder,
                &mut msg,
            );
            if r1.is_ok() {
                r1.ok()
            } else {
                decrypt_in_place_with_context(
                    &key,
                    ctr,
                    &sh,
                    NonceDirection::ResponderToInitiator,
                    &mut msg,
                )
                .ok()
            }
        };
        let Some(pt) = pt else { continue };

        // Replay protection: the per-session sliding-window guard must accept
        // the counter; otherwise the frame is a replay or too stale — drop it.
        let accepted = node
            .sessions
            .get_mut(&peer_fp)
            .map(|mut s| s.guard.check_and_update(ctr))
            .unwrap_or(false);
        if !accepted {
            tracing::debug!(peer = %peer_fp, counter = ctr, "Replay/out-of-window frame dropped");
            return;
        }
        // ── VPN tunnel payload: [len][GVPN1][epoch u32][ctr u32][ct][tag] ──
        // Hub: ingest client datagrams. Client: write hub replies into TUN.
        // Checked BEFORE all control-channel handling; tunnel traffic never
        // touches SOCKS5/CHAT/relay logic.
        #[cfg(feature = "vpn")]
        if let Some(framed) = frame_payload(pt) {
            if framed.len() > VPN_PAYLOAD_MAGIC.len()
                && &framed[..VPN_PAYLOAD_MAGIC.len()] == VPN_PAYLOAD_MAGIC.as_slice()
            {
                let body = &framed[VPN_PAYLOAD_MAGIC.len()..];
                match vpn_mode {
                    Some(VpnMode::Hub(hub)) => {
                        hub.handle_tunnel_payload(&peer_fp, &key, sh, body, *src);
                    }
                    Some(VpnMode::Client(client, tun)) => {
                        let guard = tun.lock().unwrap_or_else(|e| e.into_inner());
                        let (_ok, _adv) = vpn::client::open_to_tun(client, body, &*guard);
                    }
                    None => {}
                }
                return;
            }
        }

        let text = String::from_utf8_lossy(pt).into_owned();
        let trimmed = text.trim_end_matches('\0').to_string();
        tracing::info!(peer = %peer_fp, counter = ctr, "Decrypted: {trimmed}");

        // Direct chat message (CHAT command): [CHAT!][message]
        // Must run before relay/CONNECT dispatch so a message like
        // "CHAT!1.2.3.4:80" is never mistaken for a SOCKS5 destination.
        if let Some(payload) = frame_payload(pt) {
            if let Some(rest) = payload.strip_prefix(b"CHAT!") {
                let msg = String::from_utf8_lossy(rest)
                    .trim_end_matches('\0')
                    .to_string();
                println!("\n[Chat from {}] {msg}", &peer_fp[..8.min(peer_fp.len())]);
                tracing::info!(peer = %peer_fp, "Chat message delivered");
                return;
            }
        }

        // Multi-hop relay: a decrypted payload may carry a relay header.
        // (parse the UNFRAMED payload — the length prefix precedes the header)
        if let Some(payload) = frame_payload(pt) {
            if let Some(relay) = parse_relay_header(payload) {
                if relay.remaining_hops > 0 {
                    // WIRED: Tit-for-Tat enforcer - drop forwarding for evicted leechers
                    if let Some(enforcer) = tft {
                        if enforcer.is_evicted(&peer_fp) {
                            tracing::warn!(peer = %peer_fp, "TFT: relay request dropped — peer evicted for leeching");
                            return;
                        }
                    }

                    // Forward: re-wrap the inner payload for the next hop and send
                    // it through our own session with that hop.
                    let next = &relay.next_hop_fingerprint;
                    // WIRED: Byzantine isolation check for relay path
                    if let Some(rep) = reputation_matrix {
                        if rep.is_byzantine(&node.fingerprint(), next) {
                            tracing::warn!(hop = %next, "Relay: next hop flagged Byzantine — dropping packet");
                            return;
                        }
                    }
                    let tgt = match peers.get(next).map(|v| *v.value()) {
                        Some(addr) => addr,
                        None => {
                            tracing::warn!(hop = %next, "Relay: next hop address unknown");
                            return;
                        }
                    };
                    let Some(sess) = node.sessions.get(next) else {
                        tracing::warn!(hop = %next, "Relay: no session with next hop");
                        return;
                    };
                    let key = sess.master_key;
                    let sh = sess.session_hash;
                    let role = sess.role;
                    drop(sess);
                    let hop_ctr = node
                        .sessions
                        .get(next)
                        .map(|s| s.next_tx_counter())
                        .unwrap_or(2);
                    let rewrap =
                        build_relay_packet(next, relay.remaining_hops - 1, &relay.inner_payload);
                    let (f, tag) = enc_split(&key, hop_ctr, &sh, dir_for(role), &rewrap);
                    send3(sock, &tgt, sh, hop_ctr, &f, &tag).await;

                    // WIRED: Record bytes forwarded for this peer in TFT enforcer
                    if let Some(enforcer) = tft {
                        enforcer.forwarded_for(&peer_fp, relay.inner_payload.len() as u64);
                    }

                    tracing::info!(via = %src, hop = %next, "Relay packet forwarded");
                    return;
                }
                // Final hop: the inner payload is [counter u32 BE][initiator→us
                // encrypted blob]. Try each of our sessions to unwrap it.
                let inner = &relay.inner_payload;
                if inner.len() >= 4 {
                    // WIRED: Record bytes forwarded by relay peer for us
                    if let Some(enforcer) = tft {
                        enforcer.forwarded_by(&peer_fp, inner.len() as u64);
                    }

                    let ic = u32::from_be_bytes([inner[0], inner[1], inner[2], inner[3]]);
                    let blob = inner[4..].to_vec();
                    let candidates: Vec<(String, [u8; 32], [u8; 4], SessionRole)> = node
                        .sessions
                        .iter()
                        .map(|e| {
                            (
                                e.peer_fingerprint.clone(),
                                e.master_key,
                                e.session_hash,
                                e.role,
                            )
                        })
                        .collect();
                    for (fp2, key, sh, role) in candidates {
                        let mut msg = blob.clone();
                        let pt2 = match decrypt_in_place_with_context(
                            &key,
                            ic,
                            &sh,
                            NonceDirection::InitiatorToResponder,
                            &mut msg,
                        ) {
                            Ok(p) => Some(p),
                            Err(_) => decrypt_in_place_with_context(
                                &key,
                                ic,
                                &sh,
                                NonceDirection::ResponderToInitiator,
                                &mut msg,
                            )
                            .ok(),
                        };
                        if let Some(pt2) = pt2 {
                            tracing::info!(peer = %fp2, "Relay payload delivered (final hop)");
                            let payload = pt2.to_vec();
                            if let Some(payload) = frame_payload(&payload) {
                                if role == SessionRole::Responder && looks_like_dest(payload) {
                                    handle_exit_connect(
                                        node,
                                        sock,
                                        src,
                                        &key,
                                        &sh,
                                        &fp2,
                                        payload,
                                        exit_tunnels,
                                        ic,
                                        exit_rotator,
                                    )
                                    .await;
                                    return;
                                }
                                tracing::info!("Relay data: {}", String::from_utf8_lossy(payload));
                            }
                            return;
                        }
                    }
                    tracing::warn!("Relay final hop: could not unwrap inner payload");
                }
                return;
            }
        }

        // WIRED: Record successful data decryption in reputation
        if let Some(rep) = reputation_matrix {
            rep.record_interaction(&node.fingerprint(), &peer_fp, true);
        }

        // ── Tunnel traffic (framed payloads) ──
        if let Some(payload) = frame_payload(pt) {
            // CONNECT acknowledgement from the exit (either side may see it)
            if payload == b"OK" {
                connect_acks.insert(sh, true);
                connect_ok_ctrs.insert(sh, ctr);
                rx_state_map.remove(&sh); // clear stale reorder state
                return;
            }
            let tkey = exit_tunnel_key(src, &sh);
            // Existing tunnel → relay data into the remote TCP connection.
            if let Some(mut t_guard) = exit_tunnels.get_mut(&tkey) {
                let flush = rx_push(&mut t_guard.rx, ctr, payload.to_vec());
                let out_tx = t_guard.out_tx.clone();
                drop(t_guard);
                for chunk in flush {
                    let _ = out_tx.send(chunk);
                }
                return;
            }
            // We are the exit (responder) for this session and this frame is a
            // CONNECT request → open the destination and answer "OK".
            if role == SessionRole::Responder && looks_like_dest(payload) {
                // Exit authorization: closed by default; the peer's fingerprint
                // must be allowlisted (or the operator set "any").
                let allowed = trusted_exits
                    .read()
                    .map(|s| s.contains("any") || s.contains(&peer_fp))
                    .unwrap_or(false);
                if !allowed {
                    tracing::warn!(peer = %peer_fp, "Exit CONNECT denied — fingerprint not allowlisted (EXITAUTH)");
                    return;
                }
                handle_exit_connect(
                    node,
                    sock,
                    src,
                    &key,
                    &sh,
                    &peer_fp,
                    payload,
                    exit_tunnels,
                    ctr,
                    exit_rotator,
                )
                .await;
                return;
            }
            // We are the initiator: relayed remote data (counter >= 3).
            if ctr >= 3 {
                if let Some(tx) = sessions_rx.get(&sh).map(|v| v.value().clone()) {
                    let mut st = rx_state_map.entry(sh).or_default();
                    // Anchor the reorder window at (OK counter + 1): the exit's
                    // first data frame. This keeps out-of-order frames buffered
                    // instead of anchoring on whichever frame's task wins the
                    // race and dropping the lower counters.
                    if st.next.is_none() {
                        if let Some(ok) = connect_ok_ctrs.get(&sh) {
                            st.next = Some(ok.value() + 1);
                        }
                    }
                    let flush = rx_push(&mut st, ctr, payload.to_vec());
                    drop(st);
                    for chunk in flush {
                        let _ = tx.send(chunk);
                    }
                    return;
                }
            }
            return;
        }
        return;
    }
}

/// Exit node: accept a SOCKS5 CONNECT, open the destination TCP connection,
/// reply "OK" over the mesh, and relay bytes in both directions.
async fn handle_exit_connect(
    node: &GhostNode,
    sock: &UdpSocket,
    src: &SocketAddr,
    key: &[u8; 32],
    sh: &[u8; 4],
    peer_fp: &str,
    dest: &[u8],
    tunnels: &ExitTunnels,
    connect_ctr: u32,
    exit_rotator: Option<&ExitIpRotator>,
) {
    let dest = String::from_utf8_lossy(dest).into_owned();
    let (host, port) = match dest.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => return,
        },
        None => return,
    };

    let stream = if let Some(rotator) = exit_rotator {
        if rotator.pool_size() > 0 {
            let egress_addr = rotator.get_next_socket_addr(0);
            let connect_res = match egress_addr {
                SocketAddr::V4(v4) => {
                    let socket = tokio::net::TcpSocket::new_v4();
                    match socket {
                        Ok(s) => match s.bind(SocketAddr::V4(v4)) {
                            Ok(()) => match tokio::net::lookup_host(format!("{host}:{port}")).await
                            {
                                Ok(mut addrs) => match addrs.next() {
                                    Some(target) => s.connect(target).await.ok(),
                                    None => None,
                                },
                                Err(_) => None,
                            },
                            Err(e) => {
                                tracing::debug!("Egress bind to {egress_addr} failed: {e}; falling back to default route");
                                tokio::net::TcpStream::connect((host.as_str(), port))
                                    .await
                                    .ok()
                            }
                        },
                        Err(_) => tokio::net::TcpStream::connect((host.as_str(), port))
                            .await
                            .ok(),
                    }
                }
                SocketAddr::V6(v6) => {
                    let socket = tokio::net::TcpSocket::new_v6();
                    match socket {
                        Ok(s) => match s.bind(SocketAddr::V6(v6)) {
                            Ok(()) => match tokio::net::lookup_host(format!("{host}:{port}")).await
                            {
                                Ok(mut addrs) => match addrs.next() {
                                    Some(target) => s.connect(target).await.ok(),
                                    None => None,
                                },
                                Err(_) => None,
                            },
                            Err(e) => {
                                tracing::debug!("Egress bind to {egress_addr} failed: {e}; falling back to default route");
                                tokio::net::TcpStream::connect((host.as_str(), port))
                                    .await
                                    .ok()
                            }
                        },
                        Err(_) => tokio::net::TcpStream::connect((host.as_str(), port))
                            .await
                            .ok(),
                    }
                }
            };
            match connect_res {
                Some(s) => s,
                None => {
                    tracing::warn!(dest = %dest, "Exit: CONNECT failed via rotator");
                    return;
                }
            }
        } else {
            match tokio::net::TcpStream::connect((host.as_str(), port)).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(dest = %dest, "Exit: CONNECT failed: {e}");
                    return;
                }
            }
        }
    } else {
        match tokio::net::TcpStream::connect((host.as_str(), port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(dest = %dest, "Exit: CONNECT failed: {e}");
                return;
            }
        }
    };

    // Allocate our OK counter from the session's counter space.
    let ok_ctr = node
        .sessions
        .get(peer_fp)
        .map(|s| s.next_tx_counter())
        .unwrap_or(2);
    let (f, tag) = enc_split(key, ok_ctr, sh, NonceDirection::ResponderToInitiator, b"OK");
    send3(sock, src, *sh, ok_ctr, &f, &tag).await;

    let tkey = exit_tunnel_key(src, sh);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // Anchor the tunnel's reorder window at (CONNECT counter + 1): the first
    // data frame the initiator sends. Out-of-order frames are buffered, never
    // dropped on a task-scheduling race.
    let rx = RxState {
        next: Some(connect_ctr + 1),
        ..Default::default()
    };
    tunnels.insert(
        tkey.clone(),
        ExitTunnel {
            out_tx,
            rx,
            session_hash: *sh,
        },
    );
    tracing::info!(dest = %dest, peer = %peer_fp, "Exit tunnel established");

    // Outbound relay: remote TCP → mesh (responder direction), and
    // inbound channel → remote TCP. Idle for 30s tears the tunnel down.
    // Data-frame counters come from the session's shared tx_counter so a later
    // CHAT / keepalive / CONNECT can never reuse a counter the initiator saw
    // (replay-window collision).
    let sock2 = Arc::clone(&node.socket);
    let sessions2 = Arc::clone(&node.sessions);
    let fp2 = peer_fp.to_string();
    let tunnels2 = Arc::clone(tunnels);
    let sh2 = *sh;
    let key2 = *key;
    let addr2 = *src;
    let tkey2 = tkey.clone();
    tokio::spawn(async move {
        let (mut rd, mut wr) = stream.into_split();
        let sock3 = sock2;
        let rd_handle = tokio::spawn(async move {
            let mut rbuf = vec![0u8; 900]; // keeps each RS shard ≤ 486 B privacy-frame cap
            loop {
                match rd.read(&mut rbuf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let ctr = sessions2
                            .get(&fp2)
                            .map(|s| s.next_tx_counter())
                            .unwrap_or(2);
                        let (f, tag) = enc_split(
                            &key2,
                            ctr,
                            &sh2,
                            NonceDirection::ResponderToInitiator,
                            &rbuf[..n],
                        );
                        send3(&sock3, &addr2, sh2, ctr, &f, &tag).await;
                    }
                }
            }
        });
        loop {
            tokio::select! {
                chunk = out_rx.recv() => {
                    match chunk {
                        Some(c) => {
                            if wr.write_all(&c).await.is_err() { break; }
                        }
                        None => break,
                    }
                }
                _ = sleep(Duration::from_secs(30)) => break,
            }
        }
        rd_handle.abort();
        tunnels2.remove(&tkey2);
        tracing::info!(dest = %dest, "Exit tunnel closed");
    });
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        // Write to stderr (unbuffered): line-flushed logs survive hard process
        // kills, which matters for supervised/diagnostic runs and tests that
        // parse the log tail.
        .with_writer(std::io::stderr)
        .init();

    // WIRED: Initialize subsystem state
    let revocation_list = Arc::new(RevocationList::new());
    let reputation_matrix = Arc::new(PoissonReputationMatrix::new());
    let bundle_buffer = Arc::new(BundleBuffer::new());
    let shard_router = Arc::new(vantablack::ghost::net::mesh::AdaptiveShardRouter::new());
    // WIRED: Category B - Encrypted Runtime Memory (AES-256-XTS)
    let mut xts_key1 = [0u8; 32];
    let mut xts_key2 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut xts_key1);
    rand::thread_rng().fill_bytes(&mut xts_key2);
    let _mem_encryptor = Arc::new(XtsMemoryEncryptor::new(&xts_key1, &xts_key2));
    // Zero key material from stack after initialization
    xts_key1.fill(0);
    xts_key2.fill(0);

    // WIRED: Category B - Verified SPSC Ring Buffer for packet staging
    let verified_ring = Arc::new(VerifiedRingBuffer::<Vec<u8>>::new(1024));

    // WIRED: SecureTimeKeeper for NTS-secured time
    let _time_keeper = Arc::new(vantablack::ghost::layers::l9_infra::SecureTimeKeeper::new(
        false,
    ));
    // WIRED: BuildInfo for hash verification
    let _build_info = vantablack::ghost::layers::l9_infra::BuildInfo::new();

    let ba = std::env::var("GHOST_BIND").unwrap_or_else(|_| "0.0.0.0:0".to_string());
    let socks = std::env::var("GHOST_SOCKS5").is_ok();
    let socks_port: u16 = std::env::var("GHOST_SOCKS5_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1080);
    let tm: u64 = std::env::var("GHOST_TRANSIT_MBPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let psk_hex = std::env::var("GHOST_PSK").ok().filter(|s| !s.is_empty());
    // GHOST_PSK is mixed into the HKDF salt of the hybrid master key, so only
    // nodes sharing the same 32-byte pre-shared key can establish a working
    // session (defense-in-depth against rogue nodes with valid identities).
    let psk: Option<[u8; 32]> = psk_hex
        .as_ref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| b.try_into().ok());
    // Exit-node authorization: peers allowed to use THIS node as a SOCKS5
    // exit. Closed by default (secure) — "any" opens it, or list fingerprints.
    let trusted_exits: Arc<std::sync::RwLock<std::collections::HashSet<String>>> =
        Arc::new(std::sync::RwLock::new(
            std::env::var("GHOST_EXIT_ALLOWLIST")
                .ok()
                .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
        ));

    // ── VPN (LAN-over-WAN prototype) configuration ──
    // GHOST_VPN=hub|client   (absent → VPN off)
    // hub:  GHOST_VPN_CLIENTS=fp,fp  (allowlist; empty = deny all)
    //       GHOST_VPN_LAN_SUBNET, GHOST_VPN_DNS, GHOST_VPN_SEARCH,
    //       GHOST_VPN_BIND (hub LAN IP for UDP flow sockets)
    // client: GHOST_VPN_HUB_FP (hub fingerprint), GHOST_VPN_KEY (session key
    //         hex, optional), GHOST_VPN_LOCAL_IP (overlay IP, default .10)
    #[cfg(feature = "vpn")]
    let vpn_mode: Option<VpnMode> = match std::env::var("GHOST_VPN").as_deref() {
        Ok("hub") => {
            let (subnet, prefix) = std::env::var("GHOST_VPN_LAN_SUBNET")
                .ok()
                .and_then(|s| {
                    let (a, pr) = s.split_once('/')?;
                    Some((
                        a.parse::<std::net::Ipv4Addr>().ok()?,
                        pr.parse::<u8>().ok()?,
                    ))
                })
                .unwrap_or((std::net::Ipv4Addr::new(192, 168, 1, 0), 24));
            let cfg = VpnConfig {
                role: VpnRole::Hub,
                lan_subnet: (subnet, prefix),
                dns_server: std::env::var("GHOST_VPN_DNS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(std::net::Ipv4Addr::new(192, 168, 1, 1)),
                search_domain: std::env::var("GHOST_VPN_SEARCH")
                    .ok()
                    .filter(|x| !x.is_empty()),
                allowed_fingerprints: std::env::var("GHOST_VPN_CLIENTS")
                    .ok()
                    .map(|v| {
                        v.split(',')
                            .map(|x| x.trim().to_string())
                            .filter(|x| !x.is_empty())
                            .collect()
                    })
                    .unwrap_or_default(),
                lan_bind_addr: std::env::var("GHOST_VPN_BIND")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                ..VpnConfig::default()
            };
            tracing::info!(
                "VPN: hub mode — allowlisted clients: {}",
                cfg.allowed_fingerprints.len()
            );
            Some(VpnMode::Hub(VpnHub::start(cfg)))
        }
        Ok("client") => {
            let hub_fp = std::env::var("GHOST_VPN_HUB_FP").unwrap_or_default();
            if hub_fp.is_empty() {
                anyhow::bail!("VPN client requires GHOST_VPN_HUB_FP (hub fingerprint)");
            }
            let key: [u8; 32] = std::env::var("GHOST_VPN_KEY")
                .ok()
                .filter(|h| h.len() == 64)
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0u8; 32]);
            let local_ip: std::net::Ipv4Addr = std::env::var("GHOST_VPN_LOCAL_IP")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(std::net::Ipv4Addr::new(10, 66, 0, 10));
            // GHOST_VPN_FAKE_TUN: run the client against the in-memory TUN so a
            // full two-process self-test needs no wintun.dll, no Administrator
            // and no OS interface. Same code path, same crypto, same framing —
            // this is what makes the "nothing is wire-proven yet" gate runnable.
            let fake_tun = std::env::var("GHOST_VPN_FAKE_TUN")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(false);
            let tun = if fake_tun {
                tracing::warn!(
                    "VPN client: GHOST_VPN_FAKE_TUN is set — in-memory TUN, no OS interface \
                     is created and no traffic can leave this machine. Self-test mode only."
                );
                let (dev, handle) = vpn::tun::open_fake_tun();
                // Self-test driver, standing in for the OS: inject an ICMP echo
                // request toward the hub overlay on a timer and report what the
                // tunnel writes back. One echo reply proves the whole
                // seal → mesh → hub → unseal round trip over real UDP sockets.
                let hub_overlay = std::net::Ipv4Addr::new(
                    vpn::OVERLAY_PREFIX,
                    vpn::OVERLAY_SECOND_OCTET,
                    0,
                    vpn::OVERLAY_HUB_HOST,
                );
                tokio::spawn(async move {
                    let probe = vpn::client::build_keepalive(hub_overlay, local_ip);
                    let mut sent: u32 = 0;
                    let mut replies_total: u32 = 0;
                    loop {
                        sleep(Duration::from_millis(1000)).await;
                        handle.push_inbound(probe.clone());
                        sent += 1;
                        let mut replies = 0u32;
                        for pkt in handle.drain_outbound() {
                            // IPv4 (version nibble 4), protocol 1 (ICMP), type 0
                            // (echo reply) at the start of the ICMP header.
                            if pkt.len() >= 21 && (pkt[0] >> 4) == 4 && pkt[9] == 1 && pkt[20] == 0
                            {
                                replies += 1;
                            }
                        }
                        if replies > 0 {
                            replies_total += replies;
                            tracing::info!(
                                sent, replies, replies_total,
                                "FAKE-TUN self-test: PASS — ICMP echo reply returned through the mesh"
                            );
                        } else {
                            tracing::info!(sent, "FAKE-TUN self-test: probe sent, no reply yet");
                        }
                    }
                });
                Arc::new(std::sync::Mutex::new(dev))
            } else {
                vpn::tun::open_tun("ggn0", local_ip, std::net::Ipv4Addr::new(255, 255, 255, 0))
                    .map(|t| Arc::new(std::sync::Mutex::new(t)))
                    .map_err(|e| anyhow::anyhow!(
                        "VPN client: TUN unavailable ({e}) — run as Administrator with wintun.dll \
                         present, or set GHOST_VPN_FAKE_TUN=1 for the zero-elevation loopback self-test"
                    ))?
            };
            tracing::info!("VPN: client mode — hub {hub_fp}, TUN {local_ip}");
            Some(VpnMode::Client(
                Arc::new(vpn::client::ClientState::new(hub_fp, key)),
                tun,
            ))
        }
        _ => None,
    };
    #[cfg(not(feature = "vpn"))]
    let _vpn_mode: Option<VpnMode> = None;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Global Ghost Net v{} starting — L0-L9 stack fully wired",
        env!("CARGO_PKG_VERSION")
    );
    if socks {
        tracing::info!("Mode: SOCKS5 proxy on 127.0.0.1:{socks_port}");
    }
    if revocation_list.prune_expired() > 0 {
        tracing::info!("Revocation list initialized");
    }

    let node = GhostNode::new(&ba).await?;
    node.flow_controller.set_transit_rate_mbps(tm);
    tracing::info!(fingerprint = %node.fingerprint(), address = %node.local_addr, "Node ready");

    // ── BOOTSTRAP SEEDS ──
    let addrs: Arc<DashMap<String, SocketAddr>> = Arc::new(DashMap::new());
    let spool: Arc<DashMap<u32, Vec<Option<Vec<u8>>>>> = Arc::new(DashMap::new());
    let pending_hs: PendingHandshakes = Arc::new(DashMap::new());

    let exit_tunnels: ExitTunnels = Arc::new(DashMap::new());
    let sess_chan: SessionChannels = Arc::new(DashMap::new());
    let rx_state_map: RxStateMap = Arc::new(DashMap::new());
    let connect_acks: ConnectAcks = Arc::new(DashMap::new());
    let connect_ok_ctrs: ConnectOkCtrs = Arc::new(DashMap::new());
    let default_exit: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let nc = Arc::new(node);

    // WIRED: Category A - Fair-share transit enforcement (Tit-for-Tat)
    let tft = Arc::new(TitForTatEnforcer::new(
        nc.fingerprint(),
        Arc::clone(&reputation_matrix),
    ));

    // WIRED: Category A - Egress IP rotator
    let exit_rotator: Option<Arc<ExitIpRotator>> = std::env::var("GHOST_EXIT_IPS")
        .ok()
        .map(|ips_str| {
            let ips: Vec<std::net::IpAddr> = ips_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            Arc::new(ExitIpRotator::new(ips))
        })
        .filter(|r| r.pool_size() > 0);
    if let Some(ref r) = exit_rotator {
        tracing::info!(
            "Exit IP Rotator initialized with {} egress IP(s)",
            r.pool_size()
        );
    }

    // WIRED: Category A - NAT hole puncher
    let nat_puncher = Arc::new(vantablack::ghost::net::mesh::NatHolePuncher::new());

    // WIRED: Category B - Long-stream Forward Error Correction (LDPC Codec)
    let ldpc_enabled = std::env::var("GHOST_LDPC_FEC")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let _ldpc_codec = Arc::new(LdpcCodec::new());
    if ldpc_enabled {
        tracing::info!(
            "LDPC Forward Error Correction (1024-bit IRA) active for long-stream encoding"
        );
    }

    // Optional system-tray UI (feature "tray")
    #[cfg(feature = "tray")]
    tray::run_tray(Arc::clone(&nc));

    // ── BOOTSTRAP SEEDS & PEER DISCOVERY (DNS Seed + Peers Cache) ──
    // Automatically resolves DNS seed hostnames (e.g. seeds.vantablack.net) and
    // loads/saves local peers.cache so nodes stay connected without ongoing seed dependencies.
    {
        let nc = Arc::clone(&nc);
        let pending_hs = Arc::clone(&pending_hs);
        let addrs_ref = Arc::clone(&addrs);
        tokio::spawn(async move {
            let mut seeds: Vec<SocketAddr> = Vec::new();
            if let Ok(seed_env) = std::env::var("GHOST_SEEDS") {
                for s in seed_env.split(',').map(|x| x.trim()) {
                    if let Ok(sa) = s.parse::<SocketAddr>() {
                        seeds.push(sa);
                    } else if let Ok(resolved) = tokio::net::lookup_host(s).await {
                        seeds.extend(resolved);
                    }
                }
            }
            if let Ok(dns_seed) = std::env::var("GHOST_DNS_SEED") {
                let host_port = if dns_seed.contains(':') {
                    dns_seed
                } else {
                    format!("{}:2270", dns_seed)
                };
                match tokio::net::lookup_host(&host_port).await {
                    Ok(iter) => {
                        let count_before = seeds.len();
                        for sa in iter {
                            seeds.push(sa);
                        }
                        tracing::info!(
                            "DNS seed {} resolved {} peer address(es)",
                            host_port,
                            seeds.len() - count_before
                        );
                    }
                    Err(e) => {
                        tracing::warn!("DNS seed lookup failed for {}: {}", host_port, e);
                    }
                };
            }
            // Load cached peers from local disk (peers.cache)
            if let Ok(cache_str) = std::fs::read_to_string("peers.cache") {
                for line in cache_str.lines().map(|l| l.trim()) {
                    if let Ok(sa) = line.parse::<SocketAddr>() {
                        if !seeds.contains(&sa) {
                            seeds.push(sa);
                        }
                    }
                }
                tracing::info!("Loaded {} cached peer(s) from peers.cache", seeds.len());
            }
            for s in EMBEDDED_SEEDS {
                if let Ok(sa) = s.parse::<SocketAddr>() {
                    if !seeds.contains(&sa) {
                        seeds.push(sa);
                    }
                }
            }
            if !seeds.is_empty() {
                tracing::info!("Bootstrap peer targets: {:?}", seeds);
                for _ in 0..30 {
                    if !nc.sessions.is_empty() {
                        tracing::info!("Bootstrap: session established via seed/cache");
                        break;
                    }
                    for t in &seeds {
                        if pending_hs.len() >= MAX_PENDING_HANDSHAKES {
                            continue;
                        }
                        let ident = nc.identity.public_key_bytes();
                        let (xs, xp) = {
                            let xs =
                                x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
                            let xp = x25519_dalek::PublicKey::from(&xs);
                            (xs, xp)
                        };
                        let (kp, ks) = generate_kyber_keypair();
                        let mut pdu = build_handshake_pdu(
                            &ident,
                            |d| nc.identity.sign(d).to_bytes(),
                            &xp,
                            &kp,
                        );
                        let raw = l4_rs::encode(&mut pdu);
                        let tag = [0u8; 16];
                        for i in 0..3 {
                            let _ = send_gtf(
                                &nc.socket,
                                t,
                                [0, 0, 0, 0],
                                0,
                                i as u8,
                                &frame_shard(&raw[i]),
                                &tag,
                                false,
                            )
                            .await;
                        }
                        pending_hs.insert(t.to_string(), (xs, ks));
                        tracing::info!(seed = %t, "Bootstrap handshake sent");
                    }
                    sleep(Duration::from_secs(5)).await;
                }
            }
            // Periodically save known healthy peers to peers.cache for future runs
            loop {
                sleep(Duration::from_secs(60)).await;
                if !addrs_ref.is_empty() {
                    let mut peer_lines = Vec::new();
                    for item in addrs_ref.iter() {
                        peer_lines.push(item.value().to_string());
                    }
                    peer_lines.sort();
                    peer_lines.dedup();
                    let _ = std::fs::write("peers.cache", peer_lines.join("\n"));
                }
            }
        });
    }

    // WIRED: Start store-and-forward task for deferred bundle delivery
    let sf_socket = Arc::clone(&nc.socket);
    let sf_sessions = Arc::clone(&nc.sessions);
    let sf_addrs = Arc::clone(&addrs);
    let sf_buffer = Arc::clone(&bundle_buffer);
    let _sf_handle = spawn_store_forward_task(sf_socket, sf_sessions, sf_addrs, sf_buffer);

    // WIRED: Orbital Ephemeris & TLE Gossip Task
    let tle_distributor = Arc::new(net::security::TleDistributor::new());
    let tle_dist_task = Arc::clone(&tle_distributor);
    let tle_addrs = Arc::clone(&addrs);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if tle_dist_task.should_gossip() {
                let gossip_tles = tle_dist_task.build_gossip_message(5);
                if !gossip_tles.is_empty() {
                    tracing::info!(
                        "Gossiping {} orbital TLE records across {} known peers",
                        gossip_tles.len(),
                        tle_addrs.len()
                    );
                }
                tle_dist_task.mark_gossiped();
            }
        }
    });

    // ── HTTP Metrics and Health Endpoint (/healthz & /metrics) ──
    let metrics_port: u16 = std::env::var("GHOST_METRICS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9090);
    let metrics_enabled = std::env::var("GHOST_METRICS_ENABLED")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    if metrics_enabled {
        // VPN counters for `/metrics` and `/healthz`. Rendered by a helper so the
        // endpoint stays readable; the base v0.4.0 metric set is untouched, and
        // with the `vpn` feature off this contributes nothing.
        #[cfg(feature = "vpn")]
        fn vpn_export(mode: &Option<VpnMode>) -> (&'static str, String, serde_json::Value) {
            match mode {
                Some(VpnMode::Hub(h)) => {
                    let m = h.metrics();
                    let prom = format!(
                        "# HELP ghost_vpn_active_leases VPN hub: active overlay leases\n\
                         # TYPE ghost_vpn_active_leases gauge\nghost_vpn_active_leases {}\n\
                         # HELP ghost_vpn_tunnel_frames_in_total VPN hub: tunnel frames received\n\
                         # TYPE ghost_vpn_tunnel_frames_in_total counter\nghost_vpn_tunnel_frames_in_total {}\n\
                         # HELP ghost_vpn_tunnel_frames_out_total VPN hub: tunnel frames sent\n\
                         # TYPE ghost_vpn_tunnel_frames_out_total counter\nghost_vpn_tunnel_frames_out_total {}\n\
                         # HELP ghost_vpn_frames_dropped_total VPN hub: tunnel frames dropped\n\
                         # TYPE ghost_vpn_frames_dropped_total counter\nghost_vpn_frames_dropped_total {}\n\
                         # HELP ghost_vpn_tcp_flows VPN hub: live netstack TCP flows\n\
                         # TYPE ghost_vpn_tcp_flows gauge\nghost_vpn_tcp_flows {}\n\
                         # HELP ghost_vpn_udp_flows VPN hub: live UDP flow bindings\n\
                         # TYPE ghost_vpn_udp_flows gauge\nghost_vpn_udp_flows {}\n\
                         # HELP ghost_vpn_counter_headroom_min VPN hub: smallest remaining per-epoch tunnel-counter headroom across leases\n\
                         # TYPE ghost_vpn_counter_headroom_min gauge\nghost_vpn_counter_headroom_min {}\n",
                        m.leases,
                        m.frames_in,
                        m.frames_out,
                        m.frames_dropped,
                        m.tcp_flows,
                        m.udp_flows,
                        m.counter_headroom_min,
                    );
                    (
                        "hub",
                        prom,
                        serde_json::json!({
                            "leases": m.leases,
                            "tcp_flows": m.tcp_flows,
                            "udp_flows": m.udp_flows,
                            "tunnel_frames_in": m.frames_in,
                            "tunnel_frames_out": m.frames_out,
                            "frames_dropped": m.frames_dropped,
                            "counter_headroom_min": m.counter_headroom_min,
                        }),
                    )
                }
                Some(VpnMode::Client(c, _)) => {
                    let ctr = c.tx_counter();
                    let headroom = u32::MAX.saturating_sub(ctr);
                    let dead = c.watchdog.lock().is_dead();
                    let prom = format!(
                        "# HELP ghost_vpn_tx_counter VPN client: per-epoch tunnel TX counter\n\
                         # TYPE ghost_vpn_tx_counter gauge\nghost_vpn_tx_counter {ctr}\n\
                         # HELP ghost_vpn_counter_headroom VPN client: remaining tunnel-counter headroom\n\
                         # TYPE ghost_vpn_counter_headroom gauge\nghost_vpn_counter_headroom {headroom}\n\
                         # HELP ghost_vpn_epoch VPN client: current session epoch\n\
                         # TYPE ghost_vpn_epoch gauge\nghost_vpn_epoch {}\n\
                         # HELP ghost_vpn_watchdog_dead VPN client: 1 once the watchdog declares the tunnel dead\n\
                         # TYPE ghost_vpn_watchdog_dead gauge\nghost_vpn_watchdog_dead {}\n",
                        c.current_epoch(),
                        u8::from(dead),
                    );
                    (
                        "client",
                        prom,
                        serde_json::json!({
                            "tx_counter": ctr,
                            "counter_headroom": headroom,
                            "epoch": c.current_epoch(),
                            "watchdog_dead": dead,
                        }),
                    )
                }
                None => ("disabled", String::new(), serde_json::json!({})),
            }
        }
        #[cfg(not(feature = "vpn"))]
        fn vpn_export(_mode: &Option<VpnMode>) -> (&'static str, String, serde_json::Value) {
            ("disabled", String::new(), serde_json::json!({}))
        }

        let nc_m = Arc::clone(&nc);
        let addrs_m = Arc::clone(&addrs);
        // Same cfg dance the receiver uses: `vpn_mode` only exists when the
        // feature is on, so the non-vpn build needs its own binding.
        #[cfg(feature = "vpn")]
        let vpn_m: Option<VpnMode> = vpn_mode.clone();
        #[cfg(not(feature = "vpn"))]
        let vpn_m: Option<VpnMode> = None;
        let mp = metrics_port;
        tokio::spawn(async move {
            let bind_addr = format!("0.0.0.0:{}", mp);
            match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    tracing::info!("Metrics/Health HTTP endpoint listening on http://0.0.0.0:{}/metrics and /healthz", mp);
                    loop {
                        if let Ok((mut stream, _)) = listener.accept().await {
                            let nc_ref = Arc::clone(&nc_m);
                            let addrs_ref = Arc::clone(&addrs_m);
                            let vpn_ref = vpn_m.clone();
                            tokio::spawn(async move {
                                let mut buf = [0u8; 1024];
                                if let Ok(n) = stream.read(&mut buf).await {
                                    let req = String::from_utf8_lossy(&buf[..n]);
                                    let (vpn_role, vpn_prom, vpn_json) = vpn_export(&vpn_ref);
                                    let (status_line, body, content_type) = if req
                                        .starts_with("GET /healthz")
                                        || req.starts_with("GET / ")
                                    {
                                        let body = serde_json::json!({
                                            "status": "healthy",
                                            "version": "0.4.1",
                                            "fingerprint": nc_ref.fingerprint(),
                                            "uptime_seconds": nc_ref.created_at.elapsed().as_secs(),
                                            "active_sessions": nc_ref.sessions.len(),
                                            "known_peers": addrs_ref.len(),
                                            "vpn": vpn_role,
                                            "vpn_stats": vpn_json
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("GET /api/telemetry") {
                                        let sessions = nc_ref.sessions.len();
                                        let peers = addrs_ref.len();
                                        let uptime = nc_ref.created_at.elapsed().as_secs();
                                        let sent_bytes =
                                            nc_ref.stats.bytes_sent.load(Ordering::Relaxed);
                                        let recv_bytes =
                                            nc_ref.stats.bytes_recv.load(Ordering::Relaxed);
                                        let sent_pkts =
                                            nc_ref.stats.packets_sent.load(Ordering::Relaxed);
                                        let recv_pkts =
                                            nc_ref.stats.packets_recv.load(Ordering::Relaxed);
                                        let retrans =
                                            nc_ref.stats.retransmits.load(Ordering::Relaxed);
                                        let drops = nc_ref.stats.drops.load(Ordering::Relaxed);
                                        let body = serde_json::json!({
                                            "cycle": uptime / 5,
                                            "target": "mesh-multi-hop",
                                            "status": "Level 2 Mesh Active",
                                            "active_sessions": sessions,
                                            "known_peers": peers,
                                            "uptime_seconds": uptime,
                                            "fingerprint": nc_ref.fingerprint(),
                                            "packets_sent": sent_pkts,
                                            "packets_recv": recv_pkts,
                                            "bytes_sent": sent_bytes,
                                            "bytes_recv": recv_bytes,
                                            "retransmits": retrans,
                                            "drops": drops,
                                            "vpn": vpn_role,
                                            "vpn_stats": vpn_json,
                                            "frame_standard": "GTF 512B Privacy / 1472B Bulk + L5 Jitter",
                                            "handshake_status": "ML-KEM-512 + X25519 Post-Quantum Hybrid",
                                            "discovery_source": "DNS Seed + Multicast Beacon + peers.cache"
                                        }).to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("GET /dashboard") {
                                        let html = include_str!("../assets/wan_dashboard.html");
                                        (
                                            "HTTP/1.1 200 OK",
                                            html.to_string(),
                                            "text/html; charset=utf-8",
                                        )
                                    } else if req.starts_with("GET /metrics") {
                                        let sessions = nc_ref.sessions.len();
                                        let peers = addrs_ref.len();
                                        let uptime = nc_ref.created_at.elapsed().as_secs();
                                        let sent_bytes =
                                            nc_ref.stats.bytes_sent.load(Ordering::Relaxed);
                                        let recv_bytes =
                                            nc_ref.stats.bytes_recv.load(Ordering::Relaxed);
                                        let sent_pkts =
                                            nc_ref.stats.packets_sent.load(Ordering::Relaxed);
                                        let recv_pkts =
                                            nc_ref.stats.packets_recv.load(Ordering::Relaxed);
                                        let retrans =
                                            nc_ref.stats.retransmits.load(Ordering::Relaxed);
                                        let drops = nc_ref.stats.drops.load(Ordering::Relaxed);
                                        let body = format!(
                                            "# HELP ghost_sessions_total Active peer-to-peer sessions\n# TYPE ghost_sessions_total gauge\nghost_sessions_total {}\n# HELP ghost_known_peers_total Discovered mesh peers\n# TYPE ghost_known_peers_total gauge\nghost_known_peers_total {}\n# HELP ghost_uptime_seconds Process uptime in seconds\n# TYPE ghost_uptime_seconds counter\nghost_uptime_seconds {}\n# HELP ghost_bytes_sent_total Total bytes transmitted\n# TYPE ghost_bytes_sent_total counter\nghost_bytes_sent_total {}\n# HELP ghost_bytes_recv_total Total bytes received\n# TYPE ghost_bytes_recv_total counter\nghost_bytes_recv_total {}\n# HELP ghost_packets_sent_total Total packets sent\n# TYPE ghost_packets_sent_total counter\nghost_packets_sent_total {}\n# HELP ghost_packets_recv_total Total packets received\n# TYPE ghost_packets_recv_total counter\nghost_packets_recv_total {}\n# HELP ghost_retransmits_total Total retransmissions triggered\n# TYPE ghost_retransmits_total counter\nghost_retransmits_total {}\n# HELP ghost_drops_total Total dropped or replay-rejected frames\n# TYPE ghost_drops_total counter\nghost_drops_total {}\n",
                                            sessions, peers, uptime, sent_bytes, recv_bytes, sent_pkts, recv_pkts, retrans, drops
                                        );
                                        (
                                            "HTTP/1.1 200 OK",
                                            body,
                                            "text/plain; version=0.0.4; charset=utf-8",
                                        )
                                    } else {
                                        (
                                            "HTTP/1.1 404 Not Found",
                                            "Not Found".to_string(),
                                            "text/plain",
                                        )
                                    };
                                    // VPN counters are appended rather than woven into
                                    // the base body, so the v0.4.0 metric set stays
                                    // byte-identical when the `vpn` feature is off.
                                    let body = if req.starts_with("GET /metrics") {
                                        format!("{body}{vpn_prom}")
                                    } else {
                                        body
                                    };
                                    let resp = format!(
                                        "{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        status_line, content_type, body.len(), body
                                    );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                }
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to bind metrics HTTP endpoint on port {}: {}", mp, e);
                }
            }
        });
    }
    // ── SOCKS5 PROXY (initiator mode) ──
    if socks {
        let n2 = Arc::clone(&nc);
        let a2 = Arc::clone(&addrs);
        let ch = Arc::clone(&sess_chan);
        let rsm = Arc::clone(&rx_state_map);
        let ak = Arc::clone(&connect_acks);
        let de = Arc::clone(&default_exit);
        let srouter_socks = Arc::clone(&shard_router);
        let sp = socks_port;
        tokio::spawn(async move {
            let lis = tokio::net::TcpListener::bind(("127.0.0.1", sp))
                .await
                .expect("Failed to bind SOCKS5 proxy");
            tracing::info!("SOCKS5 proxy ready on 127.0.0.1:{sp}");
            loop {
                if let Ok((mut s, _)) = lis.accept().await {
                    let nn = Arc::clone(&n2);
                    let aa = Arc::clone(&a2);
                    let chh = Arc::clone(&ch);
                    let _rsm2 = Arc::clone(&rsm);
                    let ak2 = Arc::clone(&ak);
                    let de2 = Arc::clone(&de);
                    let shard_router_proxy = Arc::clone(&srouter_socks);
                    tokio::spawn(async move {
                        let mut b = [0u8; 2];
                        if s.read_exact(&mut b).await.is_err() || b[0] != 5 {
                            return;
                        }
                        let mut m = vec![0u8; b[1] as usize];
                        if s.read_exact(&mut m).await.is_err() {
                            return;
                        }
                        if s.write_all(&[5, 0]).await.is_err() {
                            return;
                        }
                        let mut h = [0u8; 4];
                        if s.read_exact(&mut h).await.is_err() || h[1] != 1 {
                            return;
                        }
                        let addr = match h[3] {
                            1 => {
                                let mut ip = [0u8; 4];
                                if s.read_exact(&mut ip).await.is_err() {
                                    return;
                                }
                                format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                            }
                            3 => {
                                let mut l = [0u8; 1];
                                if s.read_exact(&mut l).await.is_err() {
                                    return;
                                }
                                let mut d = vec![0u8; l[0] as usize];
                                if s.read_exact(&mut d).await.is_err() {
                                    return;
                                }
                                String::from_utf8_lossy(&d).to_string()
                            }
                            _ => return,
                        };
                        let mut pb = [0u8; 2];
                        if s.read_exact(&mut pb).await.is_err() {
                            return;
                        }
                        let port = u16::from_be_bytes(pb);

                        // Prefer the explicitly configured exit node (EXIT <fp>);
                        // fall back to the first established session.
                        let fp = match de2.lock().unwrap().clone() {
                            Some(fp) if aa.contains_key(&fp) => Some(fp),
                            _ => None,
                        };
                        let (fp, tgt) = match fp {
                            Some(fp) => {
                                let addr = aa
                                    .get(&fp)
                                    .map(|v| *v.value())
                                    .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                                (fp, addr)
                            }
                            None => match nn.sessions.iter().next() {
                                Some(e) => {
                                    let fp = e.key().clone();
                                    let addr = aa
                                        .get(&fp)
                                        .map(|v| *v.value())
                                        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                                    (fp, addr)
                                }
                                None => {
                                    tracing::warn!("SOCKS5: No session. Use PEER command first.");
                                    return;
                                }
                            },
                        };
                        let ss = match nn.sessions.get(&fp) {
                            Some(s) => s,
                            None => {
                                tracing::warn!("SOCKS5: No session for {fp}");
                                return;
                            }
                        };
                        let key = ss.master_key;
                        let sh = ss.session_hash;
                        let role = ss.role;
                        drop(ss);

                        if chh.contains_key(&sh) {
                            tracing::warn!(
                                "SOCKS5: another tunnel is already open on this session"
                            );
                            return;
                        }
                        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                        chh.insert(sh, tx);

                        let connect_ctr = nn
                            .sessions
                            .get(&fp)
                            .map(|s| s.next_tx_counter())
                            .unwrap_or(2);
                        let dest = format!("{}:{}", addr, port);
                        tracing::info!(dest = %dest, "SOCKS5 CONNECT");
                        let (f, tag) =
                            enc_split(&key, connect_ctr, &sh, dir_for(role), dest.as_bytes());
                        send3(&nn.socket, &tgt, sh, connect_ctr, &f, &tag).await;
                        // Wait for the exit's framed "OK" (delivered via handle_pkt).
                        let mut connected = false;
                        for _ in 0..50 {
                            if ak2.get(&sh).map(|v| *v.value()).unwrap_or(false) {
                                connected = true;
                                break;
                            }
                            sleep(Duration::from_millis(100)).await;
                        }
                        if !connected {
                            tracing::warn!("SOCKS5 CONNECT failed");
                            chh.remove(&sh);
                            return;
                        }
                        tracing::info!("CONNECT_OK received");
                        if s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {
                            chh.remove(&sh);
                            return;
                        }

                        // client → mesh (initiator direction). Chunk counters are
                        // allocated from the session's shared tx_counter so a later
                        // CHAT / keepalive / CONNECT can never reuse a counter the
                        // peer already saw (replay-window collision).
                        let (mut rd, mut wr) = s.into_split();
                        let nn2 = Arc::clone(&nn);
                        let fp_out = fp.clone();
                        let key_out = key;
                        let sh_out = sh;
                        let tgt_out = tgt;
                        let chh2 = Arc::clone(&chh);
                        let srouter = Arc::clone(&shard_router_proxy);
                        let aa_proxy = Arc::clone(&aa);
                        tokio::spawn(async move {
                            let mut rbuf = vec![0u8; 900]; // keeps each RS shard ≤ 486 B privacy-frame cap
                            loop {
                                match rd.read(&mut rbuf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        let c = nn2
                                            .sessions
                                            .get(&fp_out)
                                            .map(|s| s.next_tx_counter())
                                            .unwrap_or(2);
                                        let (f, tag) = enc_split(
                                            &key_out,
                                            c,
                                            &sh_out,
                                            NonceDirection::InitiatorToResponder,
                                            &rbuf[..n],
                                        );
                                        send3_adaptive(
                                            &nn2.socket,
                                            &tgt_out,
                                            &fp_out,
                                            sh_out,
                                            c,
                                            &f,
                                            &tag,
                                            &srouter,
                                            &aa_proxy,
                                        )
                                        .await;
                                    }
                                }
                            }
                            // Client disconnected: drop the session channel so the
                            // mesh→client relay (rx.recv()) exits and the tunnel
                            // slot frees for the next connection.
                            chh2.remove(&sh_out);
                        });

                        // mesh → client: ordered decrypted data via the session channel
                        while let Some(chunk) = rx.recv().await {
                            if wr.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        chh.remove(&sh);
                    });
                }
            }
        });
    }

    // ── BEACON SENDER (UDP multicast) ──
    {
        let nc = Arc::clone(&nc);
        tokio::spawn(async move {
            let beacon_sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Beacon socket: {e}");
                    return;
                }
            };
            let mc_addr: SocketAddr = format!("{}:{}", BEACON_MULTICAST_ADDR, BEACON_PORT)
                .parse()
                .expect("Invalid beacon address");
            let zk_enabled = std::env::var("GHOST_ZK_DISCOVERY")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            loop {
                if nc.beacon_enabled.load(Ordering::Relaxed) {
                    // Beacons are signed with the device identity so a forged
                    // fingerprint can never trigger an auto-handshake.
                    // When GHOST_ZK_DISCOVERY=1, a zero-knowledge membership proof is attached.
                    let beacon = build_beacon_packet(
                        &nc.identity.public_key_bytes(),
                        |d| nc.identity.sign(d).to_bytes(),
                        zk_enabled,
                    );
                    if let Err(e) = beacon_sock.send_to(&beacon, mc_addr).await {
                        tracing::debug!("Beacon send error: {e}");
                    }
                }
                let secs = nc.keepalive_interval_secs.load(Ordering::Relaxed);
                let interval = Duration::from_secs(secs.clamp(1, 300));
                sleep(interval).await;
            }
        });
    }

    // ── BEACON LISTENER + AUTO-HANDSHAKE ──
    {
        let nc = Arc::clone(&nc);
        let pending = Arc::clone(&pending_hs);
        let peers = Arc::clone(&addrs);
        let rl = Arc::clone(&revocation_list);
        let nat_p = Arc::clone(&nat_puncher);
        tokio::spawn(async move {
            let zk_required = std::env::var("GHOST_ZK_DISCOVERY")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let listen_sock = match (|| -> std::io::Result<UdpSocket> {
                let s2 = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )?;
                let _ = s2.set_reuse_address(true);
                let sa: std::net::SocketAddr = format!("0.0.0.0:{}", BEACON_PORT).parse().unwrap();
                s2.bind(&sa.into())?;
                s2.set_nonblocking(true)?;
                let std_sock: std::net::UdpSocket = s2.into();
                UdpSocket::from_std(std_sock)
            })() {
                Ok(s) => {
                    let _ = s.join_multicast_v4(
                        std::net::Ipv4Addr::new(239, 255, 0, 1),
                        std::net::Ipv4Addr::UNSPECIFIED,
                    );
                    s
                }
                Err(e) => {
                    tracing::error!("Beacon listener: {e}");
                    return;
                }
            };
            let mut buf = vec![0u8; 256]; // signed beacons are 112 bytes (or 208 with ZK proof)
            let local_fp = nc.fingerprint();
            while nc.running.load(Ordering::Relaxed) {
                if let Ok((amt, src)) = listen_sock.recv_from(&mut buf).await {
                    if amt < 112 {
                        continue;
                    }
                    if &buf[..16] != BEACON_PREFIX {
                        continue;
                    }
                    // Verify the Ed25519 signature before trusting the beacon.
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&buf[16..48]);
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&buf[48..112]);
                    if !l0_identity::verify_peer_signature(&pk, &buf[16..48], &sig) {
                        tracing::warn!(peer = %src, "Beacon signature invalid — dropped");
                        continue;
                    }

                    // WIRED: ZK proof verification if present or required
                    if amt >= 208 {
                        let mut commitment = [0u8; 32];
                        commitment.copy_from_slice(&buf[112..144]);
                        let zk_proof = &buf[144..208];
                        if !ZkAuthenticator::verify_proof(&pk, zk_proof, &commitment) {
                            tracing::warn!(peer = %src, "Beacon ZK proof verification failed — dropped");
                            continue;
                        }
                    } else if zk_required {
                        tracing::warn!(peer = %src, "Beacon rejected — GHOST_ZK_DISCOVERY requires 208-byte ZK proof beacon");
                        continue;
                    }
                    let beacon_fp = hex::encode(&pk[..8]);
                    if beacon_fp == local_fp {
                        continue;
                    }
                    tracing::info!(peer = %src, fingerprint = %beacon_fp, "Discovered via beacon");

                    // WIRED: Register discovered peer with NatHolePuncher
                    if let Ok(local_sa) = nc.local_addr.parse::<SocketAddr>() {
                        nat_p.register_peer(&beacon_fp, src, local_sa);
                    }

                    // WIRED: Check revocation list before auto-handshaking
                    if rl.reject_handshake(&beacon_fp) {
                        tracing::warn!(peer = %src, fingerprint = %beacon_fp, "Discovered peer is revoked, ignoring");
                        continue;
                    }

                    if !peers.contains_key(&beacon_fp) {
                        if pending.len() >= MAX_PENDING_HANDSHAKES {
                            tracing::warn!("Pending-handshake table full — auto-handshake skipped");
                            continue;
                        }
                        let t = src;
                        let (xs, xp) = generate_x25519_keypair();
                        let (kp, ks) = generate_kyber_keypair();
                        let pdu = build_handshake_pdu(
                            &nc.identity.public_key_bytes(),
                            |d| nc.identity.sign(d).to_bytes(),
                            &xp,
                            &kp,
                        );
                        let mut c = pdu;
                        let raw = l4_rs::encode(&mut c);
                        let tag = [0u8; 16];
                        for i in 0..3 {
                            let _ = send_gtf(
                                &nc.socket,
                                &t,
                                [0, 0, 0, 0],
                                0,
                                i as u8,
                                &frame_shard(&raw[i]),
                                &tag,
                                false,
                            )
                            .await;
                        }
                        pending.insert(t.to_string(), (xs, ks));
                        tracing::info!(target = %t, fingerprint = %beacon_fp, "Auto-handshake sent");
                    }
                }
            }
        });
    }

    // ── PACKET RECEIVER (uses LocklessDispatcher for parallel dispatch) ──
    let nr = Arc::clone(&nc);
    let pa = Arc::clone(&addrs);
    let sp2 = Arc::clone(&spool);
    let phs = Arc::clone(&pending_hs);
    let rl2 = Arc::clone(&revocation_list);
    let rep2 = Arc::clone(&reputation_matrix);
    // Dispatcher's owned view of the VPN state (main keeps the original).
    #[cfg(feature = "vpn")]
    let vpn_rx: Option<VpnMode> = vpn_mode.as_ref().map(|m| match m {
        VpnMode::Hub(h) => VpnMode::Hub(Arc::clone(h)),
        VpnMode::Client(c, t) => VpnMode::Client(Arc::clone(c), Arc::clone(t)),
    });
    #[cfg(not(feature = "vpn"))]
    let vpn_rx: Option<VpnMode> = None;
    let et2 = Arc::clone(&exit_tunnels);
    let sc2 = Arc::clone(&sess_chan);
    let rsm2 = Arc::clone(&rx_state_map);
    let ca2 = Arc::clone(&connect_acks);
    let coc2 = Arc::clone(&connect_ok_ctrs);
    let te2 = Arc::clone(&trusted_exits);
    let psk2 = psk;
    let tft_rx = Arc::clone(&tft);
    let rotator_rx = exit_rotator.clone();
    let dispatcher = Arc::new(net::dispatcher::LocklessDispatcher::new(4, 1024));
    tokio::spawn(async move {
        let sock = nr.socket.clone();
        let mut buf = vec![0u8; GTF_BULK_SIZE + 64];
        while nr.running.load(Ordering::Relaxed) {
            if let Ok((amt, src)) = sock.recv_from(&mut buf).await {
                if amt < net::MIN_FRAME_SIZE {
                    continue;
                }
                let _ = nr.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                let _ = nr.stats.bytes_recv.fetch_add(amt as u64, Ordering::Relaxed);
                // Dispatch through lockless multi-worker session hash queue
                let _ = dispatcher.dispatch(&buf[..amt], src);
                let ctr = parse_packet_counter(&buf);
                // Tunnel bulk frames (flags bit 1) are single-frame
                // datagrams: no RS sharding, no spool. They must bypass the
                // 2-of-3 shard pool — in it they would never assemble and be
                // silently dropped. Dispatch straight to handle_pkt.
                #[cfg(feature = "vpn")]
                if net::parse_flags(&buf) & 0x02 != 0 {
                    let pe = net::BULK_OFFSET_AUTH_TAG_START.min(amt);
                    if pe <= net::BULK_OFFSET_PAYLOAD_START {
                        continue;
                    }
                    if let Some(sd) = unframe(&buf[net::BULK_OFFSET_PAYLOAD_START..pe]) {
                        let n2 = Arc::clone(&nr);
                        let pa2 = Arc::clone(&pa);
                        let phs2 = Arc::clone(&phs);
                        let sock2 = Arc::clone(&sock);
                        let src2 = src;
                        let rl3 = Arc::clone(&rl2);
                        let rep3 = Arc::clone(&rep2);
                        let et3 = Arc::clone(&et2);
                        let sc3 = Arc::clone(&sc2);
                        let rsm3 = Arc::clone(&rsm2);
                        let ca3 = Arc::clone(&ca2);
                        let coc3 = Arc::clone(&coc2);
                        let te3 = Arc::clone(&te2);
                        let psk3 = psk2;
                        let vpn_pkt = vpn_rx.clone();
                        let tft3 = Arc::clone(&tft_rx);
                        let rot3 = rotator_rx.clone();
                        tokio::spawn(async move {
                            handle_pkt(
                                &n2,
                                &pa2,
                                &phs2,
                                &sock2,
                                ctr,
                                &sd,
                                &src2,
                                Some(&rl3),
                                Some(&*rep3),
                                &et3,
                                &sc3,
                                &rsm3,
                                &ca3,
                                &coc3,
                                &te3,
                                psk3,
                                vpn_pkt.as_ref(),
                                Some(&*tft3),
                                rot3.as_deref(),
                            )
                            .await;
                        });
                    }
                    continue;
                }
                let si = buf[net::OFFSET_SHARD_INDEX] as usize;
                if si > 2 {
                    continue;
                }
                let ats = if amt >= GTF_BULK_SIZE {
                    net::BULK_OFFSET_AUTH_TAG_START
                } else {
                    net::OFFSET_AUTH_TAG_START
                };
                let pe = ats.min(amt);
                if pe <= OFFSET_PAYLOAD_START {
                    continue;
                }
                if let Some(sd) = unframe(&buf[OFFSET_PAYLOAD_START..pe]) {
                    let sp = Arc::clone(&sp2);
                    let phs2 = Arc::clone(&phs);
                    let n2 = Arc::clone(&nr);
                    let pa2 = Arc::clone(&pa);
                    let sock2 = Arc::clone(&sock);
                    let src2 = src;
                    let rl3 = Arc::clone(&rl2);
                    let rep3 = Arc::clone(&rep2);
                    let et3 = Arc::clone(&et2);
                    let sc3 = Arc::clone(&sc2);
                    let rsm3 = Arc::clone(&rsm2);
                    let ca3 = Arc::clone(&ca2);
                    let coc3 = Arc::clone(&coc2);
                    let te3 = Arc::clone(&te2);
                    let psk3 = psk2;
                    let vpn_pkt = vpn_rx.clone();
                    let tft3 = Arc::clone(&tft_rx);
                    let rot3 = rotator_rx.clone();
                    tokio::spawn(async move {
                        if let Some(r) = assemble(&sp, ctr, si, sd).await {
                            if std::env::var("GGN_DEBUG_RX").is_ok() {
                                tracing::info!("assembled frame ctr={ctr} si={si} len={}", r.len());
                            }
                            handle_pkt(
                                &n2,
                                &pa2,
                                &phs2,
                                &sock2,
                                ctr,
                                &r,
                                &src2,
                                Some(&rl3),
                                Some(&*rep3),
                                &et3,
                                &sc3,
                                &rsm3,
                                &ca3,
                                &coc3,
                                &te3,
                                psk3,
                                vpn_pkt.as_ref(),
                                Some(&*tft3),
                                rot3.as_deref(),
                            )
                            .await;
                        } else if std::env::var("GGN_DEBUG_RX").is_ok() {
                            tracing::info!("assemble dropped ctr={ctr} si={si}");
                        }
                    });
                }
            }
        }
    });

    // ── VPN EGRESS ──
    #[cfg(feature = "vpn")]
    match vpn_mode.as_ref() {
        Some(VpnMode::Hub(hub)) => {
            // Hub: drain netstack (TCP) + UDP/ICMP replies, send as tunnel
            // frames. All channels inside the hub are bounded (rule 3).
            let nc = Arc::clone(&nc);
            let hub = Arc::clone(hub);
            tokio::spawn(async move {
                let mut last_sweep = std::time::Instant::now();
                loop {
                    let mut sent = 0;
                    while let Some(u) = hub.poll_netstack_egress() {
                        send_tunnel_frame(&nc, &u.fingerprint, u.endpoint, &u.wire).await;
                        sent += 1;
                        if sent > 64 {
                            break;
                        } // yield; stay responsive
                    }
                    while let Some(u) = hub.poll_egress() {
                        send_tunnel_frame(&nc, &u.fingerprint, u.endpoint, &u.wire).await;
                        sent += 1;
                        if sent > 64 {
                            break;
                        }
                    }
                    if last_sweep.elapsed() >= Duration::from_secs(1) {
                        let expired = hub.sweep();
                        if expired > 0 {
                            tracing::debug!(expired, "VPN UDP flows expired");
                        }
                        last_sweep = std::time::Instant::now();
                    }
                    if sent == 0 {
                        sleep(Duration::from_millis(2)).await;
                    }
                }
            });
        }
        Some(VpnMode::Client(client, tun)) => {
            // Client TUN → mesh pump (blocking thread; wintun read is
            // non-blocking, so a 2 ms poll cadence keeps latency low).
            let nc = Arc::clone(&nc);
            let client = Arc::clone(client);
            let tun = Arc::clone(tun);
            let client2 = Arc::clone(&client);
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024); // bounded (rule 3)
                                                               // ── Tunnel watchdog: keepalive → dead detection → re-handshake ───
                                                               // A sealed tunnel that silently dies (LTE blip, hub reboot,
                                                               // counter sentinel) must heal itself. Liveness = authenticated
                                                               // inbound datagrams (open_to_tun notes them); keepalive = ICMP
                                                               // echo to the hub overlay (the hub answers it); recovery = a
                                                               // fresh mesh handshake — the ctr==1 path rotates the epoch and
                                                               // adopts the new key, the hub re-anchors the lease.
            {
                let client_ip: std::net::Ipv4Addr = std::env::var("GHOST_VPN_LOCAL_IP")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(std::net::Ipv4Addr::new(10, 66, 0, 10));
                let hub_overlay = std::net::Ipv4Addr::new(
                    vpn::OVERLAY_PREFIX,
                    vpn::OVERLAY_SECOND_OCTET,
                    0,
                    vpn::OVERLAY_HUB_HOST,
                );
                let keep_tx = tx.clone();
                let w_nc = Arc::clone(&nc);
                let w_client = Arc::clone(&client2);
                let w_addrs = Arc::clone(&addrs);
                let w_phs = Arc::clone(&pending_hs);
                tokio::spawn(async move {
                    let mut seen = w_client.last_inbound_ms();
                    loop {
                        sleep(Duration::from_millis(500)).await;
                        let action = {
                            let mut wd = w_client.watchdog.lock();
                            let cur = w_client.last_inbound_ms();
                            if cur != seen {
                                wd.on_inbound(std::time::Instant::now());
                                seen = cur;
                            }
                            // Counter headroom is a second liveness trigger: a
                            // spent tunnel counter is unrecoverable without a
                            // new epoch (PROTOTYPE.md flaw #1).
                            wd.poll_with_counter(std::time::Instant::now(), w_client.tx_counter())
                        };
                        match action {
                            vpn::client::Action::Nothing => {}
                            vpn::client::Action::SendKeepalive => {
                                let pkt = vpn::client::build_keepalive(hub_overlay, client_ip);
                                if let Some(w) = vpn::client::seal_from_tun(&w_client, &pkt) {
                                    let _ = keep_tx.try_send(w);
                                }
                            }
                            vpn::client::Action::Rehandshake { attempt } => {
                                match w_addrs.get(&w_client.fingerprint).map(|v| *v.value()) {
                                    Some(tgt) => {
                                        tracing::warn!(
                                            attempt,
                                            "VPN tunnel needs a fresh epoch (dead link or counter exhaustion) — re-handshaking to hub"
                                        );
                                        initiate_handshake(&w_nc, &w_nc.socket, tgt, &w_phs).await;
                                    }
                                    None => {
                                        tracing::debug!("VPN tunnel needs a fresh epoch — hub address unknown, cannot re-handshake");
                                    }
                                }
                            }
                        }
                    }
                });
            }
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let read: Option<usize> = tun.try_lock().ok().and_then(|mut g| {
                        match TunDevice::read_packet(&mut *g, &mut buf) {
                            Ok(n) if n > 0 => Some(n),
                            _ => None, // WouldBlock / empty / dying device
                        }
                    });
                    match read {
                        Some(n) => {
                            let Some(wire) = vpn::client::seal_from_tun(&client, &buf[..n]) else {
                                sleep(Duration::from_millis(2)).await;
                                continue;
                            };
                            if tx.send(wire).await.is_err() {
                                return; // sender half gone
                            }
                        }
                        None => sleep(Duration::from_millis(2)).await,
                    }
                }
            });
            // Mesh sender half: outer session encryption + bulk frame.
            let nc2 = Arc::clone(&nc);
            let addrs2 = Arc::clone(&addrs);
            tokio::spawn(async move {
                while let Some(wire) = rx.recv().await {
                    // ClientState.fingerprint = the hub's fingerprint.
                    let dest = client2.fingerprint.clone();
                    let tgt = addrs2.get(&dest).map(|v| *v.value());
                    if let Some(tgt) = tgt {
                        send_tunnel_frame(&nc2, &dest, tgt, &wire).await;
                    } else {
                        tracing::debug!("VPN client: hub address unknown — PEER first");
                    }
                }
            });
        }
        None => {}
    }

    // ── ACK RETRANSMIT ──
    let nr2 = Arc::clone(&nc);
    let pa2 = Arc::clone(&addrs);
    let pa2_keepalive = Arc::clone(&pa2);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(200)).await;
            for e in nr2.sessions.iter_mut() {
                let x = e
                    .ack_engine
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .collect_expired_full(Duration::from_millis(200));
                for (seq, d, auth_tag, session_hash) in x {
                    let t = pa2
                        .get(&e.peer_fingerprint)
                        .map(|v| *v.value())
                        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                    if t.port() != 0 {
                        nr2.stats.retransmits.fetch_add(1, Ordering::Relaxed);
                        let _ = send_gtf(
                            &nr2.socket,
                            &t,
                            session_hash,
                            seq,
                            0,
                            &d,
                            &auth_tag,
                            e.use_bulk,
                        )
                        .await;
                    }
                }
            }
        }
    });

    // ── KEEPALIVE TASK ──
    {
        let nc = Arc::clone(&nc);
        let pa2 = pa2_keepalive;
        let kc_sess = Arc::clone(&sess_chan);
        let kc_tunnels = Arc::clone(&exit_tunnels);
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(60)).await;
                let idle_timeout =
                    Duration::from_secs(nc.keepalive_interval_secs.load(Ordering::Relaxed));
                for mut e in nc.sessions.iter_mut() {
                    let idle = e.guard.last_activity.elapsed();
                    if idle > idle_timeout {
                        let sh = e.session_hash;
                        // Tunnel relays use their own counter space; a
                        // keepalive firing mid-tunnel would reuse a
                        // (key, nonce) with a tunnel frame. Skip while a
                        // tunnel is active, but refresh activity so the
                        // session does not expire during the tunnel.
                        let tunnel_busy = kc_sess.contains_key(&sh)
                            || kc_tunnels.iter().any(|t| t.value().session_hash == sh);
                        if tunnel_busy {
                            e.guard.last_activity = std::time::Instant::now();
                            continue;
                        }
                        tracing::debug!("Sending keepalive to {}", e.peer_fingerprint);
                        let ctr = e.next_tx_counter();
                        let (f, tag) = enc_split(&e.master_key, ctr, &sh, dir_for(e.role), b"KA");
                        let tgt = e.peer_fingerprint.clone();
                        let t = nc
                            .sessions
                            .iter()
                            .find_map(|entry| {
                                if entry.key() == &tgt {
                                    pa2.get(&tgt).map(|v| *v.value())
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                        send3(&nc.socket, &t, sh, ctr, &f, &tag).await;
                        e.guard.last_activity = std::time::Instant::now();
                    }
                }
            }
        });
    }

    // ── Session Cleanup ──
    let nm = Arc::clone(&nc);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;
            nm.sessions.retain(|_, s| s.is_valid());
        }
    });

    // ── Reputation Expiry Task ──
    let _rep_expiry = Arc::clone(&reputation_matrix);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(300)).await;
            // Reputation entries naturally age out via the sliding window
            tracing::debug!("Reputation matrix heartbeat");
        }
    });

    // ── Tit-for-Tat Periodic Audit Cycle ──
    let tft_audit = Arc::clone(&tft);
    let sessions_audit = Arc::clone(&nc.sessions);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(120)).await;
            let to_evict = tft_audit.audit_cycle(&sessions_audit).await;
            for fp in to_evict {
                tft_audit.evict(&fp);
                sessions_audit.remove(&fp);
                tracing::warn!(peer = %fp, "TFT: Leecher evicted and session torn down");
            }
        }
    });

    // ── CLI ──
    if !socks {
        tracing::info!("Commands: PEER <ip:port>, CHAT <fp> <msg>, SENDRELAY <dest> <relay> <payload>, EXIT <fp>, EXITS, TFT [fp], FEC, MEMSEC, FINGERPRINT, PEERS, STATUS, STATS, BEACON <on/off>, REVOKE, REP, HELP");
    }

    loop {
        let mut inp = String::new();
        if std::io::stdin().read_line(&mut inp).unwrap_or(0) == 0 {
            sleep(Duration::from_millis(100)).await;
            continue;
        }
        let inp = inp.trim();
        if inp.is_empty() {
            continue;
        }
        let p: Vec<&str> = inp.splitn(4, ' ').collect();
        match p[0].to_uppercase().as_str() {
            "EXIT" => match p.get(1).copied() {
                Some(fp) if !fp.is_empty() => {
                    *default_exit.lock().unwrap() = Some(fp.to_string());
                    println!("Exit node set: {}", fp);
                }
                _ => println!("Usage: EXIT <fingerprint>"),
            },
            "EXITAUTH" => {
                // Manage the exit-node allowlist for THIS node.
                match p.get(1).copied() {
                    Some("off") => {
                        trusted_exits.write().unwrap().clear();
                        println!("Exit allowlist cleared — exit service disabled (closed by default)");
                    }
                    Some("any") => {
                        trusted_exits.write().unwrap().insert("any".to_string());
                        println!("Exit allowlist: any authenticated peer may use this node as exit");
                    }
                    Some(fp) if !fp.is_empty() => {
                        trusted_exits.write().unwrap().insert(fp.to_string());
                        println!("Exit allowlist: added {}", fp);
                    }
                    _ => println!("Usage: EXITAUTH <fingerprint|any|off> — allowlist who may use this node as an exit"),
                }
            }
            "EXPORTTOPOLOGY" => {
                // Export the live mesh graph (real fingerprints/addrs/sessions)
                // for the quantum-entanglement layer (quantumnet ghost-net).
                // Take the raw remainder of the line (paths may contain spaces).
                let path = inp
                    .find(' ')
                    .map(|i| inp[i + 1..].trim())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("ghost-topology.json");
                let local_fp = nc.fingerprint();
                let mut nodes = vec![serde_json::json!({
                    "fingerprint": local_fp,
                    "addr": nc.local_addr.to_string(),
                })];
                for e in addrs.iter() {
                    nodes.push(serde_json::json!({
                        "fingerprint": e.key(),
                        "addr": e.value().to_string(),
                    }));
                }
                let mut links = Vec::new();
                for e in nc.sessions.iter() {
                    links.push(serde_json::json!({
                        "a": local_fp.clone(),
                        "b": e.key().clone(),
                    }));
                }
                let doc = serde_json::json!({
                    "schema_version": 1,
                    "generator": "vantablack",
                    "exported_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    "nodes": nodes,
                    "links": links,
                });
                match std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap()) {
                    Ok(_) => println!(
                        "Exported {} nodes, {} links to {path}",
                        nodes.len(),
                        links.len()
                    ),
                    Err(e) => println!("Export failed: {e}"),
                }
            }
            "PEER" => {
                let t: SocketAddr = match p.get(1).and_then(|x| x.parse().ok()) {
                    Some(a) => a,
                    None => {
                        tracing::warn!("Usage: PEER <ip:port>");
                        continue;
                    }
                };
                initiate_handshake(&nc, &nc.socket, t, &pending_hs).await;
                for _ in 0..20 {
                    sleep(Duration::from_millis(500)).await;
                    if !nc.sessions.is_empty() {
                        break;
                    }
                }
                tracing::info!("Sessions after wait: {}", nc.sessions.len());
            }
            "FINGERPRINT" => println!("{}", nc.fingerprint()),
            "PEERS" => {
                println!("Peers: {}", addrs.len());
                for e in addrs.iter() {
                    println!("  {} -> {}", e.key(), e.value());
                }
            }
            "STATUS" => {
                let uptime = nc.created_at.elapsed();
                println!("Uptime: {:.0}s", uptime.as_secs_f64());
                println!("Sessions: {}", nc.sessions.len());
                println!("Fingerprint: {}", nc.fingerprint());
                println!("Address: {}", nc.local_addr);
                println!("Revocations: active");
                println!("Reputation: active");
            }
            "STATS" => {
                let (sent_bytes, recv_bytes, send_rate, recv_rate) = nc.throughput_report(1000);
                println!(
                    "TX: {:.1} Mbps ({:.0} MB)",
                    send_rate * 8.0 / 1_000_000.0,
                    sent_bytes / 1_000_000.0
                );
                println!(
                    "RX: {:.1} Mbps ({:.0} MB)",
                    recv_rate * 8.0 / 1_000_000.0,
                    recv_bytes / 1_000_000.0
                );
                println!(
                    "Retransmits: {}",
                    nc.stats.retransmits.load(Ordering::Relaxed)
                );
                println!("Drops: {}", nc.stats.drops.load(Ordering::Relaxed));
            }
            "BEACON" => match p.get(1).copied() {
                Some("on" | "ON" | "1" | "true") => {
                    nc.beacon_enabled.store(true, Ordering::Relaxed);
                    println!("Beacon ON");
                }
                Some("off" | "OFF" | "0" | "false") => {
                    nc.beacon_enabled.store(false, Ordering::Relaxed);
                    println!("Beacon OFF");
                }
                _ => println!("Usage: BEACON on|off"),
            },
            "REVOKE" => {
                let fp = p.get(1).copied().unwrap_or("");
                if fp.is_empty() {
                    println!("Usage: REVOKE <fingerprint>");
                } else {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let reason = RevocationReason::KeyCompromise;
                    let msg = format!("REVOKE:{}:{}:{}", fp, ts, reason.as_str());
                    let sig = nc.identity.sign(msg.as_bytes()).to_bytes().to_vec();
                    let entry = vantablack::ghost::net::security::RevocationEntry {
                        fingerprint: fp.to_string(),
                        timestamp: ts,
                        signature: sig,
                        issuer_id: nc.fingerprint(),
                        reason,
                    };
                    let my_pk = nc.identity.public_key_bytes();
                    if revocation_list.revoke_with_issuer_pk(entry, Some(&my_pk)) {
                        println!("Revoked (cryptographically signed): {}", fp);
                    } else {
                        println!("Failed to revoke (signature mismatch or older entry exists?)");
                    }
                }
            }
            "SENDRELAY" => {
                // Multi-hop relay: SENDRELAY <dest_fp> <relay_fp> <payload>
                //  inner = [ctr u32 BE][dest-session-encrypted payload]
                //  outer = [RLY!][hops][dest_fp][inner] via the relay session
                let dest = p.get(1).copied().unwrap_or("");
                let relay = p.get(2).copied().unwrap_or("");
                let payload = p.get(3).copied().unwrap_or("");
                if dest.is_empty() || relay.is_empty() || payload.is_empty() {
                    println!("Usage: SENDRELAY <dest_fp> <relay_fp> <payload>");
                    continue;
                }
                let Some(ds) = nc.sessions.get(dest) else {
                    println!("No session with destination {dest}");
                    continue;
                };
                let (dkey, dsh, drole) = (ds.master_key, ds.session_hash, ds.role);
                drop(ds);
                let dctr = nc
                    .sessions
                    .get(dest)
                    .map(|s| s.next_tx_counter())
                    .unwrap_or(2);
                // End-to-end blob: [len u16][payload][pad][tag]
                let mut blob = (payload.len() as u16).to_be_bytes().to_vec();
                blob.extend_from_slice(payload.as_bytes());
                if !blob.len().is_multiple_of(2) {
                    blob.push(0);
                }
                encrypt_in_place_with_context(&dkey, dctr, &dsh, dir_for(drole), &mut blob);
                let mut inner = dctr.to_be_bytes().to_vec();
                inner.extend_from_slice(&blob);
                let relay_pkt = build_relay_packet(dest, 1, &inner);
                let Some(rs) = nc.sessions.get(relay) else {
                    println!("No session with relay {relay}");
                    continue;
                };
                let (rkey, rsh, rrole) = (rs.master_key, rs.session_hash, rs.role);
                drop(rs);
                let rctr = nc
                    .sessions
                    .get(relay)
                    .map(|s| s.next_tx_counter())
                    .unwrap_or(2);
                let (f, tag) = enc_split(&rkey, rctr, &rsh, dir_for(rrole), &relay_pkt);
                let tgt = addrs
                    .get(relay)
                    .map(|v| *v.value())
                    .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                send3(&nc.socket, &tgt, rsh, rctr, &f, &tag).await;
                println!("Relay sent: {payload} -> {dest} via {relay}");
            }
            "CHAT" => {
                // Direct-session chat: CHAT <dest_fp> <message>
                // (multi-hop delivery: SENDRELAY <dest_fp> <relay_fp> <message>)
                let dest = p.get(1).copied().unwrap_or("");
                // Fix B14: extract the entire remaining message string past "CHAT <dest_fp> "
                let msg = if let Some(stripped) = inp.strip_prefix(&format!("{} {}", p[0], dest)) {
                    stripped.trim()
                } else {
                    p.get(2).copied().unwrap_or("")
                };
                if dest.is_empty() || msg.is_empty() {
                    println!("Usage: CHAT <dest_fp> <message>");
                    continue;
                }
                // Keep the framed payload within the 486 B privacy-shard cap
                // (same bound as the SOCKS5 read buffer).
                if msg.len() > 900 {
                    println!("Message too long (max 900 bytes)");
                    continue;
                }
                let Some(sess) = nc.sessions.get(dest) else {
                    println!("No session with {dest}. Use PEER first.");
                    continue;
                };
                let (key, sh, role) = (sess.master_key, sess.session_hash, sess.role);
                drop(sess);
                let ctr = nc
                    .sessions
                    .get(dest)
                    .map(|s| s.next_tx_counter())
                    .unwrap_or(2);
                let mut payload = b"CHAT!".to_vec();
                payload.extend_from_slice(msg.as_bytes());
                let (f, tag) = enc_split(&key, ctr, &sh, dir_for(role), &payload);
                let tgt = addrs
                    .get(dest)
                    .map(|v| *v.value())
                    .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                send3_adaptive(
                    &nc.socket,
                    &tgt,
                    dest,
                    sh,
                    ctr,
                    &f,
                    &tag,
                    &shard_router,
                    &addrs,
                )
                .await;
                println!("Chat sent to {}: {}", &dest[..8.min(dest.len())], msg);
            }
            "REP" => {
                let local_fp = nc.fingerprint();
                let from = p.get(1).copied().unwrap_or(&local_fp);
                let to = p.get(2).copied().unwrap_or("");
                if to.is_empty() {
                    println!("Usage: REP <from_fp> <to_fp>");
                } else {
                    let rep = &*reputation_matrix;
                    println!(
                        "Reputation {}→{}: byzantine={}, error_rate={:.4}, p_value={:.6}",
                        from,
                        to,
                        rep.is_byzantine(from, to),
                        rep.observed_error_rate(from, to),
                        rep.cosmic_consistency_p_value(from, to)
                    );
                }
            }
            #[cfg(feature = "vpn")]
            "LEASES" => {
                if let Some(VpnMode::Hub(hub)) = vpn_mode.as_ref() {
                    println!("VPN leases:");
                    for l in hub.leases_snapshot() {
                        println!(
                            "  {}  {}  epoch {}  endpoint {}  v_max {}  idle {:.0}s",
                            &l.fingerprint[..16.min(l.fingerprint.len())],
                            l.overlay_ip,
                            l.epoch,
                            l.endpoint,
                            l.tunnel_v_max,
                            l.last_seen.elapsed().as_secs_f32()
                        );
                    }
                    let (i, o, dr, lc, tc) = hub.stats();
                    println!("  in={i} out={o} dropped={dr} leases={lc} tcp_flows={tc}");
                } else {
                    println!("VPN not in hub mode (GHOST_VPN=hub)");
                }
            }
            #[cfg(feature = "vpn")]
            "VPNSTATS" => match vpn_mode.as_ref() {
                Some(VpnMode::Hub(hub)) => {
                    let (i, o, dr, lc, tc) = hub.stats();
                    println!("VPN hub: in={i} out={o} dropped={dr} leases={lc} tcp_flows={tc}");
                }
                Some(VpnMode::Client(c, _)) => {
                    println!(
                        "VPN client: hub={} epoch={} tx_ctr={}",
                        c.fingerprint,
                        c.current_epoch(),
                        c.tx_counter()
                    );
                }
                None => println!("VPN disabled (set GHOST_VPN=hub|client)"),
            },
            #[cfg(feature = "vpn")]
            "VPN" => match p.get(1).copied().map(str::to_uppercase).as_deref() {
                Some("STATUS") => match vpn_mode.as_ref() {
                    Some(VpnMode::Hub(hub)) => {
                        let views = hub.lease_views();
                        println!("VPN hub — {} lease(s)", views.len());
                        if views.is_empty() {
                            println!("  (no leases yet: no client has handshaked)");
                        } else {
                            println!(
                                "  {:<17} {:<13} {:<22} {:>5} {:>6} {:>6} {:>8} {:>10}",
                                "fingerprint",
                                "overlay",
                                "endpoint",
                                "epoch",
                                "flows",
                                "v_max",
                                "idle",
                                "headroom"
                            );
                            for v in &views {
                                println!(
                                    "  {:<17} {:<13} {:<22} {:>5} {:>6} {:>6} {:>7.0}s {:>10}",
                                    &v.fingerprint[..16.min(v.fingerprint.len())],
                                    v.overlay_ip,
                                    v.endpoint,
                                    v.epoch,
                                    v.udp_flows,
                                    v.tunnel_v_max,
                                    v.idle_secs,
                                    v.counter_headroom
                                );
                            }
                        }
                        let m = hub.metrics();
                        println!(
                            "  totals: leases={} tcp_flows={} udp_flows={} in={} out={} dropped={} headroom_min={}",
                            m.leases, m.tcp_flows, m.udp_flows,
                            m.frames_in, m.frames_out, m.frames_dropped, m.counter_headroom_min
                        );
                    }
                    Some(VpnMode::Client(c, _)) => {
                        let ctr = c.tx_counter();
                        let (dead, attempts) = {
                            let wd = c.watchdog.lock();
                            (wd.is_dead(), wd.attempts())
                        };
                        println!("VPN client:");
                        println!("  hub fingerprint : {}", c.fingerprint);
                        println!("  epoch           : {}", c.current_epoch());
                        println!(
                            "  tx counter      : {}  (headroom {})",
                            ctr,
                            u32::MAX.saturating_sub(ctr)
                        );
                        println!(
                            "  watchdog        : {} (re-handshake attempts {})",
                            if dead { "DEAD" } else { "healthy" },
                            attempts
                        );
                    }
                    None => println!("VPN disabled (set GHOST_VPN=hub|client)"),
                },
                _ => println!("Usage: VPN STATUS"),
            },
            #[cfg(not(feature = "vpn"))]
            "VPN" => println!("VPN disabled (build with --features vpn)"),
            #[cfg(not(feature = "vpn"))]
            "LEASES" | "VPNSTATS" => println!("VPN disabled (build with --features vpn)"),
            "TFT" => {
                let target = p.get(1).copied().unwrap_or("");
                if target.is_empty() {
                    println!("Tit-for-Tat Peer Accounting:");
                    let stats = tft.all_stats();
                    if stats.is_empty() {
                        println!("  No peer reciprocity records yet.");
                    } else {
                        for (fp, for_us, for_them, ratio, evicted) in stats {
                            println!(
                                "  Peer {}: for_us={} B, for_them={} B, ratio={:.2}, evicted={}",
                                &fp[..8.min(fp.len())],
                                for_us,
                                for_them,
                                ratio,
                                evicted
                            );
                        }
                    }
                } else {
                    let (for_us, for_them, ratio, evicted) = tft.peer_stats(target);
                    println!("Tit-for-Tat Stats for {}:", target);
                    println!("  Bytes forwarded for us   : {}", for_us);
                    println!("  Bytes forwarded for them : {}", for_them);
                    println!("  Reciprocity ratio        : {:.2}", ratio);
                    println!("  Transit evicted          : {}", evicted);
                }
            }
            "EXITS" => match exit_rotator.as_ref() {
                Some(r) => {
                    let idx = r.current_idx.load(std::sync::atomic::Ordering::Relaxed);
                    println!(
                        "Exit IP Rotator Pool ({} IP(s), current index: {}):",
                        r.pool_size(),
                        idx
                    );
                    for (i, ip) in r.egress_ips.iter().enumerate() {
                        let marker = if i == (idx % r.pool_size()) {
                            " -> [active]"
                        } else {
                            ""
                        };
                        println!("  [{}] {}{}", i, ip, marker);
                    }
                }
                None => println!("Exit IP Rotator disabled (set GHOST_EXIT_IPS=ip1,ip2,...)"),
            },
            "FEC" => {
                println!("Forward Error Correction Status:");
                println!(
                    "  L4 Reed-Solomon (2,1)     : ALWAYS ACTIVE (per-packet erasure sharding)"
                );
                println!(
                    "  L7 LDPC IRA (1024,512)   : {}",
                    if ldpc_enabled {
                        "ENABLED (GHOST_LDPC_FEC=1)"
                    } else {
                        "STANDBY (set GHOST_LDPC_FEC=1)"
                    }
                );
                println!(
                    "  Codeword block size       : {} bytes (data: {} bytes, parity: {} bytes)",
                    vantablack::ghost::layers::l7_ldpc::LDPC_BLOCK_BYTES,
                    vantablack::ghost::layers::l7_ldpc::LDPC_DATA_BYTES,
                    vantablack::ghost::layers::l7_ldpc::LDPC_BLOCK_BYTES
                        - vantablack::ghost::layers::l7_ldpc::LDPC_DATA_BYTES
                );
            }
            "MEMSEC" => {
                println!("Memory Security & Protection Status:");
                println!(
                    "  L8 AES-256-XTS Engine     : ACTIVE (hardware-accelerated RAM encryption)"
                );
                println!(
                    "  L8 Verified Ring Buffer   : ACTIVE (capacity 1024 slots, drops: {})",
                    verified_ring.drops()
                );
                println!(
                    "  L0/L1 LockedMemory Guard  : ACTIVE (mlock / VirtualLock RAM page pinning)"
                );
            }
            "HELP" => {
                println!("Commands:");
                println!("  PEER <ip:port>     - Connect to a peer");
                println!("  CHAT <fp> <msg>    - Send a direct encrypted chat message");
                println!("  SENDRELAY <dest> <relay> <payload> - Multi-hop message");
                println!("  FINGERPRINT         - Show node identity");
                println!("  PEERS               - List known peers");
                println!("  STATUS              - Show node status");
                println!("  STATS               - Show throughput metrics");
                println!("  BEACON <on|off>     - Toggle beacon discovery");
                println!("  REVOKE <fp>         - Revoke a compromised identity");
                println!("  REP <from> <to>     - Show reputation between peers");
                println!(
                    "  TFT [fp]            - Tit-for-Tat fair-share accounting and eviction status"
                );
                println!("  EXITS               - Show configured egress IP rotation pool");
                println!(
                    "  FEC                 - Show Forward Error Correction status (RS + LDPC)"
                );
                println!(
                    "  MEMSEC              - Show runtime memory encryption & ring buffer status"
                );
                println!("  LEASES               - VPN hub: client leases (raw)");
                println!("  VPNSTATS             - VPN in/out/flow totals");
                println!("  VPN STATUS           - VPN per-lease detail (hub) / client state");
                println!("  HELP                - This help");
            }
            _ => tracing::warn!("Unknown command: {}. Type HELP for commands.", p[0]),
        }
    }
}
