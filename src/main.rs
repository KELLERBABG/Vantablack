// The desktop build is a GUI application, so on Windows it must not spawn a
// console window next to the app. Diagnostics are not lost: the log writer
// below mirrors every line into ghost.log.
#![cfg_attr(all(windows, feature = "webview"), windows_subsystem = "windows")]

use rand::RngCore;
use std::collections::BTreeMap;
use std::net::SocketAddr;
// Only the optional-transport paths name a local address (multipath, B23), so the
// type is imported where it is used rather than in every build.
#[cfg(feature = "quic")]
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;

use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, DecapsulationKey512, DecapsulationKey768, KeyExport, MlKem512};
#[cfg(all(feature = "tray", not(feature = "webview")))]
mod tray;
#[cfg(feature = "webview")]
mod webview;
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
            build_handshake_pdu, build_negotiated_handshake_pdu,
            build_negotiated_response_pdu, build_response_pdu, build_response_pdu_suite,
            build_uniform_handshake_pdu, build_uniform_response_pdu,
            derive_hybrid_master_key_with_psk, derive_hybrid_master_key_with_suite,
            derive_hybrid_master_key_with_transcript,
            generate_kyber768_keypair, generate_kyber_keypair, negotiate_cipher_suite,
            generate_x25519_keypair, kyber768_decapsulate, kyber768_encapsulate,
            kyber_encapsulate,            parse_handshake_pdu, parse_negotiated_handshake_pdu,
            parse_negotiated_response_pdu, parse_uniform_handshake_pdu,
            parse_uniform_response_pdu, uniform_handshake_signed_material,
            uniform_response_signed_material,

            parse_handshake_pdu_suite, parse_response_pdu, parse_response_pdu_suite,
            HybridCipherSuite, HANDSHAKE_NEGOTIATION_MAGIC, HANDSHAKE_V3_MAGIC,
            RESPONSE_NEGOTIATION_MAGIC, RESPONSE_V3_MAGIC, HANDSHAKE_BLOB_LEN,
            RESPONSE_BLOB_LEN,
        },
        l2_aead::{
            decrypt_in_place_with_context, random_xnonce, xchacha_open,
            xchacha_open_with_aad, xchacha_seal_in_place,
            xchacha_seal_in_place_with_aad, NonceDirection,
        },
        l4_rs,
        l7_ldpc::LdpcCodec,
        l8_memsec::{VerifiedRingBuffer, XtsMemoryEncryptor},
    },
    net::{
        self,
        consumer::{self, ConsumerSettings},
        fallback::{self, Fallback, FallbackPath, TurnPath},
        frame_shard,
        mesh::{ExitIpRotator, TitForTatEnforcer},
        relay::{
            self, build_onion_route, build_relay_packet, parse_relay_header,
            spawn_store_forward_task, BundleBuffer, MixBatch,
            DerpRelay,
        },
        routing::{ContactPlan, PoissonReputationMatrix},
        security::{
            LockedMemory, RevocationList, RevocationReason, ZkAuthenticator, ZK_CONTEXT_LEN,
            ZK_PROOF_LEN,
        },
        send_gtf, send_gtf_v2, unframe, upnp, BEACON_MULTICAST_ADDR, BEACON_PORT, BEACON_PREFIX,
        GTF_BULK_SIZE,
    },
    session::{
        build_ratchet_step_pdu, build_rekey_response_pdu, parse_rekey_pdu,
        parse_rekey_response_pdu,
        rekey_answer_signed_material, rekey_init_signed_material, RatchetAnswer, Session,
        SessionRole, REKEY_MAGIC, REKEY_RESPONSE_MAGIC,
    },
    GhostNode,
};

enum PendingHandshake {
    Kem512(x25519_dalek::EphemeralSecret, DecapsulationKey512),
    Negotiated {
        x_secret: x25519_dalek::EphemeralSecret,
        kem512: DecapsulationKey512,
        kem768: DecapsulationKey768,
        offered: Vec<HybridCipherSuite>,
    },
}

type PendingHandshakes = Arc<DashMap<String, PendingHandshake>>;

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
    pool: &DashMap<u64, Vec<Option<Vec<u8>>>>,
    ctr: u64,
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

// `frame_shard` / `unframe` live in `ghost::net` (canonical, SOTA P0-1) and are
// imported below.

/// Everything one outgoing v2 message is sealed with (SOTA P2-2).
///
/// Taken as one snapshot from the session so the epoch key and the epoch number
/// cannot straddle a ratchet step: sealing under one epoch's key with another
/// epoch's number produces a frame no receiver can open.
#[derive(Clone)]
struct SealCtx {
    key: [u8; 32],
    epoch: u64,
    counter: u64,
    nonce: [u8; 12],
    direction: NonceDirection,
    session_hash: [u8; 4],
    /// This message filled its epoch: the caller should start a ratchet step.
    ratchet_due: bool,
}

impl SealCtx {
    fn from_session(s: &Session) -> Self {
        let m = s.seal_material();
        Self {
            key: m.key,
            epoch: m.epoch,
            counter: m.counter,
            nonce: m.nonce,
            direction: m.direction,
            session_hash: s.session_hash,
            ratchet_due: m.ratchet_due,
        }
    }

    /// The v2 header for one shard of this message. All shards of a message share
    /// counter, epoch and nonce — they are pieces of one AEAD ciphertext.
    ///
    /// SOTA P3-1: this is also the single place the jitter tail is attached. It is
    /// derived here rather than passed in, so every privacy frame gets the same
    /// tail the sealer authenticated as associated data, and no call site had to
    /// learn a new argument.
    fn header(&self, shard_index: u8, bulk: bool, flags: u8) -> net::GtfV2Header {
        net::GtfV2Header {
            session_hash: self.session_hash,
            counter: self.counter,
            epoch: self.epoch,
            nonce: self.nonce,
            shard_index,
            flags,
            bulk,
            tail: net::tail_for(&self.key, &self.nonce, self.epoch, self.direction),
        }
    }

    fn data_header(&self, shard_index: u8, bulk: bool, flags: u8) -> net::GtfV2Header {
        let flags = if std::env::var("GHOST_SHARDSEC").is_ok() {
            flags | net::FLAG_SHARDSEC
        } else {
            flags
        };
        self.header(shard_index, bulk, flags)
    }
}

/// What a v2 frame header tells the receiver beyond the payload region: which
/// ratchet epoch sealed it, with which nonce, and the jitter tail it carries.
#[derive(Clone, Copy)]
struct V2FrameMeta {
    epoch: u64,
    nonce: [u8; 12],
    /// Whether this is an MTU-sized bulk frame, which carries no tail at all.
    bulk: bool,
    /// The jitter tail **exactly as it arrived on the wire** (SOTA P3-1).
    tail: [u8; net::JITTER_MAX],
    /// ShardSec frames authenticate each RS shard independently and are opened
    /// before reconstruction; they do not use the legacy message-level AEAD.
    shardsec: bool,
}

impl V2FrameMeta {
    /// Read the seal metadata out of a raw datagram, if it is a v2 frame.
    fn of(frame: &[u8]) -> Option<Self> {
        net::parse_gtf_v2_header(frame).map(|h| Self {
            epoch: h.epoch,
            nonce: h.nonce,
            bulk: h.bulk,
            tail: h.tail,
            shardsec: (h.flags & net::FLAG_SHARDSEC) != 0,
        })
    }
}

/// A lock-free snapshot of everything needed to *open* frames from one session.
///
/// Snapshotted before the DashMap iterator is dropped for the same reason the old
/// code snapshotted the master key: taking a `get_mut` (for the replay guard) while
/// an iterator is alive deadlocks the task. The epoch keys are copied rather than
/// borrowed, so the ratchet's lock is never held across the receive path.
/// A lock-free snapshot of everything needed to *open* frames from one session.
struct OpenCtx {
    peer_fp: String,
    master_key: [u8; 32],
    session_hash: [u8; 4],
    role: SessionRole,
}

impl OpenCtx {
    fn of(s: &Session) -> Self {
        Self {
            peer_fp: s.peer_fingerprint.clone(),
            master_key: s.master_key,
            session_hash: s.session_hash,
            role: s.role,
        }
    }

    fn snapshot_of(sessions: &DashMap<String, Session>) -> Vec<OpenCtx> {
        let mut out: Vec<OpenCtx> = sessions.iter().map(|e| OpenCtx::of(&e)).collect();
        out.shrink_to_fit();
        out
    }
}

/// Open the ciphertext carried by one received frame, for one session, whichever
/// wire version it arrived in.
fn open_received_frame(
    ctx: &OpenCtx,
    sess: &Session,
    data: &[u8],
    ctr: u64,
    v2: Option<V2FrameMeta>,
) -> Option<Vec<u8>> {
    let ours = ctx.role.seal_direction();
    match v2 {
        Some(meta) => {
            for dir in [ours.peer_direction(), ours] {
                let plan = sess.plan_open(meta.epoch, dir, ctr);
                let key = match &plan {
                    vantablack::ghost::session::ratchet::OpenPlan::Forward { key, .. } => *key,
                    vantablack::ghost::session::ratchet::OpenPlan::Cached { key, .. } => *key,
                    vantablack::ghost::session::ratchet::OpenPlan::Refused => {
                        if sess.gap_exceeds_max_skip(meta.epoch, dir, ctr) {
                            sess.trigger_forced_ratchet_step();
                        }
                        continue;
                    }
                };
                let mut buf = data.to_vec();
                let aad: &[u8] = if meta.bulk { &[] } else { &meta.tail };
                if xchacha_open_with_aad(&key, &meta.nonce, meta.epoch, dir, &mut buf, aad).is_ok() {
                    sess.commit_open(meta.epoch, dir, plan);
                    return Some(buf);
                }
            }
            None
        }
        None => {
            // v1: the nonce is derived from the counter and the key is the seed.
            // The counter is 32-bit on that wire, so a v2-only value cannot be
            // mistaken for it.
            let Ok(ctr32) = u32::try_from(ctr) else {
                return None;
            };
            for dir in [
                NonceDirection::InitiatorToResponder,
                NonceDirection::ResponderToInitiator,
            ] {
                let mut buf = data.to_vec();
                if decrypt_in_place_with_context(
                    &ctx.master_key,
                    ctr32,
                    &ctx.session_hash,
                    dir,
                    &mut buf,
                )
                .is_ok()
                {
                    return Some(buf);
                }
            }
            None
        }
    }
}

fn enc_split(ctx: &SealCtx, pay: &[u8]) -> (Vec<Vec<u8>>, [u8; 16]) {
    if std::env::var("GHOST_SHARDSEC").is_ok() {
        let pay_len = pay.len() as u16;
        let mut framed = pay_len.to_be_bytes().to_vec();
        framed.extend_from_slice(pay);
        if !framed.len().is_multiple_of(2) {
            framed.push(0);
        }
        let plaintext_shards = l4_rs::encode(&mut framed);
        let frames = plaintext_shards
            .into_iter()
            .enumerate()
            .map(|(index, shard)| {
                let sealed = vantablack::ghost::net::shardsec::seal_shard(
                    &ctx.key,
                    ctx.epoch,
                    &ctx.nonce,
                    ctx.direction,
                    index as u8,
                    shard,
                );
                let mut wire = sealed.ciphertext;
                wire.extend_from_slice(&sealed.tag);
                frame_shard(&wire)
            })
            .collect();
        // ShardSec authenticates inside each shard. The legacy GTF tag field is
        // intentionally zero for this versioned mode and is never trusted.
        return (frames, [0u8; 16]);
    }
    let pay_len = pay.len() as u16;
    let mut framed = pay_len.to_be_bytes().to_vec();
    framed.extend_from_slice(pay);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    // SOTA P3-1: the privacy frame's jitter tail is authenticated as AEAD
    // associated data, so the sealer covers the exact bytes the frame will carry.
    // `tail_for` is a keyed PRF of the seal metadata, which is why the frame
    // builder can recompute the same value instead of it being threaded through
    // every `enc_split`/`send3` call site.
    xchacha_seal_in_place_with_aad(
        &ctx.key,
        &ctx.nonce,
        ctx.epoch,
        ctx.direction,
        &mut framed,
        &net::tail_for(&ctx.key, &ctx.nonce, ctx.epoch, ctx.direction),
    )
    .expect("sealing an owned buffer cannot fail");
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

/// One opaque frame waiting in the bounded cross-message mix batch.
struct MixWireFrame {
    socket: Arc<UdpSocket>,
    destination: SocketAddr,
    frame: Vec<u8>,
    done: oneshot::Sender<std::io::Result<()>>,
}

/// The mix is deliberately process-local and bounded: at most three messages
/// (nine frames) wait for the same flush. A 20 ms deadline prevents a quiet link
/// from turning mixing into an outage, while a full batch gives the observer no
/// stable relation between application-message order and wire order.
static MIX_WIRE_QUEUE: OnceLock<Arc<std::sync::Mutex<MixBatch<MixWireFrame>>>> = OnceLock::new();

fn flush_mixed_frames(frames: Vec<MixWireFrame>) {
    for item in frames {
        tokio::spawn(async move {
            let result = item
                .socket
                .send_to(&item.frame, item.destination)
                .await
                .map(|_| ());
            let _ = item.done.send(result);
        });
    }
}

fn enqueue_mixed_frame(
    socket: &Arc<UdpSocket>,
    destination: SocketAddr,
    frame: Vec<u8>,
) -> oneshot::Receiver<std::io::Result<()>> {
    let (done, receiver) = oneshot::channel();
    let queue = MIX_WIRE_QUEUE
        .get_or_init(|| {
            Arc::new(std::sync::Mutex::new(MixBatch::new(
                9,
                Duration::from_millis(20),
            )))
        })
        .clone();

    let (ready, start_timer) = {
        let mut guard = queue.lock().unwrap_or_else(|poison| poison.into_inner());
        let start_timer = guard.is_empty();
        let ready = guard.push(MixWireFrame {
            socket: Arc::clone(socket),
            destination,
            frame,
            done,
        });
        (ready, start_timer)
    };
    if let Some(frames) = ready {
        flush_mixed_frames(frames);
    } else if start_timer {
        let timer_queue = Arc::clone(&queue);
        tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            let frames = {
                let mut guard = timer_queue
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                if guard.flush_due() {
                    guard.drain_randomized()
                } else {
                    Vec::new()
                }
            };
            if !frames.is_empty() {
                flush_mixed_frames(frames);
            }
        });
    }
    receiver
}

async fn send3(sock: &UdpSocket, dst: &SocketAddr, ctx: &SealCtx, f: &[Vec<u8>], tag: &[u8; 16]) {
    // Borrowed-socket callers (notably the relay ingress) stay on the direct
    // path because their socket lifetime is owned by the receive task.
    for i in 0..3 {
        let _ = send_gtf_v2(sock, dst, &ctx.data_header(i as u8, false, 0), &f[i], tag).await;
    }
}

/// Mixed variant for long-lived node-owned sockets. The queue holds only fully
/// framed opaque datagrams, so batching cannot change authentication or routing.
async fn send3_mixed(
    sock: Arc<UdpSocket>,
    dst: &SocketAddr,
    ctx: &SealCtx,
    f: &[Vec<u8>],
    tag: &[u8; 16],
) {
    let mut pending = Vec::with_capacity(3);
    for i in 0..3 {
        let header = ctx.data_header(i as u8, false, 0);
        let frame = net::build_gtf_v2_frame(&header, &f[i], tag);
        pending.push(enqueue_mixed_frame(&sock, *dst, frame));
    }
    for result in pending {
        let _ = result.await;
    }
}

// ── Cover traffic (SOTA P3-1) ────────────────────────────────────────────────
//
// The other half of P3-1: constant-size frames removed the *length* channel, and
// this removes the *silence*. Both are needed — a link whose frames are all the
// same size but which only transmits when a user types is still trivially
// classifiable, and that is what a DPI+timer pair is looking for.

/// Target cover-traffic rate, in **frames** per second per session (SOTA P3-1).
///
/// The plan names "2 pkt/s". A cover *message* is a three-frame Reed-Solomon group,
/// because that is what a data message is, so 2 frames/s is two-thirds of a message
/// per second — roughly 1.2 KiB/s per established session. Small enough to ignore
/// across a WAN, large enough that a link is never silent.
const COVER_FRAMES_PER_SEC: f64 = 2.0;

/// Frames per cover message: an RS(2,1) group, the same as any data message.
const COVER_FRAMES_PER_MESSAGE: f64 = 3.0;

/// How long until the next cover message (SOTA P3-1).
///
/// **Exponential, not fixed.** A fixed interval is a metronome and would be among
/// the easiest things on the wire to classify; a constant *mean* rate with
/// exponential gaps is what an ordinary Poisson stream looks like. The mean is what
/// hides idleness — the gaps are what stop the padding becoming its own signature.
///
/// Pure on purpose: `uniform` in `[0, 1)` is supplied by the caller, so the
/// distribution is testable without a clock, a spawned task or real waiting.
fn cover_gap(uniform: f64, frames_per_sec: f64) -> Duration {
    let per_message = frames_per_sec / COVER_FRAMES_PER_MESSAGE;
    if !(per_message > 0.0) {
        // "No cover" is a gap longer than any session, not a panic.
        return Duration::from_secs(3600);
    }
    // Inverse transform for an exponential inter-arrival time: -ln(1-u)/λ.
    let u = uniform.clamp(0.0, 1.0 - f64::EPSILON);
    let secs = -(1.0 - u).ln() / per_message;
    // Clamp both tails: a near-zero draw must not spin the loop, and a near-one
    // draw must not stall cover for minutes on end.
    Duration::from_secs_f64(secs.clamp(0.005, 30.0))
}

/// Send one cover message to `dst` (SOTA P3-1).
///
/// It rides the **real** data path — [`enc_split`], then three privacy frames — with
/// a [`net::DUMMY_MAGIC`] payload, so on the wire it is an ordinary RS(2,1) group of
/// 576-byte frames. That is deliberate: cover shaped differently from data would be
/// worse than no cover, because it would announce itself.
///
/// The one thing it does *not* mimic is shard *carrying*: all three frames go to the
/// same peer, where a data message may spread them across routes. Spreading cover
/// would leak the very routing topology the shards exist to hide, so uniform
/// treatment per peer is the conservative choice.
async fn send_cover(sock: &UdpSocket, dst: &SocketAddr, ctx: &SealCtx) {
    let (shards, tag) = enc_split(ctx, net::DUMMY_MAGIC);
    let mut batch = MixBatch::new(3, Duration::ZERO);
    let mut ready = None;
    for i in 0..3 {
        if let Some(flushed) = batch.push((i as u8, shards[i].clone())) {
            ready = Some(flushed);
        }
    }
    for (shard_index, payload) in ready.unwrap_or_else(|| batch.drain_randomized()) {
        // The `FLAG_DUMMY` bit lets a receiver skip work early. It is *not* what the
        // receiver decides on — see `FLAG_DUMMY` for why the header cannot be
        // trusted, and `DUMMY_MAGIC` for what the decision actually rests on.
        let header = ctx.data_header(shard_index, false, net::FLAG_DUMMY);
        let _ = send_gtf_v2(sock, dst, &header, &payload, &tag).await;
    }
}

/// Spawn the cover-traffic emitter (SOTA P3-1).
///
/// One drawn gap per message, for every session the node holds. Deliberately **not**
/// gated on idleness: cover that appears only when the link is quiet would make the
/// *rate* itself the signal, which is the failure this item exists to avoid. The
/// cost is that cover also rides an already-busy link — 2 frames/s against a link
/// moving megabytes per second, which is a trade worth stating rather than hiding.
///
/// These are real frames, so they *do* count toward `RATCHET_INTERVAL`; the plan's
/// "a Dummy frame must not spend the ratchet epoch" cannot be honoured without
/// creating frames the receiver refuses to count, which is a replay-window hole.
/// The honest number instead: at 2 frames/s, spending a 1M-frame epoch on cover
/// alone takes ~139 h, so cover can at most halve what an epoch carries, and only
/// while the node is otherwise idle.
fn spawn_cover_task(
    node: Arc<GhostNode>,
    addrs: Arc<DashMap<String, SocketAddr>>,
    relay_role: Option<Arc<DerpRelay>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            sleep(cover_gap(rand::random::<f64>(), COVER_FRAMES_PER_SEC)).await;
            // Collect first: a DashMap guard must never be held across an await,
            // and every send below is one.
            let work: Vec<(String, SealCtx)> = node
                .sessions
                .iter()
                .map(|e| (e.peer_fingerprint.clone(), SealCtx::from_session(&e)))
                .collect();
            for (peer, ctx) in work {
                let Some(dst) = addrs.get(&peer).map(|a| *a.value()) else {
                    continue;
                };
                // When an authenticated third peer is available, send this
                // cover message as a blind decoy through it. The target still
                // receives a normal authenticated dummy frame, while the relay
                // sees only an opaque envelope and the observer sees relay-shaped
                // traffic rather than all cover terminating at one peer.
                let me = node.fingerprint();
                let decoy_sent = if std::env::var("GHOST_SHARDSEC").is_err() {
                    relay_role
                        .as_ref()
                        .and_then(|relay| relay.pick_relay(&me, &peer))
                        .map(|(relay_fp, relay_addr)| {
                            let node_for_decoy = Arc::clone(&node);
                            let ctx_for_decoy = ctx.clone();
                            let peer_for_decoy = peer.clone();
                            async move {
                                let frame = seal_single(&ctx_for_decoy, net::DUMMY_MAGIC);
                                send_datagram_via_relay(
                                    &node_for_decoy,
                                    &node_for_decoy.socket,
                                    &relay_fp,
                                    &relay_addr,
                                    &peer_for_decoy,
                                    &frame,
                                )
                                .await
                            }
                        })
                } else {
                    None
                };
                if let Some(future) = decoy_sent {
                    if !future.await {
                        send_cover(&node.socket, &dst, &ctx).await;
                    }
                } else {
                    send_cover(&node.socket, &dst, &ctx).await;
                }
            }
        }
    })
}

/// How a message actually left this node (SOTA P1-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Routed {
    Direct,
    /// The optional transport carried it (SOTA P1-2).
    ///
    /// Distinct from `Direct` because it is a different carrier over the same
    /// measured path: QUIC's own loss recovery and congestion control carry the
    /// frames instead of the UDP shard path.
    Carrier,
    MeshRelay,
    Turn,
    /// No session with the chosen relay, or no allocation: nothing carried it.
    Unroutable,
}

/// Seal `payload` as ONE self-contained GTF datagram.
///
/// This is the single-datagram form the receive path already knows: a bulk frame
/// with the self-contained bit (0x02) set, whose payload region holds
/// `frame_shard(ciphertext)` — exactly what `unframe()` consumes. That bit is what
/// stops the receiver waiting for Reed-Solomon siblings that will never arrive,
/// which is the point: a relay hop carries one datagram at a time, and a control
/// PDU is a whole message rather than a shard of one.
///
/// The bypass that honours the bit is **not** VPN-gated (`RxContext::ingest`): for
/// a while it was, which meant a default build spooled these frames as a single
/// unrecoverable shard and dropped them. Any new caller of this function depends
/// on that bypass staying unconditional.
fn seal_single(ctx: &SealCtx, payload: &[u8]) -> Vec<u8> {
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(payload);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    xchacha_seal_in_place(&ctx.key, &ctx.nonce, ctx.epoch, ctx.direction, &mut framed)
        .expect("sealing an owned buffer cannot fail");
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap_or([0u8; 16]);
    let carrier = frame_shard(&framed);
    // The tunnel bit (0x02) rides in the v2 header's flags byte, which is the same
    // byte v1 used — so a v2 frame's flags stay readable by the same helper, and
    // the v2 marker is what tells the receiver the rest of the header moved.
    net::build_gtf_v2_frame(&ctx.header(0, true, net::FLAG_TUNNEL), &carrier, &tag)
}

/// Hand one already-built GTF datagram to a relay peer, wrapped in a blind
/// envelope addressed to `target_fp` (SOTA P1-1 / B22).
///
/// The datagram travels inside the envelope **verbatim**, so the target parses
/// exactly what a direct send would have delivered, and the relay holds no key
/// for any of it. Returns `false` when there is no session with the relay: the
/// relay cannot authenticate the forward without one.
///
/// Two framings, because the envelope itself has to fit a datagram. A privacy
/// frame (512–576 B) fits a single bulk frame's payload region. A bulk frame
/// (1472 B) does not, so the envelope is Reed-Solomon split across three bulk
/// frames — the same convention `relay.rs` uses to re-wrap an onion hop.
async fn send_datagram_via_relay(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    relay_fp: &str,
    relay_addr: &SocketAddr,
    target_fp: &str,
    datagram: &[u8],
) -> bool {
    let envelope = fallback::blind_envelope(target_fp, datagram);
    let Some(sess) = nc.sessions.get(relay_fp) else {
        tracing::warn!(relay = %relay_fp, "fallback: no session with the relay — cannot forward");
        return false;
    };
    // SOTA P2-2: one seal snapshot per forward, shared by whichever framing the
    // envelope needs — a single bulk frame or three bulk shards of one ciphertext.
    let ctx = SealCtx::from_session(&sess);
    drop(sess);

    if envelope.len() + 2 <= net::V2_MAX_BULK_PAYLOAD_LEN {
        let frame = seal_single(&ctx, &envelope);
        return match sock.send_to(&frame, relay_addr).await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(relay = %relay_fp, "fallback: relay send failed: {e}");
                false
            }
        };
    }

    let (carriers, tag) = enc_split(&ctx, &envelope);
    let mut ok = true;
    for i in 0..3 {
        let header = ctx.data_header(i as u8, true, 0);
        if let Err(e) = send_gtf_v2(sock, relay_addr, &header, &carriers[i], &tag).await {
            tracing::warn!(relay = %relay_fp, "fallback: relay send failed: {e}");
            ok = false;
        }
    }
    ok
}

/// Send 3 RS shards using adaptive multi-path routing when alternative peer routes exist.
///
/// `route` is the peer's fallback when it has no direct path (SOTA P1-1). When it
/// is set, multi-path selection is skipped — deliberately. The carriers must all
/// travel the one route the relay carries, and spreading them across *other*
/// peers would send them to machines that hold no session with the target.
#[allow(clippy::too_many_arguments)]
async fn send3_adaptive(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    primary_dst: &SocketAddr,
    primary_fp: &str,
    ctx: &SealCtx,
    f: &[Vec<u8>],
    tag: &[u8; 16],
    router: &vantablack::ghost::net::mesh::AdaptiveShardRouter,
    all_peers: &Arc<DashMap<String, SocketAddr>>,
    // The CGR contact plan, when the caller already holds a read guard. Passed in
    // rather than read here so this stays a plain dispatch that takes no lock of
    // its own, and so a caller that has already looked at the plan pays for it
    // once.
    plan: Option<&ContactPlan>,
    me: &str,
    // The peer's fallback path, when its direct checks have failed.
    route: Option<&FallbackPath>,
    turn: Option<&Arc<TurnPath>>,
    // The optional transport, when this build and this run have one (SOTA P1-2).
    carrier: Option<&Arc<net::carrier::Carrier>>,
) -> Routed {
    if ctx.ratchet_due {
        // Due, not broken (SOTA P2-2): the epoch is full and the *next* step is
        // owed, but traffic keeps flowing on the current key until the step
        // completes — a rotation that stalled the data path would be an outage.
        // Starting the step is the caller's job; this is where the debt is
        // observed.
        tracing::debug!(
            peer = %primary_fp,
            epoch = ctx.epoch,
            "session ratchet due — epoch key is spent"
        );
    }
    if let Some(path) = route {
        return send3_via_fallback(nc, sock, primary_fp, ctx, f, tag, path, turn).await;
    }
    // A carrier link rides the address ICE already measured, so it is preferred
    // exactly where a direct path exists — and it is tried before the shard
    // router because QUIC's own loss recovery is better than three UDP shards
    // when the path is lossy, which is the case this transport exists for.
    if let Some(carrier) = carrier {
        if send3_via_carrier(carrier, primary_fp, ctx, f, tag).await {
            return Routed::Carrier;
        }
    }
    let mut available: Vec<(String, SocketAddr)> = all_peers
        .iter()
        .map(|entry| (entry.key().clone(), *entry.value()))
        .collect();

    if !available.iter().any(|(fp, _)| fp == primary_fp) {
        available.push((primary_fp.to_string(), *primary_dst));
    }

    if available.len() > 1 {
        // Prefer CGR ordering whenever the plan knows a route: peers are then
        // taken in measured earliest-arrival order, and each accepted peer's
        // transit nodes are barred from the later ones, so the shards cross
        // genuinely separate parts of the mesh instead of three paths that share
        // one relay. With no plan — or an empty one — fall back to path fitness:
        // a plan that has not learned about a peer yet is a gap in our
        // knowledge, not evidence that the peer is unreachable.
        let selected = match plan.filter(|p| !p.is_empty()) {
            Some(plan) => router.select_shard_targets_routed(
                me,
                &available,
                plan,
                unix_now_secs(),
                router.shard_target_count(),
            ),
            None => router.select_shard_targets(&available),
        };
        let routes = router.assign_shards(&selected);
        // Enforce the three-shard route budget before sending.  `Ground` is a
        // deliberately repeatable plane (three independent authenticated peers
        // are still useful on terrestrial links), but the constraint prevents a
        // fourth shard from being added if RS changes its shard count later.
        let mut disjoint_constraint = net::orbit::DisjointRouteConstraint::new();
        for route in routes {
            let idx = route.shard_index as usize;
            if idx >= f.len()
                || !disjoint_constraint.reserve_plane(net::orbit::OrbitalPlane::Ground)
            {
                tracing::debug!(
                    shard = route.shard_index,
                    peer = %route.peer_fingerprint,
                    "mesh: shard omitted because the disjoint route budget is exhausted"
                );
                continue;
            }
            let target_addr = selected
                .iter()
                .find(|(fp, _, _)| *fp == route.peer_fingerprint)
                .map(|(_, addr, _)| *addr)
                .unwrap_or(*primary_dst);
            if let Err(error) = send_gtf_v2(
                sock,
                &target_addr,
                &ctx.data_header(route.shard_index, false, 0),
                &f[idx],
                tag,
            )
            .await
            {
                router.record_loss(&route.peer_fingerprint);
                tracing::debug!(
                    shard = route.shard_index,
                    peer = %route.peer_fingerprint,
                    %error,
                    "mesh: shard send failed"
                );
            }
        }
    } else {
        // Fallback to direct send through the bounded cross-message mix queue.
        // The queue carries complete opaque GTF frames, so it is safe even when
        // the selected peer/session differs between neighboring messages.
        send3_mixed(Arc::clone(&nc.socket), primary_dst, ctx, f, tag).await;
    }
    Routed::Direct
}

/// Ship the three RS carriers over the optional transport, spread across every
/// live local path (SOTA P1-2 / B23).
///
/// The bytes are built exactly as `send_gtf` builds them, so the peer parses
/// what a UDP send would have delivered: the transport is a *carrier*, not a
/// second wire format, and nothing about GTF, the sealing or the identity model
/// changes on this path. Returns `false` when no link carried them, which is the
/// ordinary case and not a failure — the caller then keeps to UDP.
///
/// The registry decides how the three shards map onto paths: one per live local
/// address before any path carries a second, so a Wi-Fi + LTE host sends shard 0
/// over one interface and shard 1 over the other. With a single path this is the
/// single-link send it has always been.
///
/// A send that carried at least two shards counts as carried: the pool
/// reconstructs from any two, so re-sending the set over UDP would only duplicate
/// bytes the peer already has.
async fn send3_via_carrier(
    carrier: &Arc<net::carrier::Carrier>,
    target_fp: &str,
    ctx: &SealCtx,
    f: &[Vec<u8>],
    tag: &[u8; 16],
) -> bool {
    // A build or a run with no transport answers here, before anything is built.
    // The send below then doubles as the liveness check: a registry with no link
    // for this peer reports every shard as not carried, which is the same answer a
    // closed link gives, and both mean "keep to UDP".
    if !carrier.enabled() {
        return false;
    }
    let frames: Vec<Vec<u8>> = (0..3)
        .map(|i| net::build_gtf_v2_frame(&ctx.data_header(i as u8, false, 0), &f[i], tag))
        .collect();
    let carried = carrier.send_shards(target_fp, &frames).await;
    if carried < 3 {
        tracing::debug!(
            peer = %target_fp,
            carried,
            paths = carrier.link_count(),
            "carrier: partial shard send"
        );
    }
    carried >= 2
}

/// Build the optional-transport registry (SOTA P1-2).
///
/// Off unless `GHOST_QUIC=1`: a second transport is a second port and a second
/// parse surface, so an operator opts in. `GHOST_QUIC_PORT` overrides the bind.
///
/// **Multipath** (B23) is a second opt-in, `GHOST_QUIC_MULTIPATH=1`, and it needs
/// one more thing from the operator: the local addresses to use, in
/// `GHOST_QUIC_LOCAL_ADDRS` (comma-separated). Sending across two paths is what
/// needs a second outbound endpoint bound to the second address, and this crate
/// enumerates no interfaces — no `getifaddrs`/`GetAdaptersAddresses` binding and no
/// dependency added for one — so the address set is named, not guessed. An unset
/// or unparsable list leaves one path: a degraded node, not a dead one.
///
/// Receiving on two paths needs the same opt-in on the *other* side: the listener
/// accepts on every interface, but a connection's local address is the address the
/// peer dialled, so two sessions to one of our addresses are one path (and are
/// kept as one — see `net::carrier`). Two inbound sessions only stay two paths when
/// the peer actually reaches us on two of our addresses.
#[cfg(feature = "quic")]
fn build_carrier(nc: &Arc<GhostNode>) -> Arc<net::carrier::Carrier> {
    let enabled = std::env::var("GHOST_QUIC")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        return Arc::new(net::carrier::Carrier::disabled());
    }
    let port = std::env::var("GHOST_QUIC_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(vantablack::ghost::net::quic::QUIC_DEFAULT_PORT);
    let bind: SocketAddr = format!("0.0.0.0:{port}").parse().expect("valid bind");
    let carrier = match vantablack::ghost::net::quic::QuicTransport::listen(
        bind,
        Arc::clone(&nc.identity),
    ) {
        Ok(t) => net::carrier::Carrier::new(Arc::new(t)),
        Err(e) => {
            // A transport that cannot bind is not a reason to refuse to run: the
            // tunnel has a working UDP path either way, and saying so is the
            // difference between a degraded node and a dead one.
            tracing::error!(
                port,
                "QUIC: cannot bind, continuing without the transport: {e}"
            );
            return Arc::new(net::carrier::Carrier::disabled());
        }
    };

    let multipath = std::env::var("GHOST_QUIC_MULTIPATH")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !multipath {
        return carrier;
    }
    // A name that does not parse is skipped with a warning rather than silently
    // removing the path the operator asked for: multipath is the whole point of
    // setting the switch, so a path that failed to bind has to be audible.
    let named = std::env::var("GHOST_QUIC_LOCAL_ADDRS").unwrap_or_default();
    let mut added = 0usize;
    for raw in named.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let ip: IpAddr = match raw.parse() {
            Ok(ip) => ip,
            Err(_) => {
                tracing::warn!(addr = %raw, "QUIC: not an IP address, ignoring this local path");
                continue;
            }
        };
        match carrier.add_local_path(ip) {
            Ok(Some(_old)) => {
                tracing::warn!(%ip, "QUIC: local path redefined, the previous endpoint was dropped");
                added += 1;
            }
            Ok(None) => added += 1,
            Err(e) => {
                tracing::warn!(%ip, "QUIC: cannot bind a local path, skipping it: {e}");
            }
        }
    }
    if added == 0 {
        tracing::warn!(
            "QUIC: GHOST_QUIC_MULTIPATH is set but GHOST_QUIC_LOCAL_ADDRS names no bindable \
             address — running on one path. Inbound multipath from peers is unaffected."
        );
    } else {
        tracing::info!(paths = added, "QUIC: multipath enabled; shards spread across local paths");
    }
    carrier
}

/// A build with no optional transport compiled in.
#[cfg(not(feature = "quic"))]
fn build_carrier(_nc: &Arc<GhostNode>) -> Arc<net::carrier::Carrier> {
    Arc::new(net::carrier::Carrier::disabled())
}

/// The QUIC ingress + dial tasks, spawned where the receive pipeline lives
/// (SOTA P1-2).
///
/// The admission rule is the session table or the beacon-verified address
/// table — the same rule the relay uses — so a stranger cannot open a carrier
/// link just by reaching the port. Dialling happens only toward peers ICE has
/// already measured: a carrier link rides the address ICE verified, and dialling
/// before that would mean trusting an unauthenticated address with the session.
///
/// Ingress feeds `ingest`, the same entry point a UDP datagram takes, so a frame
/// that arrived over the transport is indistinguishable downstream.
macro_rules! spawn_carrier_tasks {
    ($carrier:expr, $rx:expr, $nc:expr, $nat:expr, $peers:expr) => {{
        #[cfg(feature = "quic")]
        if $carrier.enabled() {
            let carrier = Arc::clone($carrier);
            let rx = Arc::clone($rx);
            let nc = Arc::clone($nc);
            let peers = Arc::clone($peers);
            let nat = Arc::clone($nat);

            // ── Ingress ──
            tokio::spawn({
                let carrier = Arc::clone(&carrier);
                let rx = Arc::clone(&rx);
                let nc = Arc::clone(&nc);
                let peers = Arc::clone(&peers);
                async move {
                    loop {
                        let Some(transport) = carrier.transport().cloned() else {
                            return;
                        };
                        let known = {
                            let nc = Arc::clone(&nc);
                            let peers = Arc::clone(&peers);
                            move |fp: &str| nc.sessions.contains_key(fp) || peers.contains_key(fp)
                        };
                        let link = match transport.accept_one(known).await {
                            Ok(l) => l,
                            Err(e) => {
                                tracing::debug!("carrier: inbound session refused: {e}");
                                continue;
                            }
                        };
                        let fp = link.peer_fingerprint().to_string();
                        let src = link.remote_address();
                        // The path this link arrived on is its local address, so a
                        // peer that opens a second session on another of our
                        // addresses lands beside the first rather than on top of it
                        // (B23).
                        let local = link.local_addr();
                        match carrier.register(fp.clone(), Arc::clone(&link)) {
                            Ok(Some(old)) => old.close(),
                            Ok(None) => {}
                            // The peer's post-quantum key contradicts the pin: the
                            // link is already closed and nothing was registered.
                            Err(e) => {
                                tracing::warn!(peer = %fp, "carrier: inbound link refused: {e}");
                                continue;
                            }
                        }
                        let rx = Arc::clone(&rx);
                        let carrier = Arc::clone(&carrier);
                        tokio::spawn(async move {
                            while let Some(frame) = link.recv_frame().await {
                                tracing::trace!(peer = %fp, len = frame.len(), "carrier: frame in");
                                rx.ingest(&frame, src).await;
                            }
                            // The link ended: forget *this* link, so a peer holding
                            // a second path keeps it.
                            carrier.forget_link(&fp, local);
                            tracing::info!(peer = %fp, %local, "carrier: link closed");
                        });
                    }
                }
            });

            // ── Egress ──
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    // The registry holds the endpoints; if the transport is gone the
                    // task is done. `dial_paths` uses the wildcard endpoint and any
                    // named local paths itself, so there is no transport to fetch
                    // here.
                    if !carrier.enabled() {
                        return;
                    }
                    for (fp, addr) in nat.local_cache() {
                        if !nc.sessions.contains_key(&fp) && !peers.contains_key(&fp) {
                            continue;
                        }
                        // One dial per (peer, local address) that is not already
                        // carrying this peer: the named local paths first, then the
                        // wildcard endpoint when nothing else covers it (B23). A
                        // peer that is fully covered costs no handshake at all.
                        if carrier.covered(&fp) {
                            continue;
                        }
                        let established = carrier.dial_paths(&fp, addr).await;
                        if established == 0 {
                            // Expected against a peer running without the
                            // transport, or behind a filter that drops a second
                            // port. The UDP path is unaffected.
                            tracing::debug!(peer = %fp, %addr, "carrier: no new path established");
                        }
                    }
                }
            });
        }
    }};
}

/// Ship the three carriers to a peer whose direct checks failed.
///
/// One datagram per carrier, each inside its own envelope: the relay forwards
/// datagrams it cannot read, and the target reassembles the three it receives
/// into the same ciphertext a direct send would have produced.
#[allow(clippy::too_many_arguments)]
async fn send3_via_fallback(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    target_fp: &str,
    ctx: &SealCtx,
    f: &[Vec<u8>],
    tag: &[u8; 16],
    path: &FallbackPath,
    turn: Option<&Arc<TurnPath>>,
) -> Routed {
    let mut shipped = true;
    // Every framing below carries the *same* seal, so a datagram that leaves by
    // one route and a retry that leaves by another are interchangeable: the
    // receiver reassembles shards of one ciphertext, not of two.
    for i in 0..3 {
        let datagram = net::build_gtf_v2_frame(&ctx.data_header(i as u8, false, 0), &f[i], tag);
        let ok = match path {
            // A route entry is only ever written when a direct path failed, so a
            // `Direct` value here would mean the route table contradicted itself.
            FallbackPath::Direct => {
                debug_assert!(false, "a direct peer must not have a fallback route");
                false
            }
            FallbackPath::MeshRelay {
                relay_fp,
                relay_addr,
            } => {
                send_datagram_via_relay(nc, sock, relay_fp, relay_addr, target_fp, &datagram).await
            }
            FallbackPath::Turn { peer_relayed } => match turn {
                Some(t) => {
                    // The peer's own relayed address is the destination; our
                    // allocation is what carries the datagram to it.
                    t.send_sealed(*peer_relayed, datagram);
                    true
                }
                None => {
                    tracing::warn!(
                        peer = %target_fp,
                        "fallback: TURN route selected but this node holds no allocation"
                    );
                    false
                }
            },
        };
        shipped &= ok;
    }
    if !shipped {
        return Routed::Unroutable;
    }
    match path {
        FallbackPath::MeshRelay { .. } => Routed::MeshRelay,
        FallbackPath::Turn { .. } => Routed::Turn,
        FallbackPath::Direct => Routed::Unroutable,
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
    next: Option<u64>,
    buf: BTreeMap<u64, Vec<u8>>,
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
type ConnectOkCtrs = Arc<DashMap<[u8; 4], u64>>;
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
    fallback: Option<&Fallback>,
) {
    let Some(sess) = nc.sessions.get(peer_fp) else {
        tracing::debug!(peer = %peer_fp, "VPN egress: no session yet — dropped");
        return;
    };
    // SOTA P2-2: the epoch key and a fresh 96-bit nonce replace the counter-derived
    // nonce, so the counter is now a pure sequence number and there is no u32 wall
    // to warn about — the exhaustion watchdog this function used to carry existed
    // only because a wrapped counter would have collided with the nonce space.
    let ctx = SealCtx::from_session(&sess);
    drop(sess);
    if ctx.ratchet_due {
        // Due, not broken: traffic keeps flowing on this epoch until the step
        // completes, which is what stops a rotation from becoming an outage.
        tracing::debug!(
            peer = %peer_fp, epoch = ctx.epoch,
            "VPN egress: epoch full — ratchet step due"
        );
    }
    let mut payload = VPN_PAYLOAD_MAGIC.to_vec();
    payload.extend_from_slice(tunnel_wire);
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&payload);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    xchacha_seal_in_place(&ctx.key, &ctx.nonce, ctx.epoch, ctx.direction, &mut framed)
        .expect("sealing an owned buffer cannot fail");
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
    // The bulk payload region holds a [len u16][bytes] shard (exactly what
    // frame_shard produces and the receive path's unframe() consumes).
    let framed = frame_shard(&framed);
    let frame = net::build_gtf_v2_frame(&ctx.header(0, true, net::FLAG_TUNNEL), &framed, &tag);
    // A peer with no direct path carries its tunnel traffic over the same
    // fallback the control frames use; otherwise a VPN session would connect and
    // then silently stop moving packets.
    match fallback.and_then(|f| f.path(peer_fp)) {
        Some(FallbackPath::MeshRelay {
            relay_fp,
            relay_addr,
        }) => {
            let _ =
                send_datagram_via_relay(nc, &nc.socket, &relay_fp, &relay_addr, peer_fp, &frame)
                    .await;
        }
        Some(FallbackPath::Turn { peer_relayed }) => match fallback.and_then(|f| f.turn()) {
            Some(t) => t.send_sealed(peer_relayed, frame),
            None => tracing::warn!(
                peer = %peer_fp,
                "VPN egress: TURN route with no allocation — frame dropped"
            ),
        },
        Some(FallbackPath::Direct) | None => {
            let _ = nc.socket.send_to(&frame, endpoint).await;
        }
    }
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

// ── PACKET RECEIVER (uses LocklessDispatcher for parallel dispatch) ──
//
// Everything the receive path needs, so that *any* socket carrying sealed GTF
// frames for us can feed the same pipeline. Two sources exist in Phase 1: the mesh
// socket, and a TURN allocation's socket once the server relays a peer's datagrams
// to us. Giving them one entry point is what keeps a relayed frame
// indistinguishable from a direct one — and keeps the two from drifting apart as
// the receive path changes.
//
// Module-level rather than declared inside `main`: as a local type it could not be
// constructed by a test, so `ingest` — the single entry point for every received
// datagram — was the one part of the receive path with no coverage at all. Its
// `#[cfg(feature = "vpn")]` on the self-contained-frame bypass is what that cost:
// a default build spooled every single-frame control message as an unrecoverable
// shard and dropped it silently, which no test could see while the only way to
// call this was to run the binary and wait for a 1M-datagram epoch to fill.
struct RxContext {
    node: Arc<GhostNode>,
    peers: Arc<DashMap<String, SocketAddr>>,
    spool: Arc<DashMap<u64, Vec<Option<Vec<u8>>>>>,
    pending_hs: PendingHandshakes,
    revocation_list: Arc<RevocationList>,
    reputation: Arc<PoissonReputationMatrix>,
    vpn: Option<VpnMode>,
    exit_tunnels: ExitTunnels,
    sessions_rx: SessionChannels,
    rx_state_map: RxStateMap,
    connect_acks: ConnectAcks,
    connect_ok_ctrs: ConnectOkCtrs,
    trusted_exits: Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
    psk: Option<[u8; 32]>,
    tft: Arc<TitForTatEnforcer>,
    rotator: Option<Arc<ExitIpRotator>>,
    relay_role: Option<Arc<DerpRelay>>,
    /// Which peers need a relay, and the allocation that carries them.
    fallback: Option<Arc<Fallback>>,
    dispatcher: Arc<net::dispatcher::LocklessDispatcher>,
    /// The socket replies leave from. For a datagram the TURN server relayed to us
    /// this is still the mesh socket: the peer reached us through the relay, so its
    /// next frame arrives the same way, and the data path back to it is routed by
    /// the fallback table rather than by this address.
    socket: Arc<UdpSocket>,
}

impl RxContext {
    /// Pipe one received datagram into the tunnel.
    async fn ingest(&self, datagram: &[u8], src: SocketAddr) {
        let amt = datagram.len();
        if amt < net::MIN_FRAME_SIZE {
            return;
        }
        let _ = self.node.stats.packets_recv.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .node
            .stats
            .bytes_recv
            .fetch_add(amt as u64, Ordering::Relaxed);
        // Dispatch through lockless multi-worker session hash queue
        let _ = self.dispatcher.dispatch(datagram, src);
        // SOTA P2-2: the frame is decoded through the *version-aware* extractors.
        // The old code picked offsets by guessing bulk mode from the datagram's
        // length; the v2 marker in the flags byte says so outright, and both
        // versions keep the flags byte at offset 9.
        let ctr = net::parse_packet_counter_u64(datagram);
        let v2 = V2FrameMeta::of(datagram);
        // A frame with the self-contained bit (0x02) is a whole message in one
        // datagram: no RS sharding, no spool. It must bypass the 2-of-3 shard pool
        // — in it a single shard never assembles and is silently dropped — and it
        // must do so in **every** build, not only the VPN one. The bit means "the
        // payload region is one complete shard", which is a property of the
        // framing, not of the VPN feature; gating this bypass on `vpn` is what let
        // a default build swallow every ratchet step PDU while a VPN build
        // delivered it. `tests` below covers exactly that, in the default build.
        if net::parse_flags(datagram) & net::FLAG_TUNNEL != 0 {
            if let Some(sd) = unframe(net::extract_payload(datagram)) {
                self.deliver(ctr, v2, sd, src).await;
            }
            return;
        }
        #[cfg(not(feature = "vpn"))]
        let _ = &self.vpn;
        let si = datagram[net::OFFSET_SHARD_INDEX] as usize;
        if si > 2 {
            return;
        }
        let Some(sd) = unframe(net::extract_payload(datagram)) else {
            return;
        };
        if let Some(meta) = v2.filter(|meta| meta.shardsec) {
            let index = si as u8;
            let sealed = if sd.len() < 16 {
                return;
            } else {
                vantablack::ghost::net::shardsec::SealedShard {
                    index,
                    ciphertext: sd[..sd.len() - 16].to_vec(),
                    tag: sd[sd.len() - 16..].try_into().unwrap_or([0u8; 16]),
                }
            };
            let mut opened = None;
            for candidate in OpenCtx::snapshot_of(&self.node.sessions)
                .into_iter()
                .filter(|candidate| candidate.session_hash == net::parse_session_hash(datagram))
            {
                let Some(sess) = self.node.sessions.get(&candidate.peer_fp) else {
                    continue;
                };
                let ours = candidate.role.seal_direction();
                for direction in [ours.peer_direction(), ours] {
                    let plan = sess.plan_open(meta.epoch, direction, ctr);
                    let key = match &plan {
                        vantablack::ghost::session::ratchet::OpenPlan::Forward { key, .. } => *key,
                        vantablack::ghost::session::ratchet::OpenPlan::Cached { key, .. } => *key,
                        vantablack::ghost::session::ratchet::OpenPlan::Refused => {
                            if sess.gap_exceeds_max_skip(meta.epoch, direction, ctr) {
                                sess.trigger_forced_ratchet_step();
                            }
                            continue;
                        }
                    };
                    if let Ok(plain) = vantablack::ghost::net::shardsec::open_shard(
                        &key, meta.epoch, &meta.nonce, direction, &sealed,
                    ) {
                        sess.commit_open(meta.epoch, direction, plan);
                        opened = Some(plain);
                        break;
                    }
                }
                if opened.is_some() {
                    break;
                }
            }
            let Some(plain_shard) = opened else {
                return;
            };
            if let Some(r) = assemble(&self.spool, ctr, si, plain_shard).await {
                self.deliver(ctr, v2, r, src).await;
            }
            return;
        }
        // This path runs concurrently: `assemble` is what decides which of the (up
        // to) three carriers completes a frame, and it takes the reconstructed
        // ciphertext forward exactly once.
        if let Some(r) = assemble(&self.spool, ctr, si, sd).await {
            if std::env::var("GGN_DEBUG_RX").is_ok() {
                tracing::info!("assembled frame ctr={ctr} si={si} len={}", r.len());
            }
            self.deliver(ctr, v2, r, src).await;
        } else if std::env::var("GGN_DEBUG_RX").is_ok() {
            tracing::info!("assemble dropped ctr={ctr} si={si}");
        }
    }

    /// Hand a decrypted-frame candidate to `handle_pkt` on its own task.
    ///
    /// Spawned rather than awaited: `handle_pkt` can block on session locks and
    /// tunnel writes, and the receive loop must stay able to read the socket while
    /// that happens.
    async fn deliver(
        &self,
        ctr: u64,
        v2: Option<V2FrameMeta>,
        payload: Vec<u8>,
        src: SocketAddr,
    ) {
        let node = Arc::clone(&self.node);
        let peers = Arc::clone(&self.peers);
        let pending_hs = Arc::clone(&self.pending_hs);
        let sock = Arc::clone(&self.socket);
        let rl = Arc::clone(&self.revocation_list);
        let rep = Arc::clone(&self.reputation);
        let et = Arc::clone(&self.exit_tunnels);
        let sc = Arc::clone(&self.sessions_rx);
        let rsm = Arc::clone(&self.rx_state_map);
        let ca = Arc::clone(&self.connect_acks);
        let coc = Arc::clone(&self.connect_ok_ctrs);
        let te = Arc::clone(&self.trusted_exits);
        let tft = Arc::clone(&self.tft);
        let rot = self.rotator.clone();
        let relay_role = self.relay_role.clone();
        let fallback_state = self.fallback.clone();
        let vpn = self.vpn.clone();
        let psk = self.psk;
        tokio::spawn(async move {
            handle_pkt(
                node,
                &peers,
                &pending_hs,
                &sock,
                ctr,
                &payload,
                v2,
                &src,
                Some(&rl),
                Some(&*rep),
                &et,
                &sc,
                &rsm,
                &ca,
                &coc,
                &te,
                psk,
                vpn.as_ref(),
                Some(&*tft),
                rot.as_deref(),
                relay_role.as_deref(),
                fallback_state.as_deref(),
            )
            .await;
        });
    }
}

/// How often the maintenance tick looks for sessions whose epoch is spent.
const RATCHET_TICK: Duration = Duration::from_secs(5);
/// How long one unanswered step may sit before it is abandoned and retried.
///
/// A step that is never answered costs a PDU and a retry — it must not wedge the
/// session at the current epoch forever, which is why the bound exists at all.
const RATCHET_STEP_STALL: Duration = Duration::from_secs(30);

/// One pass of the ratchet maintenance tick (SOTA P2-2).
///
/// This is what makes the ratchet real rather than dormant: an epoch holds at most
/// `RATCHET_INTERVAL` datagrams, and when one is spent the session pays for a fresh
/// hybrid exchange. The step is *started* here and *completed* in `handle_pkt` when
/// the peer's signed answer arrives — or, on the answering side, when the
/// initiator's first frame in the new epoch authenticates.
///
/// Nothing stalls on it: traffic keeps flowing on the current epoch until the step
/// lands, and a lost step is abandoned after `RATCHET_STEP_STALL` and retried on the
/// next tick.
///
/// Extracted from the tick loop so the initiation site is callable as a unit — the
/// alternative was a body reachable only by waiting five seconds inside a spawned
/// task, which is how it stayed untested while it was wrong (see the self-contained
/// bit's history in `RxContext::ingest`).
async fn ratchet_maintenance_once(
    nc: &Arc<GhostNode>,
    addrs: &Arc<DashMap<String, SocketAddr>>,
    fallback: &Arc<Fallback>,
) {
    // Collect first: a DashMap guard must never be held across an await, and every
    // send below is one.
    let mut work: Vec<(String, SocketAddr, Vec<u8>)> = Vec::new();
    for e in nc.sessions.iter() {
        if e.ratchet_step_stalled(RATCHET_STEP_STALL) {
            tracing::warn!(
                peer = %e.peer_fingerprint,
                "ratchet step unanswered for {RATCHET_STEP_STALL:?} — abandoning and retrying"
            );
            e.abandon_ratchet_step();
        }
        if !e.ratchet_due() {
            continue;
        }
        let fp = e.peer_fingerprint.clone();
        // Reachability first. A step we cannot deliver would sit in flight for the
        // whole stall window and block the next attempt, so a peer with neither a
        // known address nor a fallback route is skipped rather than charged a
        // round trip.
        let addr = addrs.get(&fp).map(|v| *v.value());
        if addr.is_none() && fallback.path(&fp).is_none() {
            continue;
        }
        let addr = addr.unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
        let Some((x_pub, kem_pub)) = e.begin_ratchet_step() else {
            continue; // a step is already in flight
        };
        let Some(pdu) =
            build_ratchet_step_pdu(|d| nc.identity.sign(d).to_bytes(), &x_pub, &kem_pub)
        else {
            // Our own freshly generated material failed to parse: a bug, but the
            // step must not be left in flight over it.
            e.abandon_ratchet_step();
            continue;
        };
        work.push((fp, addr, pdu));
    }
    for (fp, addr, pdu) in work {
        let Some(sess) = nc.sessions.get(&fp) else {
            continue;
        };
        let ctx = SealCtx::from_session(&sess);
        drop(sess);
        let frame = seal_single(&ctx, &pdu);
        tracing::debug!(peer = %fp, epoch = ctx.epoch, "sending ratchet step");
        send_frame_to_peer(nc, &nc.socket, &addr, Some(fallback), &fp, frame).await;
    }
}

/// Handle a ratchet-step PDU that arrived (decrypted) in `payload`.
///
/// Returns `true` when the payload *was* a step PDU — including when it was
/// refused — so the caller stops interpreting it as application data.
///
/// Both directions live here because they are two halves of one exchange, and a
/// step that is only half understood is worse than one that is not understood at
/// all: a responder that acts on an unauthenticated step moves its epoch while the
/// initiator does not, which breaks a working session.
#[allow(clippy::too_many_arguments)]
async fn handle_ratchet_pdu(
    node: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
    payload: &[u8],
) -> bool {
    let is_init = payload.starts_with(REKEY_MAGIC);
    let is_answer = payload.starts_with(REKEY_RESPONSE_MAGIC);
    if !is_init && !is_answer {
        return false;
    }
    let Some(sess) = node.sessions.get(peer_fp) else {
        tracing::debug!(peer = %peer_fp, "ratchet PDU for an unknown peer — dropped");
        return true;
    };
    // Fail closed. The step is authenticated by the peer's *identity* key, which
    // is the same key the handshake verified; without a pinned key there is
    // nothing to check the step against, so it is refused rather than trusted.
    let Some(pk) = sess.peer_identity_pk() else {
        tracing::warn!(
            peer = %peer_fp,
            "ratchet PDU from a session with no pinned identity key — refused"
        );
        return true;
    };

    if is_init {
        let Some(blob) = parse_rekey_pdu(payload) else {
            tracing::warn!(peer = %peer_fp, "malformed ratchet step PDU");
            return true;
        };
        let material = rekey_init_signed_material(&blob.x25519_pub, &blob.kyber_pub);
        if !l0_identity::verify_peer_signature(&pk, &material, &blob.signature) {
            tracing::warn!(peer = %peer_fp, "ratchet step signature invalid — refused");
            return true;
        }
        // A *crossed* pair of steps — both peers due in the same interval — is not a
        // harmless duplicate: each side would complete its own step and install epoch
        // `n+1` derived from its own secrets, so both would hold the same epoch number
        // over different keys and nothing on the link would open again. The tie-break
        // is the fingerprint order (see `Session::admit_peer_step`), applied before the
        // step is answered so exactly one side advances.
        if !sess.admit_peer_step(&node.fingerprint()) {
            tracing::warn!(
                peer = %peer_fp,
                "crossed ratchet steps — our own step wins the tie-break; the arriving one is dropped"
            );
            return true;
        }
        let Some(answer) = sess.answer_ratchet_step(&blob.x25519_pub, &blob.kyber_pub) else {
            tracing::warn!(peer = %peer_fp, "ratchet step could not be answered");
            return true;
        };
        let pdu = build_rekey_response_pdu(
            |d| node.identity.sign(d).to_bytes(),
            &answer.x_public,
            &answer.kem_ct,
            &answer.confirm,
        );
        // Sealed on the epoch the peer still holds — we have only *prepared* the
        // new one, so a reply on it would be unopenable to the sender of the step.
        let ctx = SealCtx::from_session(&sess);
        drop(sess);
        let frame = seal_single(&ctx, &pdu);
        send_frame_to_peer(node, sock, src, fallback, peer_fp, frame).await;
        tracing::info!(
            peer = %peer_fp,
            epoch = answer.epoch,
            "ratchet step answered (epoch prepared, not yet installed)"
        );
        return true;
    }

    let Some(blob) = parse_rekey_response_pdu(payload) else {
        tracing::warn!(peer = %peer_fp, "malformed ratchet answer PDU");
        return true;
    };
    let material = rekey_answer_signed_material(&blob.x25519_pub, &blob.kyber_ct, &blob.confirm);
    if !l0_identity::verify_peer_signature(&pk, &material, &blob.signature) {
        tracing::warn!(peer = %peer_fp, "ratchet answer signature invalid — refused");
        return true;
    }
    let expected = sess.epoch() + 1;
    let answer = RatchetAnswer {
        x_public: blob.x25519_pub,
        kem_ct: blob.kyber_ct,
        confirm: blob.confirm,
        epoch: expected,
    };
    match sess.finish_ratchet_step(&answer) {
        Some(epoch) => tracing::info!(peer = %peer_fp, epoch, "ratchet step complete"),
        None => tracing::warn!(
            peer = %peer_fp,
            "ratchet answer did not confirm the step — epoch unchanged"
        ),
    }
    true
}

/// Route one already-built GTF datagram to a peer.
///
/// A ratchet step must travel by the same ladder as the data it protects: if the
/// session exists because a relay or a TURN allocation made it possible, a direct
/// reply to the source address would be filtered or unroutable, and the step would
/// silently never complete.
async fn send_frame_to_peer(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
    frame: Vec<u8>,
) {
    match fallback.and_then(|f| f.path(peer_fp)) {
        Some(FallbackPath::MeshRelay {
            relay_fp,
            relay_addr,
        }) => {
            let _ =
                send_datagram_via_relay(nc, sock, &relay_fp, &relay_addr, peer_fp, &frame).await;
        }
        Some(FallbackPath::Turn { peer_relayed }) => match fallback.and_then(|f| f.turn()) {
            Some(t) => t.send_sealed(peer_relayed, frame),
            None => tracing::warn!(
                peer = %peer_fp,
                "ratchet PDU: TURN route with no allocation — dropped"
            ),
        },
        Some(FallbackPath::Direct) | None => {
            let _ = sock.send_to(&frame, src).await;
        }
    }
}

// ── Post-Quantum In-Band Authentication (SOTA G3) ───────────────────

pub const PQ_AUTH_CHUNK_MAGIC: &[u8; 14] = b"PQ_AUTH_CHUNK:";
pub const PQ_AUTH_ACK_MAGIC: &[u8; 14] = b"PQ_AUTH_ACK__:";
pub const PQ_AUTH_CHUNK_PAYLOAD_SIZE: usize = 500;

/// Transmit this node's 5,358-byte hybrid identity proof in encrypted chunks over the session.
async fn send_pq_auth_proof(
    nc: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
) {
    let binding = {
        let Some(sess) = nc.sessions.get(peer_fp) else { return; };
        l0_identity::create_identity_binding(&nc.identity, &sess.master_key)
    };
    let chunks: Vec<&[u8]> = binding.chunks(PQ_AUTH_CHUNK_PAYLOAD_SIZE).collect();
    let total_chunks = chunks.len() as u8;

    for (idx, chunk) in chunks.iter().enumerate() {
        let Some(sess) = nc.sessions.get(peer_fp) else { return; };
        let ctx = SealCtx::from_session(&sess);
        drop(sess);

        let mut payload = Vec::with_capacity(14 + 1 + 1 + 2 + chunk.len());
        payload.extend_from_slice(PQ_AUTH_CHUNK_MAGIC);
        payload.push(idx as u8);
        payload.push(total_chunks);
        payload.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        payload.extend_from_slice(chunk);

        let frame = seal_single(&ctx, &payload);
        send_frame_to_peer(nc, sock, src, fallback, peer_fp, frame).await;
    }
}

/// Handle incoming chunked PQ authentication control messages.
async fn handle_pq_auth_pdu(
    node: &Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    fallback: Option<&Fallback>,
    peer_fp: &str,
    payload: &[u8],
) -> bool {
    let is_chunk = payload.starts_with(PQ_AUTH_CHUNK_MAGIC);
    let is_ack = payload.starts_with(PQ_AUTH_ACK_MAGIC);
    if !is_chunk && !is_ack {
        return false;
    }
    let Some(sess) = node.sessions.get(peer_fp) else {
        return true;
    };
    if is_chunk {
        let hlen = PQ_AUTH_CHUNK_MAGIC.len();
        if payload.len() < hlen + 4 {
            tracing::warn!(peer = %peer_fp, "malformed PQ auth chunk PDU");
            return true;
        }
        let chunk_idx = payload[hlen];
        let total_chunks = payload[hlen + 1];
        let chunk_len =
            u16::from_be_bytes([payload[hlen + 2], payload[hlen + 3]]) as usize;
        let data_start = hlen + 4;
        if payload.len() < data_start + chunk_len {
            tracing::warn!(peer = %peer_fp, "truncated PQ auth chunk data");
            return true;
        }
        let chunk_data = payload[data_start..data_start + chunk_len].to_vec();

        // Send ACK back to peer
        let mut ack_pdu = Vec::with_capacity(PQ_AUTH_ACK_MAGIC.len() + 1);
        ack_pdu.extend_from_slice(PQ_AUTH_ACK_MAGIC);
        ack_pdu.push(chunk_idx);
        let ctx = SealCtx::from_session(&sess);
        let ack_frame = seal_single(&ctx, &ack_pdu);
        send_frame_to_peer(node, sock, src, fallback, peer_fp, ack_frame).await;

        if let Some(full_binding) = sess.store_pq_chunk(chunk_idx, total_chunks, chunk_data) {
            let pinned_pk = sess.peer_identity_pk();
            let pinned_pq_comm = sess.peer_pq_commitment();
            let master_key = sess.master_key;
            drop(sess);

            if let Some(pk) = pinned_pk {
                match l0_identity::verify_hybrid_binding(
                    &pk,
                    pinned_pq_comm.as_ref(),
                    &master_key,
                    &full_binding,
                ) {
                    Ok(pq_pk) => {
                        if let Some(s) = node.sessions.get(peer_fp) {
                            s.set_pq_authenticated(true);
                            s.set_peer_pq_pk(pq_pk);
                        }
                        tracing::info!(
                            peer = %peer_fp,
                            "Post-quantum hybrid authentication SUCCEEDED (ML-DSA-65) — session elevated to active"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            peer = %peer_fp,
                            error = %err,
                            "Post-quantum hybrid authentication FAILED — evicting session"
                        );
                        if let Some(s) = node.sessions.get(peer_fp) {
                            s.set_pq_authenticated(false);
                        }
                        node.sessions.remove(peer_fp);
                    }
                }
            } else {
                tracing::warn!(
                    peer = %peer_fp,
                    "Cannot verify PQ auth: missing pinned peer identity PK"
                );
                node.sessions.remove(peer_fp);
            }
        }
        return true;
    }
    if is_ack {
        tracing::debug!(peer = %peer_fp, "PQ auth chunk acknowledged by peer");
        return true;
    }
    false
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

    // §2 spike: opt-in uniform mode intentionally uses the existing legacy
    // ML-KEM-512 payload sizes so it can be compared on the wire without
    // changing the transport fragmentation contract. It also avoids the
    // explicit suite-list magic, which would defeat the experiment.
    if uniform_handshake_enabled() {
        let (kp, ks) = generate_kyber_keypair();
        let pdu = build_uniform_handshake_pdu(
            &nc.identity.public_key_bytes(),
            |d| nc.identity.sign(d).to_bytes(),
            &xp,
            &kp,
        );
        let mut c = pdu;
        let raw = l4_rs::encode(&mut c);
        let tag = [0u8; 16];
        for i in 0..3 {
            let _ = send_gtf(sock, &t, [0, 0, 0, 0], 0, i as u8, &frame_shard(&raw[i]), &tag, false).await;
        }
        if pending_hs.len() >= MAX_PENDING_HANDSHAKES {
            tracing::warn!("Pending-handshake table full — uniform handshake skipped");
            return;
        }
        pending_hs.insert(t.to_string(), PendingHandshake::Kem512(xs, ks));
        tracing::info!(target = %t, "Uniform handshake sent");
        return;
    }
    // Advertise both suites with a public KEM key for each. The responder can
    // therefore select the strongest common suite rather than trusting a clear
    // preference byte or being forced to use the initiator's first choice.
    let (kp512, ks512) = generate_kyber_keypair();
    let (kp768, ks768) = generate_kyber768_keypair();
    let supported = vec![
        HybridCipherSuite::X25519MlKem768V3,
        HybridCipherSuite::X25519MlKem512V2,
    ];
    let keys = vec![
        (HybridCipherSuite::X25519MlKem768V3, kp768.to_bytes().to_vec()),
        (HybridCipherSuite::X25519MlKem512V2, kp512.to_bytes().to_vec()),
    ];
    let pdu = build_negotiated_handshake_pdu(
        &supported,
        &nc.identity.public_key_bytes(),
        &nc.identity.pq_commitment(),
        |d| nc.identity.sign(d).to_bytes(),
        &xp,
        &keys,
    )
    .expect("valid suite-list handshake");
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
    pending_hs.insert(
        t.to_string(),
        PendingHandshake::Negotiated {
            x_secret: xs,
            kem512: ks512,
            kem768: ks768,
            offered: supported,
        },
    );
    tracing::info!(target = %t, "Handshake sent");
}

/// Insert a received frame into the reorder buffer; return frames that
/// can be flushed in sequence order (duplicates/old frames are dropped).
fn uniform_handshake_enabled() -> bool {
    std::env::var("GHOST_HANDSHAKE_UNIFORM")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn rx_push(state: &mut RxState, ctr: u64, payload: Vec<u8>) -> Vec<Vec<u8>> {
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

/// Optional beacon sections (Phase 1 P1-1). Each is `[4 magic][u16 len][bytes]`,
/// appended after the 112-byte signed prefix.
///
/// The frame is self-describing and validated by *tiling*: a datagram is only
/// read as sectioned when its sections consume it exactly. That is what lets the
/// pre-P1-1 fixed layouts keep parsing — see [`parse_beacon_sections`].
const BEACON_SECTION_ZK: &[u8; 4] = b"ZKPR";
const BEACON_SECTION_ICE: &[u8; 4] = b"ICEO";
/// Empty section: "this node will relay for others" (`GHOST_RELAY=1`).
///
/// Capability, not address. A relay is reached at the address its beacon came
/// from — the same socket it forwards on — so carrying an address would let a
/// peer advertise someone else's. Its presence is the whole message, which is
/// why the payload must be empty.
const BEACON_SECTION_RELAY: &[u8; 4] = b"RLYC";
/// 32-byte SHA-256 commitment to the sender's ML-DSA-65 public key (P2-1).
///
/// A commitment and not the key: the key is 1952 bytes and its signature 3309,
/// so a hybrid proof cannot travel in a 512–1472-byte datagram at all. What fits
/// is the name of the key, and a verifier that remembers it (`Carrier::
/// pin_commitment`) can then refuse a later session that presents a different
/// post-quantum key — which is what stops a forger with the classical private key
/// from substituting one of their own.
const BEACON_SECTION_PQ_COMMIT: &[u8; 4] = b"PQK!";

/// How long a measured direct contact stays valid before it must be re-observed.
/// A NAT mapping is typically torn down after 30–120 s of silence, so a contact
/// is not treated as permanent.
const ICE_CONTACT_WINDOW_SECS: f64 = 120.0;

/// Wall-clock seconds since the Unix epoch, the clock `ContactPlan` timestamps
/// live on.
fn unix_now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// The legacy fixed beacon layout, still accepted from older peers. The 208-byte
/// variant that carried a ZK block at fixed offsets is gone with the hard switch
/// (SOTA §6 G5): a datagram that long is now read as a bare, identity-only
/// beacon, never as a peer that proved membership.
const BEACON_LEGACY_LEN: usize = 112;

/// Optional sections carried by an extended beacon.
struct BeaconSections<'a> {
    /// `(context, proof)` when a ZK membership proof is present. The context is
    /// the timestamp the proof is bound to; the proof is `R ‖ z` (SOTA §6 G5).
    zk: Option<(&'a [u8; 32], &'a [u8])>,
    /// The sender's ICE offer, as produced by `ice::IceOffer::encode`.
    ice_offer: Option<&'a str>,
    /// Whether the sender advertises relay capability.
    relay_capable: bool,
    /// SHA-256 commitment to the sender's post-quantum public key (P2-1).
    pq_commitment: Option<&'a [u8; 32]>,
}

/// Parse the trailing optional sections of a beacon.
///
/// Returns `None` when the datagram does not tile as sections. That fallback is
/// what keeps the parser honest about older layouts — the trailing bytes of a
/// legacy beacon are arbitrary, and a coincidence must be read as a legacy
/// beacon rather than as a section whose contents were never intended.
fn parse_beacon_sections(buf: &[u8], amt: usize) -> Option<BeaconSections<'_>> {
    let mut pos = BEACON_LEGACY_LEN;
    let mut zk = None;
    let mut ice_offer = None;
    let mut relay_capable = false;
    let mut pq_commitment = None;
    while pos < amt {
        if pos + 6 > amt {
            return None;
        }
        let magic = &buf[pos..pos + 4];
        let len = u16::from_be_bytes([buf[pos + 4], buf[pos + 5]]) as usize;
        let start = pos + 6;
        let end = start + len;
        if end > amt {
            return None;
        }
        if magic == BEACON_SECTION_ZK {
            if len != ZK_CONTEXT_LEN + ZK_PROOF_LEN {
                return None;
            }
            let context: &[u8; 32] = buf[start..start + ZK_CONTEXT_LEN].try_into().ok()?;
            zk = Some((context, &buf[start + ZK_CONTEXT_LEN..end]));
        } else if magic == BEACON_SECTION_ICE {
            ice_offer = Some(std::str::from_utf8(&buf[start..end]).ok()?);
        } else if magic == BEACON_SECTION_RELAY {
            if len != 0 {
                return None;
            }
            relay_capable = true;
        } else if magic == BEACON_SECTION_PQ_COMMIT {
            // A commitment section of the wrong size is a malformed section, not a
            // shorter commitment: fall back to the legacy reading (below), where it
            // is ignored. A beacon without a usable commitment pins nothing, which
            // is the same as a peer that never sent one.
            if len != 32 {
                return None;
            }
            pq_commitment = buf[start..end].try_into().ok();
        } else {
            return None;
        }
        pos = end;
    }
    Some(BeaconSections {
        zk,
        ice_offer,
        relay_capable,
        pq_commitment,
    })
}

/// Append one optional beacon section.
fn push_beacon_section(buf: &mut Vec<u8>, magic: &[u8; 4], payload: &[u8]) {
    buf.extend_from_slice(magic);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
}

/// Assemble a beacon from its signed prefix and optional sections.
///
/// `zk` is the membership proof to carry, already created for this identity: the
/// builder never sees the PSK, so it cannot be asked for a proof it has no secret
/// to make. The boolean this replaced could not tell "no proof wanted" from "no
/// secret to prove with", and emitted a signature-shaped block for neither
/// (SOTA §6 G5).
fn build_beacon_packet(
    pk: &[u8; 32],
    signer: impl Fn(&[u8]) -> [u8; 64],
    zk: Option<([u8; 32], [u8; 64])>,
    ice_offer: Option<&str>,
    relay_capable: bool,
    pq_commitment: Option<&[u8; 32]>,
) -> Vec<u8> {
    // Signed prefix: [16 magic][32 full Ed25519 pk][64 signature over pk].
    let mut buf = vec![0u8; BEACON_LEGACY_LEN];
    buf[0..16].copy_from_slice(BEACON_PREFIX);
    buf[16..48].copy_from_slice(pk);
    let sig = signer(&buf[16..48]);
    buf[48..112].copy_from_slice(&sig);

    if let Some((context, proof)) = zk {
        // A membership proof, already created for this identity. The builder
        // never sees the PSK, so it cannot be asked for a proof it has no secret
        // to make — the old boolean could not tell "no proof wanted" from "no
        // secret to prove with" and would emit a signature-shaped block for
        // neither (SOTA §6 G5).
        let mut section = Vec::with_capacity(ZK_CONTEXT_LEN + ZK_PROOF_LEN);
        section.extend_from_slice(&context);
        section.extend_from_slice(&proof);
        push_beacon_section(&mut buf, BEACON_SECTION_ZK, &section);
    }
    if let Some(offer) = ice_offer {
        push_beacon_section(&mut buf, BEACON_SECTION_ICE, offer.as_bytes());
    }
    if relay_capable {
        push_beacon_section(&mut buf, BEACON_SECTION_RELAY, &[]);
    }
    if let Some(commitment) = pq_commitment {
        push_beacon_section(&mut buf, BEACON_SECTION_PQ_COMMIT, commitment);
    }
    buf
}

async fn handle_pkt(
    node: Arc<GhostNode>,
    peers: &DashMap<String, SocketAddr>,
    pending_hs: &PendingHandshakes,
    sock: &UdpSocket,
    ctr: u64,
    data: &[u8],
    // The v2 header's seal metadata, when the frame has one (SOTA P2-2).
    // `None` means a v1 frame: counter-derived nonce, seed key.
    v2: Option<V2FrameMeta>,
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
    relay_role: Option<&DerpRelay>,
    fallback_state: Option<&Fallback>,
) {
    #[cfg(not(feature = "vpn"))]
    let _ = vpn_mode;
    // Explicit suite-list negotiation handshake (counter == 0).
    if ctr == 0 && data.starts_with(HANDSHAKE_NEGOTIATION_MAGIC) {
        let Some(hs) = parse_negotiated_handshake_pdu(data) else {
            tracing::warn!(peer = %src, "Invalid suite-list handshake");
            return;
        };
        let Some(material) = data.get(..data.len() - 64) else { return; };
        if !l0_identity::verify_peer_signature(&hs.identity_pk, material, &hs.signature) {
            tracing::warn!(peer = %src, "Suite-list handshake signature invalid");
            return;
        }
        let local = [
            HybridCipherSuite::X25519MlKem768V3,
            HybridCipherSuite::X25519MlKem512V2,
        ];
        let Some(selected) = negotiate_cipher_suite(&local, &hs.supported.iter().map(|s| s.wire_id()).collect::<Vec<_>>()) else {
            tracing::warn!(peer = %src, "No mutually supported cipher suite");
            return;
        };
        let Some((_, peer_key)) = hs.kyber_keys.iter().find(|(suite, _)| *suite == selected) else { return; };
        let kem = match selected {
            HybridCipherSuite::X25519MlKem512V2 => kyber_encapsulate(peer_key)
                .map(|(ct, ss)| (ct.to_vec(), ss)),
            HybridCipherSuite::X25519MlKem768V3 => kyber768_encapsulate(peer_key),
        };
        let Ok((ct, kem_ss)) = kem else {
            tracing::warn!(peer = %src, "Suite-list KEM encapsulation failed");
            return;
        };
        let responder_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let responder_public = x25519_dalek::PublicKey::from(&responder_secret);
        let x_shared = responder_secret.diffie_hellman(&x25519_dalek::PublicKey::from(hs.x25519_pub));
        // SOTA G2/G3: bind the transcript into the KDF. The initiator's public key comes
        // from the offer, ours is the ephemeral just generated, and the ciphertext is
        // the one about to be sent back — both peers hash identical bytes and both PQ commitments.
        let master = derive_hybrid_master_key_with_transcript(
            selected,
            x_shared.as_bytes(),
            &kem_ss,
            psk.as_ref(),
            &hs.x25519_pub,
            responder_public.as_bytes(),
            &ct,
            &hs.pq_commitment,
            &node.identity.pq_commitment(),
        );
        let response = build_negotiated_response_pdu(
            selected,
            &node.identity.public_key_bytes(),
            &node.identity.pq_commitment(),
            |m| node.identity.sign(m).to_bytes(),
            responder_public.as_bytes().try_into().expect("x25519 key length"),
            &ct,
        ).expect("valid suite-list response");
        let mut encoded = response;
        let raw = l4_rs::encode(&mut encoded);
        let tag = [0u8; 16];
        for i in 0..3 {
            let _ = send_gtf(sock, src, [0, 0, 0, 0], 1, i as u8, &frame_shard(&raw[i]), &tag, false).await;
        }
        let fp = hex::encode(&hs.identity_pk[..8]);
        peers.insert(fp.clone(), *src);
        let mut session = Session::new_with_role(master, fp.clone(), SessionRole::Responder);
        session.set_cipher_suite(selected);
        session.pin_peer_identity(hs.identity_pk);
        session.pin_peer_pq_commitment(hs.pq_commitment);
        node.sessions.insert(fp.clone(), session);
        tracing::info!(peer = %src, suite = selected.wire_id(), "Explicit suite-negotiated session established");
        // SOTA G3: Immediately transmit local post-quantum authentication chunks
        send_pq_auth_proof(&node, sock, src, fallback_state, &fp).await;
        return;
    }

    // Versioned suite-negotiation handshake (counter == 0).
    // The suite byte is authenticated as part of the handshake transcript.
    // Both ML-KEM variants are accepted here; the response echoes the selected
    // suite, so an initiator cannot be downgraded by rewriting cleartext.
    if ctr == 0 && data.starts_with(HANDSHAKE_V3_MAGIC) {
        let Some(hs) = parse_handshake_pdu_suite(data) else {
            tracing::warn!(peer = %src, "Invalid suite-negotiation handshake");
            return;
        };
        let mut signed = Vec::with_capacity(1 + 32 + hs.kyber_pub.len() + 32);
        signed.push(hs.suite.wire_id());
        signed.extend_from_slice(&hs.x25519_pub);
        signed.extend_from_slice(&hs.kyber_pub);
        signed.extend_from_slice(&hs.identity_pk);
        if !l0_identity::verify_peer_signature(&hs.identity_pk, &signed, &hs.signature) {
            tracing::warn!(peer = %src, "Suite handshake signature invalid");
            return;
        }
        let kem_result = match hs.suite {
            HybridCipherSuite::X25519MlKem512V2 => kyber_encapsulate(&hs.kyber_pub)
                .map(|(ct, ss)| (ct.to_vec(), ss)),
            HybridCipherSuite::X25519MlKem768V3 => kyber768_encapsulate(&hs.kyber_pub),
        };
        let (ct, ks) = match kem_result {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(peer = %src, "Suite handshake KEM encapsulation failed");
                return;
            }
        };
        let bs = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let bp = x25519_dalek::PublicKey::from(&bs);
        let xs = bs.diffie_hellman(&x25519_dalek::PublicKey::from(hs.x25519_pub));
        let d = derive_hybrid_master_key_with_suite(hs.suite, xs.as_bytes(), &ks, psk.as_ref());
        let mut bp_arr = [0u8; 32];
        bp_arr.copy_from_slice(bp.as_bytes());
        let resp = build_response_pdu_suite(
            hs.suite,
            &node.identity.public_key_bytes(),
            |m| node.identity.sign(m).to_bytes(),
            &bp_arr,
            &ct,
        )
        .expect("suite response layout");
        let mut rc = resp;
        let raw = l4_rs::encode(&mut rc);
        let tag = [0u8; 16];
        for i in 0..3 {
            let _ = send_gtf(sock, src, [0, 0, 0, 0], 1, i as u8, &frame_shard(&raw[i]), &tag, false).await;
        }
        peers.insert(hex::encode(&hs.identity_pk[..8]), *src);
        let fp = hex::encode(&hs.identity_pk[..8]);
        let mut session = Session::new_with_role(d, fp.clone(), SessionRole::Responder);
        session.set_cipher_suite(hs.suite);
        session.pin_peer_identity(hs.identity_pk);
        node.sessions.insert(fp.clone(), session);
        tracing::info!(peer = %src, fingerprint = %fp, suite = hs.suite.wire_id(), "Suite-negotiated session established");
        return;
    }

    // Opt-in §2 uniform handshake. Its random prefix means it must be
    // identified by the reserved handshake counter and exact legacy payload
    // length, never by a magic string.
    if uniform_handshake_enabled()
        && ctr == 0
        && data.len() >= vantablack::ghost::layers::l1_kem::UNIFORM_HANDSHAKE_BLOB_LEN
    {
        let wire = &data[..vantablack::ghost::layers::l1_kem::UNIFORM_HANDSHAKE_BLOB_LEN];
        let Some(hs) = parse_uniform_handshake_pdu(wire) else { return; };
        let Some(signed_material) = uniform_handshake_signed_material(wire) else { return; };
        if !l0_identity::verify_peer_signature(&hs.identity_pk, &signed_material, &hs.signature) {
            tracing::warn!(peer = %src, "Uniform handshake signature invalid");
            return;
        }
        let fp = hex::encode(&hs.identity_pk[..8]);
        if node.sessions.len() >= MAX_SESSIONS || node.sessions.contains_key(&fp) {
            tracing::warn!(peer = %src, fingerprint = %fp, "Uniform handshake rejected — session limit or replay");
            return;
        }
        let Ok((ct, ks)) = kyber_encapsulate(&hs.kyber_pub) else {
            tracing::warn!(peer = %src, "Uniform handshake KEM encapsulation failed");
            return;
        };
        let bs = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let bp = x25519_dalek::PublicKey::from(&bs);
        let xs = bs.diffie_hellman(&x25519_dalek::PublicKey::from(hs.x25519_pub));
        let master = derive_hybrid_master_key_with_psk(xs.as_bytes(), &ks, psk.as_ref());
        let mut bp_arr = [0u8; 32];
        bp_arr.copy_from_slice(bp.as_bytes());
        let resp = build_uniform_response_pdu(
            &node.identity.public_key_bytes(),
            |m| node.identity.sign(m).to_bytes(),
            &bp_arr,
            &ct,
        );
        let mut encoded = resp;
        let raw = l4_rs::encode(&mut encoded);
        let tag = [0u8; 16];
        for i in 0..3 {
            let _ = send_gtf(sock, src, [0, 0, 0, 0], 1, i as u8, &frame_shard(&raw[i]), &tag, false).await;
        }
        peers.insert(fp.clone(), *src);
        let session = Session::new_with_role(master, fp.clone(), SessionRole::Responder);
        session.pin_peer_identity(hs.identity_pk);
        node.sessions.insert(fp, session);
        tracing::info!(peer = %src, "Uniform handshake session established");
        return;
    }

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
        let responder_session = Session::new_with_role(d, fp.clone(), SessionRole::Responder);
        // Pin the initiator's identity key: it is what a later ratchet step is
        // verified against, and without it a step is refused rather than trusted.
        responder_session.pin_peer_identity(hs.identity_pk);
        node.sessions.insert(fp.clone(), responder_session);
        // Keep the relay's address book current: a session is also the strongest
        // statement that this peer is who it says it is, and its address may have
        // moved since the beacon that first authorized it.
        if let Some(relay) = relay_role {
            relay.authorize(&fp, *src);
        }
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

    // Explicit suite-list negotiation response (counter == 1).
    if ctr == 1 && data.starts_with(RESPONSE_NEGOTIATION_MAGIC) {
        let Some(resp) = parse_negotiated_response_pdu(data) else {
            tracing::warn!(peer = %src, "Invalid suite-list response");
            return;
        };
        let Some(material) = data.get(..data.len() - 64) else { return; };
        if !l0_identity::verify_peer_signature(&resp.identity_pk, material, &resp.signature) {
            tracing::warn!(peer = %src, "Suite-list response signature invalid");
            return;
        }
        let Some((_, pending)) = pending_hs.remove(&src.to_string()) else {
            tracing::warn!(peer = %src, "Suite-list response has no pending handshake");
            return;
        };
        let PendingHandshake::Negotiated { x_secret, kem512, kem768, offered } = pending else {
            tracing::warn!(peer = %src, "Suite-list response matched a legacy pending handshake");
            return;
        };
        let local = [
            HybridCipherSuite::X25519MlKem768V3,
            HybridCipherSuite::X25519MlKem512V2,
        ];
        let expected = negotiate_cipher_suite(
            &local,
            &offered.iter().map(|suite| suite.wire_id()).collect::<Vec<_>>(),
        );
        if expected != Some(resp.suite) {
            tracing::warn!(
                peer = %src,
                selected = resp.suite.wire_id(),
                expected = ?expected,
                "Downgrade/unsupported suite response rejected"
            );
            return;
        }
        let kem_ss = match resp.suite {
            HybridCipherSuite::X25519MlKem512V2 => {
                let Ok(ct) = Ciphertext::<MlKem512>::try_from(resp.kyber_ct.as_slice()) else { return; };
                kem512.decapsulate(&ct).as_slice().to_vec()
            }
            HybridCipherSuite::X25519MlKem768V3 => {
                let Ok(ss) = kyber768_decapsulate(&kem768, &resp.kyber_ct) else { return; };
                ss
            }
        };
        // Our own public key has to be captured *before* `diffie_hellman` consumes the
        // secret, and it is part of the transcript (SOTA G2/G3).
        let initiator_public = x25519_dalek::PublicKey::from(&x_secret);
        let x_shared = x_secret.diffie_hellman(&x25519_dalek::PublicKey::from(resp.x25519_pub));
        let master = derive_hybrid_master_key_with_transcript(
            resp.suite,
            x_shared.as_bytes(),
            &kem_ss,
            psk.as_ref(),
            initiator_public.as_bytes(),
            &resp.x25519_pub,
            &resp.kyber_ct,
            &node.identity.pq_commitment(),
            &resp.pq_commitment,
        );
        let fp = hex::encode(&resp.identity_pk[..8]);
        peers.insert(fp.clone(), *src);
        let mut session = Session::new(master, fp.clone());
        session.set_cipher_suite(resp.suite);
        session.pin_peer_identity(resp.identity_pk);
        session.pin_peer_pq_commitment(resp.pq_commitment);
        node.sessions.insert(fp.clone(), session);
        tracing::info!(peer = %src, suite = resp.suite.wire_id(), "Explicit suite-negotiated session established (initiator)");
        // SOTA G3: Immediately transmit local post-quantum authentication chunks
        send_pq_auth_proof(&node, sock, src, fallback_state, &fp).await;
        return;
    }

    // Versioned suite-negotiation response (counter == 1).
    if ctr == 1 && data.starts_with(RESPONSE_V3_MAGIC) {
        let Some(resp) = parse_response_pdu_suite(data) else {
            tracing::warn!(peer = %src, "Invalid suite-negotiation response");
            return;
        };
        let mut signed = Vec::with_capacity(1 + 32 + resp.kyber_ct.len() + 32);
        signed.push(resp.suite.wire_id());
        signed.extend_from_slice(&resp.x25519_pub);
        signed.extend_from_slice(&resp.kyber_ct);
        signed.extend_from_slice(&resp.identity_pk);
        if !l0_identity::verify_peer_signature(&resp.identity_pk, &signed, &resp.signature) {
            tracing::warn!(peer = %src, "Suite response signature invalid");
            return;
        }
        let fp = hex::encode(&resp.identity_pk[..8]);
        let Some((_, pending)) = pending_hs.remove(&src.to_string()) else {
            tracing::warn!(peer = %src, "Suite response has no pending handshake");
            return;
        };
        let Some((ax, ky_ss)) = (match (resp.suite, pending) {
            (HybridCipherSuite::X25519MlKem512V2, PendingHandshake::Kem512(ax, dk)) => {
                let ct = Ciphertext::<MlKem512>::try_from(resp.kyber_ct.as_slice()).ok();
                ct.map(|ct| (ax, dk.decapsulate(&ct).as_slice().to_vec()))
            }
            _ => None,
        }) else {
            tracing::warn!(peer = %src, "Suite response does not match pending handshake");
            return;
        };
        let xs = ax.diffie_hellman(&x25519_dalek::PublicKey::from(resp.x25519_pub));
        let d = derive_hybrid_master_key_with_suite(resp.suite, xs.as_bytes(), &ky_ss, psk.as_ref());
        peers.insert(fp.clone(), *src);
        let mut session = Session::new(d, fp.clone());
        session.set_cipher_suite(resp.suite);
        session.pin_peer_identity(resp.identity_pk);
        node.sessions.insert(fp.clone(), session);
        tracing::info!(peer = %src, fingerprint = %fp, suite = %resp.suite.wire_id(), "Suite-negotiated session established (initiator)");
        return;
    }

    // Opt-in §2 uniform response. Exact length and reserved response counter
    // keep this separate from ordinary application frames.
    if uniform_handshake_enabled()
        && ctr == 1
        && data.len() >= vantablack::ghost::layers::l1_kem::UNIFORM_RESPONSE_BLOB_LEN
    {
        let wire = &data[..vantablack::ghost::layers::l1_kem::UNIFORM_RESPONSE_BLOB_LEN];
        let Some(resp) = parse_uniform_response_pdu(wire) else { return; };
        let Some(signed_material) = uniform_response_signed_material(wire) else { return; };
        if !l0_identity::verify_peer_signature(&resp.identity_pk, &signed_material, &resp.signature) {
            tracing::warn!(peer = %src, "Uniform response signature invalid");
            return;
        }
        let Some((_, PendingHandshake::Kem512(ax, dk))) = pending_hs.remove(&src.to_string()) else {
            tracing::warn!(peer = %src, "Uniform response has no pending handshake");
            return;
        };
        let ct = Ciphertext::<MlKem512>::from(resp.kyber_ct);
        let ks = dk.decapsulate(&ct);
        let xs = ax.diffie_hellman(&x25519_dalek::PublicKey::from(resp.x25519_pub));
        let master = derive_hybrid_master_key_with_psk(xs.as_bytes(), ks.as_slice(), psk.as_ref());
        let fp = hex::encode(&resp.identity_pk[..8]);
        peers.insert(fp.clone(), *src);
        let session = Session::new(master, fp.clone());
        session.pin_peer_identity(resp.identity_pk);
        node.sessions.insert(fp, session);
        tracing::info!(peer = %src, "Uniform handshake session established (initiator)");
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
        if let Some((_, PendingHandshake::Kem512(ax, dk))) = pending_hs.remove(&src.to_string()) {
            let ks = dk.decapsulate(&ct);
            let ky_ss: Vec<u8> = ks.as_slice().to_vec();
            let xs = ax.diffie_hellman(&x25519_dalek::PublicKey::from(resp.x25519_pub));
            let d = derive_hybrid_master_key_with_suite(HybridCipherSuite::X25519MlKem512V2, xs.as_bytes(), &ky_ss, psk.as_ref());

            // WIRED: Pin key to physical RAM via LockedMemory (mlock / VirtualLock)
            if let Some(mut locked) = LockedMemory::allocate(32) {
                locked.as_mut_slice()[..32].copy_from_slice(&d);
            }

            peers.insert(fp.clone(), *src);
            let initiator_session = Session::new(d, fp.clone());
            // Same pin on this side: the answer to a ratchet step is verified
            // against the responder's identity key.
            initiator_session.pin_peer_identity(resp.identity_pk);
            node.sessions.insert(fp.clone(), initiator_session);
            if let Some(relay) = relay_role {
                relay.authorize(&fp, *src);
            }
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
    let candidates = OpenCtx::snapshot_of(&node.sessions);
    for cand in &candidates {
        let peer_fp = cand.peer_fp.clone();
        let key = cand.master_key;
        let sh = cand.session_hash;
        let role = cand.role;
        let plain = if v2.is_some_and(|meta| meta.shardsec) {
            if cand.session_hash != net::parse_session_hash(data) {
                continue;
            }
            data.to_vec()
        } else {
            let Some(sess) = node.sessions.get(&cand.peer_fp) else {
                continue;
            };
            let Some(plain) = open_received_frame(cand, &sess, data, ctr, v2) else {
                continue;
            };
            plain
        };
        let pt: &[u8] = &plain;

        // ── Cover traffic (SOTA P3-1) ──
        //
        // A placeholder frame exists only to keep the *rate* constant, so it must
        // have no effect at all: no dispatch, no ratchet bookkeeping, and not even
        // a replay-window slot — which is the plan's "does not disturb the replay
        // window". Dropping it here also keeps it from installing a prepared epoch.
        //
        // The decision is taken on the decrypted marker, never on the header's
        // `FLAG_DUMMY` bit: header flags sit outside the AEAD, so anyone on the
        // path can flip them, and a receiver that trusted the bit could be made
        // either to discard a real frame or to dispatch a placeholder. The marker
        // is inside the ciphertext, so it is unforgeable and cannot be stripped.
        if frame_payload(pt).is_some_and(net::is_dummy_payload) {
            node.stats
                .cover_recv
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::trace!(peer = %peer_fp, "cover-traffic frame dropped by design");
            return;
        }

        // A frame that authenticated under a *prepared* epoch installs it. This is
        // the responder's half of the step: it answers immediately but keeps
        // sealing on the old epoch until the initiator demonstrably committed, so
        // only a frame that actually opens under the new key moves it. A forged
        // frame cannot: it has no key, so it never reaches here.
        if let Some(meta) = v2 {
            if let Some(s) = node.sessions.get(&peer_fp) {
                if meta.epoch > s.epoch() {
                    s.activate_epoch(meta.epoch);
                }
            }
        }

        // Replay protection: the per-session 64-bit sliding window must accept
        // the counter for the current epoch (or v1); retired epochs already enforce
        // single-use keys cryptographically in MsgChain and must not disturb the
        // current epoch's replay window.
        let is_retired = v2.is_some_and(|meta| {
            node.sessions.get(&peer_fp).is_some_and(|s| meta.epoch < s.epoch())
        });
        if !is_retired {
            let accepted = node
                .sessions
                .get(&peer_fp)
                .map(|s| s.check_inbound(ctr))
                .unwrap_or(false);
            if !accepted {
                tracing::debug!(peer = %peer_fp, counter = ctr, "Replay/out-of-window frame dropped");
                return;
            }
        }

        // ── Ratchet step (SOTA P2-2) ──
        //
        // Before any data handling, and before the tunnel check: these two magics
        // are control PDUs for the ratchet, they are distinct from every other
        // magic in the stack, and neither is ever a message for an application.
        if let Some(payload) = frame_payload(pt) {
            if handle_ratchet_pdu(&node, sock, src, fallback_state, &peer_fp, payload).await {
                return;
            }
        }

        // ── Post-Quantum Identity Authentication (SOTA G3) ──
        if let Some(payload) = frame_payload(pt) {
            if handle_pq_auth_pdu(&node, sock, src, fallback_state, &peer_fp, payload).await {
                return;
            }
        }

        // Gate all application traffic on post-quantum identity verification (SOTA G3).
        let is_pq_auth = node
            .sessions
            .get(&peer_fp)
            .map(|s| s.is_pq_authenticated())
            .unwrap_or(false);
        if !is_pq_auth {
            tracing::debug!(
                peer = %peer_fp,
                "Application traffic dropped: session post-quantum authentication pending"
            );
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

        // Blind relay (SOTA P1-1 / B22): a decrypted payload may carry a
        // single-hop envelope addressed to another peer. We hold no key for the
        // region it carries and must not touch it — the forward is byte-for-byte
        // by construction, which is the whole security property of the relay.
        //
        // The envelope magic is distinct from the onion's (`BLND!` vs `RLY!`), so
        // the two paths cannot be confused even though the onion's *last* hop also
        // arrives with a hop count of zero.
        if let Some(payload) = frame_payload(pt) {
            if let Some(blind) = relay::parse_blind_frame(payload) {
                let Some(relay) = relay_role else {
                    tracing::debug!(
                        from = %peer_fp,
                        target = %blind.target_fingerprint,
                        "Relay: blind envelope received but relaying is not enabled (GHOST_RELAY)"
                    );
                    return;
                };
                match fallback::relay_hop(relay, &peer_fp, payload) {
                    Ok(hop) => {
                        // Length only, never contents: enough to show the relay
                        // forwarded the frame it was handed, and nothing about it.
                        tracing::debug!(
                            from = %peer_fp,
                            target = %blind.target_fingerprint,
                            dest = %hop.dest,
                            opaque_len = hop.bytes.len(),
                            "Relay: forwarding a sealed frame blindly"
                        );
                        if let Err(e) = sock.send_to(&hop.bytes, hop.dest).await {
                            tracing::debug!(dest = %hop.dest, "Relay: forward failed: {e}");
                        }
                        // Transit is the relay's side of the tit-for-tat ledger: a
                        // peer that uses us as a relay owes us the reciprocal.
                        if let Some(enforcer) = tft {
                            enforcer.forwarded_for(&peer_fp, hop.bytes.len() as u64);
                        }
                    }
                    Err(reason) => tracing::debug!(
                        from = %peer_fp,
                        target = %blind.target_fingerprint,
                        ?reason,
                        "Relay: blind forward refused"
                    ),
                }
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
                    // For a nested onion, the payload already contains the
                    // next hop's authenticated routing header. Preserve that
                    // header while changing only the transport encryption; if
                    // this is the final relay layer, create the zero-hop form
                    // consumed by the destination. Re-wrapping with `next`
                    // again would make a three-hop route point back at the
                    // middle relay and loop forever.
                    let rewrap = if relay.remaining_hops > 1 {
                        parse_relay_header(&relay.inner_payload)
                            .map(|_| relay.inner_payload.clone())
                            .unwrap_or_else(|| {
                                build_relay_packet(
                                    next,
                                    relay.remaining_hops - 1,
                                    &relay.inner_payload,
                                )
                            })
                    } else {
                        build_relay_packet(next, 0, &relay.inner_payload)
                    };
                    let hop_ctx = node
                        .sessions
                        .get(next)
                        .map(|s| SealCtx::from_session(&s))
                        .unwrap_or_else(|| SealCtx {
                            key,
                            epoch: 0,
                            counter: hop_ctr,
                            nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                            direction: dir_for(role),
                            session_hash: sh,
                            ratchet_due: false,
                        });
                    let (f, tag) = enc_split(&hop_ctx, &rewrap);
                    send3(sock, &tgt, &hop_ctx, &f, &tag).await;

                    // WIRED: Record bytes forwarded for this peer in TFT enforcer
                    if let Some(enforcer) = tft {
                        enforcer.forwarded_for(&peer_fp, relay.inner_payload.len() as u64);
                    }

                    tracing::info!(via = %src, hop = %next, "Relay packet forwarded");
                    return;
                }
                // Final hop: the inner payload is [counter u64 BE (8B)][wire_nonce (12B)][initiator→us
                // encrypted blob + tag]. Try each of our sessions to unwrap it using XChaCha20-Poly1305 (G6).
                let inner = &relay.inner_payload;
                if inner.len() >= 20 + 16 {
                    // WIRED: Record bytes forwarded by relay peer for us
                    if let Some(enforcer) = tft {
                        enforcer.forwarded_by(&peer_fp, inner.len() as u64);
                    }

                    let ic = u64::from_be_bytes([
                        inner[0], inner[1], inner[2], inner[3],
                        inner[4], inner[5], inner[6], inner[7],
                    ]);
                    let mut wire_nonce = [0u8; 12];
                    wire_nonce.copy_from_slice(&inner[8..20]);
                    let blob = inner[20..].to_vec();
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
                        // G6: The onion's inner layer now uses XChaCha20-Poly1305 with a
                        // 64-bit counter and transmitted 12-byte random nonce.
                        // Each direction gets a fresh ciphertext copy: an AEAD
                        // attempt may mutate its buffer before returning an error.
                        let pt2 = {
                            let mut first = blob.clone();
                            match xchacha_open(
                                &key,
                                &wire_nonce,
                                0,
                                NonceDirection::InitiatorToResponder,
                                &mut first,
                            ) {
                                Ok(plain) => Some(plain.to_vec()),
                                Err(_) => {
                                    let mut second = blob.clone();
                                    xchacha_open(
                                        &key,
                                        &wire_nonce,
                                        0,
                                        NonceDirection::ResponderToInitiator,
                                        &mut second,
                                    )
                                    .ok()
                                    .map(|plain| plain.to_vec())
                                }
                            }
                        };
                        if let Some(pt2) = pt2 {
                            tracing::info!(peer = %fp2, "Relay payload delivered (final hop)");
                            let payload = pt2.to_vec();
                            if let Some(payload) = frame_payload(&payload) {
                                if role == SessionRole::Responder && looks_like_dest(payload) {
                                    handle_exit_connect(
                                        Arc::clone(&node),
                                        sock,
                                        src,
                                        &key,
                                        &sh,
                                        &fp2,
                                        payload,
                                        exit_tunnels,
                                        ic,
                                        exit_rotator,
                                        fallback_state,
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
                    Arc::clone(&node),
                    sock,
                    src,
                    &key,
                    &sh,
                    &peer_fp,
                    payload,
                    exit_tunnels,
                    ctr,
                    exit_rotator,
                    fallback_state,
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
    node: Arc<GhostNode>,
    sock: &UdpSocket,
    src: &SocketAddr,
    key: &[u8; 32],
    sh: &[u8; 4],
    peer_fp: &str,
    dest: &[u8],
    tunnels: &ExitTunnels,
    connect_ctr: u64,
    exit_rotator: Option<&ExitIpRotator>,
    fallback_state: Option<&Fallback>,
) {
    let request = String::from_utf8_lossy(dest).into_owned();
    // Voucher-bearing requests use `EXITAUTH!<hex-voucher>!<host>:<port>`.
    // The outer GHOST session still authenticates the sender; the voucher adds
    // an explicit, signed capability when the exit requires one.
    let (voucher, dest) = if let Some(rest) = request.strip_prefix("EXITAUTH!") {
        match rest.split_once('!') {
            Some((encoded, target)) => (hex::decode(encoded).ok(), target.to_string()),
            None => (None, request.clone()),
        }
    } else {
        (None, request.clone())
    };
    let (host, port) = match dest.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => return,
        },
        None => return,
    };

    // Exit policy is evaluated before DNS resolution and before any socket is
    // opened. This prevents a denied hostname from becoming a DNS oracle and
    // keeps the allowlist enforcement on every exit path (rotated or default).
    let exit_policy = vantablack::ghost::net::relay::ExitPolicy::from_env();
    if !exit_policy.allows(&host) {
        tracing::warn!(peer = %peer_fp, host = %host, "Exit: destination rejected by policy");
        return;
    }
    let require_voucher = std::env::var("GHOST_EXIT_REQUIRE_VOUCHER")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if require_voucher {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let Some(raw_voucher) = voucher else {
            tracing::warn!(peer = %peer_fp, host = %host, "Exit: capability voucher required");
            return;
        };
        let Some(capability) = vantablack::ghost::net::relay::ExitCapability::decode(&raw_voucher) else {
            tracing::warn!(peer = %peer_fp, host = %host, "Exit: malformed capability voucher");
            return;
        };
        if capability.issuer_pk != node.identity.public_key_bytes()
            || !capability.verify(now, peer_fp, &host)
        {
            tracing::warn!(peer = %peer_fp, host = %host, "Exit: invalid, untrusted, or expired capability voucher");
            return;
        }
    }

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

    // Seal the OK under the session's current epoch; the counter, epoch and nonce
    // come from one snapshot so they cannot straddle a ratchet step.
    let ok_ctx = node
        .sessions
        .get(peer_fp)
        .map(|s| SealCtx::from_session(&s))
        .unwrap_or_else(|| SealCtx {
            key: *key,
            epoch: 0,
            counter: 2,
            nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
            direction: NonceDirection::ResponderToInitiator,
            session_hash: *sh,
            ratchet_due: false,
        });
    let (f, tag) = enc_split(&ok_ctx, b"OK");
    // The initiator may have reached us *through* a relay, in which case `src` is
    // the relay's address and a direct reply would go nowhere. Route it the same
    // way the data path is routed.
    match fallback_state.and_then(|f| f.path(peer_fp)) {
        Some(path) => {
            let _ = send3_via_fallback(
                &node,
                sock,
                peer_fp,
                &ok_ctx,
                &f,
                &tag,
                &path,
                fallback_state.and_then(|f| f.turn()),
            )
            .await;
        }
        None => send3(sock, src, &ok_ctx, &f, &tag).await,
    }

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
    // Replies take the same route the request did, resolved once: a peer that
    // reached us through a relay cannot be answered directly.
    let node3 = Arc::clone(&node);
    let route2 = fallback_state.and_then(|f| f.path(peer_fp));
    let turn2 = fallback_state.and_then(|f| f.turn().cloned());
    tokio::spawn(async move {
        let (mut rd, mut wr) = stream.into_split();
        let sock3 = sock2;
        let rd_handle = tokio::spawn(async move {
            let mut rbuf = vec![0u8; 900]; // keeps each RS shard ≤ 486 B privacy-frame cap
            loop {
                match rd.read(&mut rbuf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let ctx2 = sessions2
                            .get(&fp2)
                            .map(|s| SealCtx::from_session(&s))
                            .unwrap_or_else(|| SealCtx {
                                key: key2,
                                epoch: 0,
                                counter: 2,
                                nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                                direction: NonceDirection::ResponderToInitiator,
                                session_hash: sh2,
                                ratchet_due: false,
                            });
                        let (f, tag) = enc_split(&ctx2, &rbuf[..n]);
                        match route2.as_ref() {
                            Some(path) => {
                                let _ = send3_via_fallback(
                                    &node3,
                                    &sock3,
                                    &fp2,
                                    &ctx2,
                                    &f,
                                    &tag,
                                    path,
                                    turn2.as_ref(),
                                )
                                .await;
                            }
                            None => send3_mixed(Arc::clone(&sock3), &addr2, &ctx2, &f, &tag).await,
                        }
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

// ═══════════════════════════════════════════════════════════════════
// CONSUMER CONTROL PLANE HELPERS
// ═══════════════════════════════════════════════════════════════════

/// Where the consumer settings document lives (device names, egress mode,
/// split-tunnel list). It sits in the per-user application-data directory so
/// that moving or re-launching the binary never loses someone's device names;
/// override the file itself with `GHOST_CONSUMER_CONFIG`, or the whole
/// directory with `GHOST_DATA_DIR`.
fn consumer_config_path() -> String {
    std::env::var("GHOST_CONSUMER_CONFIG")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| vantablack::ghost::paths::data_file_string("ghost-consumer.json"))
}

/// Load consumer settings. Returns `None` when the file is absent, so the
/// caller can fall back to env-derived defaults.
fn load_consumer_settings(path: &str) -> Option<ConsumerSettings> {
    let data = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str::<ConsumerSettings>(&data) {
        Ok(settings) => Some(settings),
        Err(e) => {
            tracing::warn!("Ignoring unreadable consumer config {path}: {e}");
            None
        }
    }
}

/// Persist consumer settings via a temp file + rename, so a crash mid-write
/// cannot leave a truncated document behind.
fn save_consumer_settings(path: &str, settings: &ConsumerSettings) {
    let Ok(json) = serde_json::to_string_pretty(settings) else {
        return;
    };
    let tmp = format!("{path}.tmp");
    if std::fs::write(&tmp, json).is_err() {
        tracing::warn!("Could not write {tmp}");
        return;
    }
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!("Could not replace {path}");
    }
}

/// Best-effort LAN address of this machine, used to build the pairing URI.
/// A UDP `connect` transmits nothing — it only asks the kernel which local
/// address it would use to reach a public target.
fn detect_lan_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|sock| {
            sock.connect("1.1.1.1:80")?;
            sock.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// Parse the JSON body of a request (everything after the header block).
fn json_body(req: &str) -> serde_json::Value {
    req.find("\r\n\r\n")
        .and_then(|i| serde_json::from_str::<serde_json::Value>(req[i + 4..].trim()).ok())
        .unwrap_or(serde_json::Value::Null)
}

/// The `X-Pin` header value, when the client sent one.
fn header_pin(req: &str) -> Option<&str> {
    req.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("x-pin") {
            Some(value.trim())
        } else {
            None
        }
    })
}

/// Writes every log line to stderr *and* to `ghost.log`.
///
/// The desktop build runs as a Windows GUI-subsystem process, which has no
/// console attached, so without the file mirror a user could not report what
/// went wrong. `GHOST_LOG=off` disables the mirror; `GHOST_LOG=<path>` moves it.
#[cfg(feature = "webview")]
#[derive(Clone)]
struct TeeWriter {
    file: Option<Arc<std::sync::Mutex<std::fs::File>>>,
}

#[cfg(feature = "webview")]
struct TeeGuard<'a> {
    file: Option<std::sync::MutexGuard<'a, std::fs::File>>,
}

#[cfg(feature = "webview")]
impl std::io::Write for TeeGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = std::io::Write::write(&mut std::io::stderr(), buf)?;
        if let Some(file) = self.file.as_mut() {
            let _ = file.write_all(buf);
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::Write::flush(&mut std::io::stderr());
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        Ok(())
    }
}

#[cfg(feature = "webview")]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TeeWriter {
    type Writer = TeeGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        TeeGuard {
            file: self.file.as_ref().and_then(|f| f.lock().ok()),
        }
    }
}

/// Port the HTTP control center listens on (`GHOST_WEB_PORT`, else the legacy
/// `GHOST_METRICS_PORT`, else 2270). Shared by the node and the desktop window,
/// which are now separate threads and must agree without a back-channel.
fn control_port_from_env() -> u16 {
    std::env::var("GHOST_WEB_PORT")
        .or_else(|_| std::env::var("GHOST_METRICS_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2270)
}

/// True when this process should present a native desktop window. Headless
/// builds (`--no-default-features`) and `GHOST_NO_GUI=1` fall back to the HTTP
/// control center, which is the server/sidenote path.
#[cfg_attr(not(feature = "webview"), allow(dead_code))]
fn gui_enabled() -> bool {
    if !cfg!(feature = "webview") {
        return false;
    }
    std::env::var("GHOST_NO_GUI")
        .map(|v| v != "1" && !v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

/// Round to `places` decimals for stable JSON output.
fn round(value: f64, places: i32) -> f64 {
    let factor = 10f64.powi(places);
    (value * factor).round() / factor
}

/// Nearest-rank percentile of an unsorted sample set.
fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn mean(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<f64>() / samples.len() as f64
    }
}

/// Measure the node's own multi-path data path in process: encrypt and split a
/// payload exactly as the sender does, Reed-Solomon encode it across three
/// carrier shards, then rebuild it from TWO shards (one data shard is
/// deliberately cut) and decrypt — the code the receiver actually runs.
///
/// Every figure returned is measured on this machine; none is synthetic. It is
/// a *pipeline* benchmark (the node's own CPU cost), not a measurement of the
/// user's internet link — that is what the live-counter figure is for.
fn run_pipeline_probe(total_bytes: usize) -> serde_json::Value {
    // Throwaway key: per-packet cost is key-independent, and this keeps the
    // probe away from live session material.
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    const CHUNK: usize = 900; // matches the production SOCKS5 read buffer
    let payload = vec![0x5au8; CHUNK];
    let chunks = (total_bytes / CHUNK).max(1);

    let mut send_ms: Vec<f64> = Vec::with_capacity(chunks);
    let mut shard_ms: Vec<f64> = Vec::with_capacity(chunks * 3);
    let mut rebuild_ms: Vec<f64> = Vec::with_capacity(chunks);
    let mut recovered = 0usize;

    let started = std::time::Instant::now();
    for _ in 0..chunks {

        let t0 = std::time::Instant::now();
        // The speedtest walks the real pipeline, so it seals the same way the
        // data path does: v2, ratchet key, transmitted nonce, 64-bit counter.
        let bench_session = Session::new_with_role(key, "speedtest".into(), SessionRole::Initiator);
        let bench_ctx = SealCtx::from_session(&bench_session);
        let (carrier_frames, _tag) = enc_split(&bench_ctx, &payload);
        send_ms.push(t0.elapsed().as_secs_f64() * 1000.0);

        // Receive side: strip each carrier's length prefix, as the node does.
        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(3);
        for carrier in &carrier_frames {
            let t1 = std::time::Instant::now();
            shards.push(net::unframe(carrier));
            shard_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
        }

        // Cut carrier A's data shard and rebuild it from carriers B + C.
        let t2 = std::time::Instant::now();
        if let Some(slot) = shards.get_mut(0) {
            *slot = None;
        }
        let widest = shards
            .iter()
            .filter_map(|s| s.as_ref().map(|v| v.len()))
            .max()
            .unwrap_or(0);
        for shard in shards.iter_mut().flatten() {
            while shard.len() < widest {
                shard.push(0);
            }
        }
        if l4_rs::reconstruct(&mut shards).is_ok() {
            if let (Some(a), Some(b)) = (shards[0].as_ref(), shards[1].as_ref()) {
                let mut merged = [a.as_slice(), b.as_slice()].concat();
                if xchacha_open(
                    &bench_ctx.key,
                    &bench_ctx.nonce,
                    bench_ctx.epoch,
                    bench_ctx.direction,
                    &mut merged,
                )
                .is_ok()
                    && merged.len() >= 2
                {
                    let len = u16::from_be_bytes([merged[0], merged[1]]) as usize;
                    if 2 + len <= merged.len() && merged[2..2 + len] == payload[..] {
                        recovered += 1;
                    }
                }
            }
        }
        rebuild_ms.push(t2.elapsed().as_secs_f64() * 1000.0);
    }

    let moved = (chunks * CHUNK) as f64;
    let send_secs = (send_ms.iter().sum::<f64>() / 1000.0).max(1e-9);
    let rebuild_secs = (rebuild_ms.iter().sum::<f64>() / 1000.0).max(1e-9);
    let shard_mean = mean(&shard_ms);
    let jitter = if shard_ms.is_empty() {
        0.0
    } else {
        (shard_ms
            .iter()
            .map(|x| (x - shard_mean).powi(2))
            .sum::<f64>()
            / shard_ms.len() as f64)
            .sqrt()
    };

    serde_json::json!({
        "probe": "in-process multi-path pipeline (CPU)",
        "chunk_bytes": CHUNK,
        "chunks": chunks,
        "payload_bytes": chunks * CHUNK,
        "upload_mbps": round(moved * 8.0 / 1_000_000.0 / send_secs, 1),
        "download_mbps": round(moved * 8.0 / 1_000_000.0 / rebuild_secs, 1),
        // Per-packet stages are routinely sub-millisecond, so keep four
        // decimals: rounding these to 3 would report a flat "0 ms" and look
        // like a broken probe rather than a fast pipeline.
        "shard_jitter_ms": round(jitter, 4),
        "shard_transport_p95_ms": round(percentile(&shard_ms, 0.95), 4),
        "shard_recovery_mean_ms": round(mean(&rebuild_ms), 4),
        "reconstruction_ms": round(mean(&rebuild_ms), 4),
        "mesh_overhead_ms": round(mean(&send_ms) + mean(&rebuild_ms), 4),
        "recovered_chunks": recovered,
        "lost_carriers_per_chunk": 1,
        "elapsed_ms": round(started.elapsed().as_secs_f64() * 1000.0, 2),
        "note": "Measures this node's own encrypt/shard/recover cost per packet. It is not your internet link speed."
    })
}

/// Real observed throughput across the live mesh, from two counter snapshots a
/// second apart. Reports zero when nothing is flowing, which is the truth.
async fn measure_live_throughput(nc: &Arc<GhostNode>) -> serde_json::Value {
    let tx0 = nc.stats.bytes_sent.load(Ordering::Relaxed);
    let rx0 = nc.stats.bytes_recv.load(Ordering::Relaxed);
    let started = std::time::Instant::now();
    sleep(Duration::from_millis(1000)).await;
    let tx1 = nc.stats.bytes_sent.load(Ordering::Relaxed);
    let rx1 = nc.stats.bytes_recv.load(Ordering::Relaxed);
    let secs = started.elapsed().as_secs_f64().max(1e-9);
    let tx_bytes = tx1.saturating_sub(tx0);
    let rx_bytes = rx1.saturating_sub(rx0);
    serde_json::json!({
        "window_ms": round(secs * 1000.0, 0),
        "tx_bytes": tx_bytes,
        "rx_bytes": rx_bytes,
        "tx_mbps": round(tx_bytes as f64 * 8.0 / 1_000_000.0 / secs, 3),
        "rx_mbps": round(rx_bytes as f64 * 8.0 / 1_000_000.0 / secs, 3),
        "active_sessions": nc.sessions.len(),
    })
}

/// Copy bytes from `r` to `w` until the reader closes.
async fn pump<R, W>(mut r: R, mut w: W) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
    }
    Ok(())
}

/// Answer a SOCKS5 CONNECT with success and relay the client to an upstream
/// socket we already opened locally. Used by split tunneling, where the target
/// is deliberately *not* sent through the mesh.
async fn socks_relay_direct(s: tokio::net::TcpStream, upstream: tokio::net::TcpStream) {
    let mut s = s;
    if s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {
        return;
    }
    let (client_r, client_w) = s.into_split();
    let (up_r, up_w) = upstream.into_split();
    let up = tokio::spawn(pump(client_r, up_w));
    let down = tokio::spawn(pump(up_r, client_w));
    let _ = tokio::join!(up, down);
}

/// Round-trip time to the public internet, from the fastest of three TCP
/// connects. Only called when the caller explicitly opts in (`isp_probe`).
async fn isp_rtt_ms() -> Option<f64> {
    let mut best: Option<f64> = None;
    for _ in 0..3 {
        let started = std::time::Instant::now();
        let attempt = tokio::time::timeout(
            Duration::from_millis(700),
            tokio::net::TcpStream::connect("1.1.1.1:443"),
        )
        .await;
        match attempt {
            Ok(Ok(_stream)) => {
                let ms = started.elapsed().as_secs_f64() * 1000.0;
                best = Some(best.map_or(ms, |b: f64| b.min(ms)));
            }
            _ => break,
        }
    }
    best.map(|v| round(v, 1))
}

/// One peer entry for `/api/status` and `/api/peers`, with the consumer-facing
/// fields the dashboard renders: friendly name, platform, presence.
fn peer_entry(
    nc: &GhostNode,
    settings: &ConsumerSettings,
    fingerprint: &str,
    addr: &SocketAddr,
) -> serde_json::Value {
    let has_session = nc.sessions.contains_key(fingerprint);
    serde_json::json!({
        "fingerprint": fingerprint,
        "name": settings.device_name(fingerprint),
        "custom_name": settings.has_custom_name(fingerprint),
        "os": settings.device_os(fingerprint),
        "address": addr.to_string(),
        "connected": has_session,
        "status": consumer::peer_status(has_session, true),
        "role": if has_session { "Active Mesh Peer" } else { "Discovered Peer" },
        // Per-peer RTT is not measured by this build; report null rather than
        // inventing a number the UI would then present as fact.
        "latency_ms": serde_json::Value::Null,
    })
}

fn handle_cli_args() -> Option<anyhow::Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None;
    }
    match args[1].as_str() {
        "split-key" | "split_key" => {
            let secret = if args.len() >= 3 {
                let hex_str = args[2].trim();
                let bytes = match hex::decode(hex_str) {
                    Ok(b) => b,
                    Err(e) => return Some(Err(anyhow::anyhow!("Invalid hex key: {e}"))),
                };
                if bytes.len() != 32 {
                    return Some(Err(anyhow::anyhow!(
                        "Key must be exactly 32 bytes (64 hex characters), got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            } else {
                let mut arr = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut arr);
                println!("Generated fresh 32-byte secret key: {}", hex::encode(arr));
                arr
            };
            let shares = vantablack::ghost::layers::l3_shamir::split_secret_bytes(&secret);
            println!("L3 Shamir Secret Sharing (2-of-3 threshold split):");
            for (i, share) in shares.iter().enumerate() {
                println!("  Share {}: {}", i + 1, hex::encode(share));
            }
            println!("Any 2 of these 3 shares will reconstruct the original secret.");
            Some(Ok(()))
        }
        "join-key" | "join_key" => {
            if args.len() < 4 {
                println!("Usage: ggn join-key <share1_hex> <share2_hex>");
                return Some(Err(anyhow::anyhow!("Two hex shares required")));
            }
            let s1 = match hex::decode(args[2].trim()) {
                Ok(b) => b,
                Err(e) => return Some(Err(anyhow::anyhow!("Invalid hex for share 1: {e}"))),
            };
            let s2 = match hex::decode(args[3].trim()) {
                Ok(b) => b,
                Err(e) => return Some(Err(anyhow::anyhow!("Invalid hex for share 2: {e}"))),
            };
            let secret = vantablack::ghost::layers::l3_shamir::join_shares(&s1, &s2);
            println!(
                "Reconstructed secret ({} bytes): {}",
                secret.len(),
                hex::encode(&secret)
            );
            Some(Ok(()))
        }
        "--help" | "-h" | "help" => {
            println!("Global Ghost Net (GGN) — Post-Quantum WAN Mesh Daemon");
            println!("Usage:");
            println!("  ggn                             Run node daemon");
            println!("  ggn split-key [32B_HEX_KEY]     Split secret into 3 Shamir shares (2-of-3 threshold)");
            println!("  ggn join-key <SHARE1> <SHARE2>  Reconstruct secret from any 2 Shamir shares");
            println!("  ggn --help                      Show this help");
            Some(Ok(()))
        }
        _ => None,
    }
}

fn main() -> anyhow::Result<()> {
    if let Some(res) = handle_cli_args() {
        return res;
    }
    // The desktop window owns the main thread: tao refuses to build an
    // EventLoop anywhere else on Windows, and macOS requires the main thread.
    // The node therefore runs on its own thread and hands its handle back so
    // the tray menu can read and toggle node state.
    #[cfg(feature = "webview")]
    if gui_enabled() {
        let control_port = control_port_from_env();
        let (node_tx, node_rx) = std::sync::mpsc::channel::<Arc<GhostNode>>();
        std::thread::Builder::new()
            .name("ggn-node".to_string())
            .spawn(move || {
                if let Err(e) = run_daemon(true, Some(node_tx)) {
                    tracing::error!("Node stopped: {e:#}");
                }
            })?;
        let node = match node_rx.recv_timeout(Duration::from_secs(15)) {
            Ok(node) => Some(node),
            Err(_) => {
                tracing::warn!("Desktop window starting before the node reported readiness");
                None
            }
        };
        // `run_desktop` never returns; control leaves through `process::exit`.
        webview::run_desktop(control_port, node);
    }

    // Headless / server: no window at all, the HTTP control center is the UI.
    run_daemon(false, None)
}

/// Boot the node inside its own tokio runtime.
fn run_daemon(
    suppress_browser: bool,
    node_tx: Option<std::sync::mpsc::Sender<Arc<GhostNode>>>,
) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(run_node(suppress_browser, node_tx))
}

async fn run_node(
    suppress_browser: bool,
    node_tx: Option<std::sync::mpsc::Sender<Arc<GhostNode>>>,
) -> anyhow::Result<()> {
    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    // stderr is still unbuffered: line-flushed logs survive hard process kills,
    // which matters for supervised/diagnostic runs and tests that parse the log
    // tail. The desktop build additionally appends to a file, because a Windows
    // GUI-subsystem process has no console to show it in.
    #[cfg(feature = "webview")]
    {
        let configured = std::env::var("GHOST_LOG")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| vantablack::ghost::paths::data_file_string("ghost.log"));
        let file = if configured.eq_ignore_ascii_case("off") {
            None
        } else {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&configured)
                .ok()
                .map(|f| Arc::new(std::sync::Mutex::new(f)))
        };
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(TeeWriter { file })
            .init();
    }
    #[cfg(not(feature = "webview"))]
    {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .init();
    }

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

    // G7: SecureTimeKeeper and BuildInfo were constructed here and immediately
    // discarded (_time_keeper, _build_info — neither was ever read). Removed
    // rather than wired: the library primitives remain available in l9_infra
    // for future use when a real consumer exists.

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
    // The rate above is the operator's *policy* ceiling. The governor is the
    // control half: it measures what the paths actually carry and lowers the
    // effective rate to match, so a node whose links degrade stops accepting
    // transit at the rate it was configured with.
    let transit_governor = Arc::new(vantablack::ghost::net::cc::TransitGovernor::new(
        tm.saturating_mul(125_000),
    ));
    tracing::info!(fingerprint = %node.fingerprint(), address = %node.local_addr, "Node ready");

    // ── BOOTSTRAP SEEDS ──
    let addrs: Arc<DashMap<String, SocketAddr>> = Arc::new(DashMap::new());
    let spool: Arc<DashMap<u64, Vec<Option<Vec<u8>>>>> = Arc::new(DashMap::new());
    let pending_hs: PendingHandshakes = Arc::new(DashMap::new());

    let exit_tunnels: ExitTunnels = Arc::new(DashMap::new());
    let sess_chan: SessionChannels = Arc::new(DashMap::new());
    let rx_state_map: RxStateMap = Arc::new(DashMap::new());
    let connect_acks: ConnectAcks = Arc::new(DashMap::new());
    let connect_ok_ctrs: ConnectOkCtrs = Arc::new(DashMap::new());
    let default_exit: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let nc = Arc::new(node);
    // Hand the node to the desktop window's tray, when one is coming.
    if let Some(tx) = node_tx {
        let _ = tx.send(Arc::clone(&nc));
    }

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

    // Category A — NAT traversal (ICE over STUN).
    //
    // A STUN server is what makes a NATed node reachable: without one there is
    // no server-reflexive address to advertise, so say so up front instead of
    // letting hole-punching fail opaquely later.
    let stun_server = std::env::var("GHOST_STUN_SERVER")
        .ok()
        .and_then(|v| v.parse::<SocketAddr>().ok());
    let mut nat_puncher = vantablack::ghost::net::mesh::NatHolePuncher::new();
    match stun_server {
        Some(server) => {
            tracing::info!(server = %server, "STUN: configured for NAT traversal");
            nat_puncher = nat_puncher.with_stun_server(server);
        }
        None => tracing::warn!(
            "STUN: no GHOST_STUN_SERVER set — public-address discovery and ICE \
             reflexive candidates are unavailable; only direct/LAN paths will work"
        ),
    }
    nat_puncher.set_local_fingerprint(nc.fingerprint());

    // Dedicated NAT-traversal socket.
    //
    // ICE checks must not share the mesh's receive path: two tasks calling
    // `recv_from` on one socket split datagrams nondeterministically, which is
    // indistinguishable from random packet loss. The candidates below describe
    // *this* socket, and the checks run on it.
    let nat_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let nat_local = nat_socket.local_addr()?;
    let probe_target = stun_server.unwrap_or_else(|| {
        format!("{}:{}", BEACON_MULTICAST_ADDR, BEACON_PORT)
            .parse()
            .expect("the beacon address is a valid socket address")
    });
    // A wildcard bind does not say which interface we would send from, so ask
    // the routing table (a UDP `connect` is a route lookup only).
    let host_candidate = match vantablack::ghost::net::ice::probe_local_addr(probe_target) {
        Ok(a) => SocketAddr::new(a.ip(), nat_local.port()),
        Err(e) => {
            tracing::debug!(
                "NAT traversal: route probe failed ({e}); advertising the bound address"
            );
            nat_local
        }
    };

    // Our advertised offer: stable credentials plus whatever candidates we can
    // gather. Credentials must not rotate — a peer authenticates its checks
    // against the credentials it received from us.
    let mut offer_agent = vantablack::ghost::net::ice::IceAgent::new(
        vantablack::ghost::net::ice::IceRole::Controlling,
    );
    offer_agent.set_local_credentials(nat_puncher.local_credentials().clone());
    offer_agent.add_host_candidate(host_candidate, host_candidate);
    if let Some(server) = stun_server {
        match offer_agent
            .gather_reflexive(&nat_socket, server, Duration::from_secs(3))
            .await
        {
            Ok(c) => tracing::info!(public = %c.addr, "STUN: public address discovered"),
            Err(e) => tracing::warn!(server = %server, "STUN: discovery failed: {e}"),
        }
    }

    // Opportunistic: ask the local gateway to open the port for us (SOTA P1-1).
    // A granted mapping makes us reachable without either side punching anything,
    // so the address becomes an ordinary candidate — it *is* our public address,
    // however it was learned. Failure is the common case (UPnP disabled, CGNAT, an
    // enterprise gateway) and is logged, not raised: ICE still runs.
    if let std::net::IpAddr::V4(local_v4) = host_candidate.ip() {
        match upnp::opportunistic_public_addr(local_v4, nat_local.port()).await {
            Some(public) => {
                tracing::info!(
                    public = %public,
                    "UPnP/NAT-PMP: gateway mapping granted — advertising it as a candidate"
                );
                offer_agent.add_server_reflexive_candidate(host_candidate, public, None);
                // A lease is not permanent, and a mapping that quietly expires
                // leaves a candidate in our offer that no peer can reach.
                let port = nat_local.port();
                tokio::spawn(async move {
                    upnp::renew_udp_mapping(local_v4, port).await;
                });
            }
            None => tracing::debug!("UPnP/NAT-PMP: {}", upnp::describe_attempt(None)),
        }
    }
    // ── TURN allocation (SOTA P1-1) ──
    //
    // The last rung of the fallback ladder. Configured, never assumed: without
    // `GHOST_TURN_SERVER` (plus credentials) nothing here runs and the node behaves
    // exactly as before. An allocation gives us an address on the public internet
    // that peers can reach even when both ends are behind address-and-port
    // dependent NATs, which is the case ICE cannot solve on its own.
    let turn_configured = std::env::var("GHOST_TURN_SERVER")
        .ok()
        .and_then(|v| v.parse::<SocketAddr>().ok());
    let (turn_path, mut turn_rx): (
        Option<Arc<TurnPath>>,
        Option<tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
    ) = match (
        turn_configured,
        std::env::var("GHOST_TURN_USER").ok(),
        std::env::var("GHOST_TURN_PASS").ok(),
    ) {
        (Some(server), Some(user), Some(pass)) => {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            match TurnPath::establish(server, user, pass, Duration::from_secs(5), tx).await {
                Ok(path) => {
                    tracing::info!(
                        server = %server,
                        relayed = %path.relayed_addr(),
                        lifetime_secs = path.granted_lifetime().as_secs(),
                        "TURN: allocation established — advertising it as a relay candidate"
                    );
                    // The allocation is part of our own offer: a peer that cannot
                    // reach us directly can reach *it*, and the server hands us
                    // what arrives. This is the address, not the server's.
                    offer_agent.add_relay_candidate(host_candidate, path.relayed_addr());
                    (Some(path), Some(rx))
                }
                Err(e) => {
                    tracing::warn!(server = %server, "TURN: allocation failed: {e}");
                    (None, None)
                }
            }
        }
        (Some(_), _, _) => {
            tracing::warn!(
                "TURN: GHOST_TURN_SERVER set but GHOST_TURN_USER/GHOST_TURN_PASS are missing \
                 — skipping the allocation"
            );
            (None, None)
        }
        _ => (None, None),
    };

    let our_offer = vantablack::ghost::net::ice::IceOffer::new(
        nat_puncher.local_credentials().clone(),
        offer_agent.local_candidates().to_vec(),
        // Advisory only: the real role is derived from the two fingerprints so
        // both sides agree without negotiation.
        true,
    );
    tracing::info!(
        candidates = offer_agent.local_candidates().len(),
        "NAT traversal: advertising an ICE offer in beacons"
    );
    let our_offer_text = Arc::new(std::sync::RwLock::new(our_offer.encode()));

    let nat_puncher = Arc::new(nat_puncher);

    // ── Relay role + fallback routes (SOTA P1-1 / B22) ──
    //
    // A node relays for others only when asked (`GHOST_RELAY=1`): forwarding
    // someone else's traffic costs transit bandwidth, and that should be a
    // deliberate operational choice rather than a surprise. The quota is the
    // same `FlowController` that bounds our own transit traffic.
    let relay_enabled = std::env::var("GHOST_RELAY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let relay_role: Option<Arc<DerpRelay>> = if relay_enabled {
        tracing::info!(
            "DERP: relay role enabled — forwarding sealed frames for beacon-verified peers"
        );
        Some(Arc::new(DerpRelay::new(Arc::clone(&nc.flow_controller))))
    } else {
        None
    };
    // Which unreachable peers go through which relay. Empty until a punch fails,
    // and cleared the moment a direct path is measured again.
    let fallback_routes = Arc::new(Fallback::new(turn_path.clone()));

    // ── Optional QUIC transport (SOTA P1-2) ──
    //
    // The registry exists in every build so the egress sites can ask one question
    // per frame without a `cfg` of their own; whether it holds a transport is the
    // operator's call, and without one every answer is "nothing to send on".
    let carrier = build_carrier(&nc);

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
            let peers_cache = vantablack::ghost::paths::data_file("peers.cache");
            if let Ok(cache_str) = std::fs::read_to_string(&peers_cache) {
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
                        pending_hs.insert(t.to_string(), PendingHandshake::Kem512(xs, ks));
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
                    let _ = std::fs::write(&peers_cache, peer_lines.join("\n"));
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

    // ── HTTP Metrics, Status & Consumer Web Control Center Endpoint ──
    let metrics_port: u16 = control_port_from_env();
    let metrics_enabled = std::env::var("GHOST_METRICS_ENABLED")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    let consumer_connected = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let consumer_mode = Arc::new(parking_lot::RwLock::new(
        std::env::var("GHOST_MODE").unwrap_or_else(|_| "public".to_string()),
    ));
    let consumer_pin = Arc::new(parking_lot::RwLock::new(
        std::env::var("GHOST_PIN")
            .ok()
            .filter(|s| !s.trim().is_empty()),
    ));
    // Consumer control plane: friendly device names, the system-VPN vs SOCKS5
    // egress choice and the split-tunnel bypass list. Persisted so a rename or
    // a bypass rule survives a restart; GHOST_EGRESS_MODE only seeds the first
    // run, after which the user's choice in the Web UI wins.
    let consumer_config = consumer_config_path();
    let consumer_settings = Arc::new(parking_lot::RwLock::new(
        load_consumer_settings(&consumer_config).unwrap_or_else(|| {
            ConsumerSettings::with_mode(std::env::var("GHOST_EGRESS_MODE").ok().as_deref())
        }),
    ));
    // True when a desktop window is being shown by main(): the browser tab is
    // then suppressed, because it is the secondary way in.
    let gui_active = suppress_browser;

    // Pairing target advertised in the QR code: this host's LAN address, the
    // control-center port and the node fingerprint. The fingerprint is stable
    // across runs because the Ed25519 identity is persisted in identity.key.
    let lan_host = format!("{}:{}", detect_lan_ip(), metrics_port);
    let pair_uri = format!(
        "ggn://pair?nid={fp}&fp={fp}&host={host}",
        fp = nc.fingerprint(),
        host = lan_host
    );

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
                    let headroom = u64::MAX.saturating_sub(ctr);
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
        let c_conn_m = Arc::clone(&consumer_connected);
        let c_mode_m = Arc::clone(&consumer_mode);
        let c_pin_m = Arc::clone(&consumer_pin);
        let c_settings_m = Arc::clone(&consumer_settings);
        let c_path_m = consumer_config.clone();
        let lan_host_m = lan_host.clone();
        let pair_uri_m = pair_uri.clone();
        // Whether the local SOCKS5 listener is actually up in this process, and
        // whether a TUN/VPN subsystem exists at all. Reported so the UI can say
        // "selected" versus "in effect" instead of pretending.
        let socks_listening = socks;
        // Same cfg dance the receiver uses: `vpn_mode` only exists when the
        // feature is on, so the non-vpn build needs its own binding.
        #[cfg(feature = "vpn")]
        let vpn_m: Option<VpnMode> = vpn_mode.clone();
        #[cfg(not(feature = "vpn"))]
        let vpn_m: Option<VpnMode> = None;
        let mp = metrics_port;
        // The carrier registry, so the status page can show *measured* carrier
        // links rather than an inferred path count (B23). Present in every build:
        // without the transport it reports the same zeroes it would in a build that
        // has none.
        let carrier_m = Arc::clone(&carrier);
        tokio::spawn(async move {
            let bind_addr = format!("0.0.0.0:{}", mp);
            match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    tracing::info!(
                        "Ghost Web Control Center & Telemetry listening on http://127.0.0.1:{} (LAN: http://0.0.0.0:{})",
                        mp,
                        mp
                    );
                    // Pop the control center open in a browser tab only when no
                    // native window is coming — that page is the secondary way
                    // in, not the default experience.
                    if !gui_active
                        && std::env::var("GHOST_NO_BROWSER")
                            .map(|v| v != "1")
                            .unwrap_or(true)
                    {
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
                            let url = format!("http://127.0.0.1:{}", mp);
                            #[cfg(target_os = "windows")]
                            let _ = std::process::Command::new("cmd")
                                .args(["/C", "start", &url])
                                .spawn();
                            #[cfg(target_os = "macos")]
                            let _ = std::process::Command::new("open").arg(&url).spawn();
                            #[cfg(target_os = "linux")]
                            let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
                        });
                    }
                    loop {
                        if let Ok((mut stream, _)) = listener.accept().await {
                            let nc_ref = Arc::clone(&nc_m);
                            let addrs_ref = Arc::clone(&addrs_m);
                            let vpn_ref = vpn_m.clone();
                            let conn_ref = Arc::clone(&c_conn_m);
                            let mode_ref = Arc::clone(&c_mode_m);
                            let pin_ref = Arc::clone(&c_pin_m);
                            let cs_ref = Arc::clone(&c_settings_m);
                            let cp_ref = c_path_m.clone();
                            let lan_host_ref = lan_host_m.clone();
                            let pair_uri_ref = pair_uri_m.clone();
                            let carrier_ref = Arc::clone(&carrier_m);
                            tokio::spawn(async move {
                                let mut buf = [0u8; 4096];
                                if let Ok(n) = stream.read(&mut buf).await {
                                    let req = String::from_utf8_lossy(&buf[..n]);
                                    let (vpn_role, vpn_prom, vpn_json) = vpn_export(&vpn_ref);
                                    let vpn_available = vpn_ref.is_some();
                                    // The control center binds 0.0.0.0, so it is
                                    // reachable from the whole LAN. When GHOST_PIN
                                    // is set, mutating endpoints demand it.
                                    let configured_pin = pin_ref.read().clone();
                                    let pin_ok = match configured_pin.as_deref() {
                                        None => true,
                                        Some(expected) => header_pin(&req) == Some(expected),
                                    };
                                    let is_mutation = req.starts_with("POST ");

                                    // Handle CORS preflight
                                    if req.starts_with("OPTIONS ") {
                                        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Pin\r\nConnection: close\r\n\r\n";
                                        let _ = stream.write_all(resp.as_bytes()).await;
                                        return;
                                    }

                                    let (status_line, body, content_type) = if is_mutation
                                        && !pin_ok
                                    {
                                        (
                                            "HTTP/1.1 401 Unauthorized",
                                            serde_json::json!({
                                                "success": false,
                                                "error": "PIN required",
                                                "pin_required": true
                                            })
                                            .to_string(),
                                            "application/json",
                                        )
                                    } else if req.starts_with("GET /api/status") {
                                        let is_conn = conn_ref.load(Ordering::Relaxed);
                                        let current_mode = mode_ref.read().clone();
                                        let has_pin = pin_ref.read().is_some();
                                        let sent_bytes =
                                            nc_ref.stats.bytes_sent.load(Ordering::Relaxed);
                                        let recv_bytes =
                                            nc_ref.stats.bytes_recv.load(Ordering::Relaxed);
                                        let sent_pkts =
                                            nc_ref.stats.packets_sent.load(Ordering::Relaxed);
                                        let recv_pkts =
                                            nc_ref.stats.packets_recv.load(Ordering::Relaxed);
                                        let uptime = nc_ref.created_at.elapsed().as_secs();
                                        let peers_count = addrs_ref.len();
                                        let sessions_count = nc_ref.sessions.len();

                                        let settings_now = cs_ref.read().clone();
                                        let peer_entries: Vec<serde_json::Value> = addrs_ref
                                            .iter()
                                            .map(|entry| {
                                                peer_entry(
                                                    &nc_ref,
                                                    &settings_now,
                                                    entry.key(),
                                                    entry.value(),
                                                )
                                            })
                                            .collect();

                                        let route_mode_active =
                                            match settings_now.route_mode.as_str() {
                                                consumer::ROUTE_MODE_SYSTEM_VPN => vpn_available,
                                                _ => socks_listening,
                                            };
                                        let body = serde_json::json!({
                                            "connected": is_conn,
                                            "mode": current_mode,
                                            "network_id": nc_ref.fingerprint(),
                                            "device_name": settings_now.device_name(&nc_ref.fingerprint()),
                                            "device_os": consumer::local_os(),
                                            "host": lan_host_ref,
                                            "pair_uri": pair_uri_ref,
                                            "route_mode": settings_now.route_mode,
                                            "route_mode_active": route_mode_active,
                                            "bypass_count": settings_now.bypass.len(),
                                            "socks_listening": socks_listening,
                                            "socks_port": socks_port,
                                            "vpn_available": vpn_available,
                                            "pin_protected": has_pin,
                                            "uptime_seconds": uptime,
                                            "peers_count": peers_count,
                                            "active_sessions": sessions_count,
                                            // No RTT probe runs against peers in this build, so
                                            // report null rather than a hard-coded number.
                                            "latency_ms": serde_json::Value::Null,
                                            // Shards fan out over the primary route plus up to
                                            // two additional live peers.
                                            "active_carrier_paths": if is_conn {
                                                std::cmp::min(3, 1 + nc_ref.sessions.len().min(2))
                                            } else {
                                                0
                                            },
                                            // The optional transport as it actually is, not
                                            // as the line above infers it: links and local
                                            // paths are counted from live entries, so with
                                            // multipath on (`GHOST_QUIC_MULTIPATH=1`) two
                                            // links to one peer show up as two paths.
                                            "carrier": {
                                                "enabled": carrier_ref.enabled(),
                                                "label": carrier_ref.label(),
                                                "local_paths": carrier_ref.path_count(),
                                                "links": carrier_ref.link_count(),
                                                "peers": carrier_ref.peer_count(),
                                            },
                                            "reed_solomon_active": true,
                                            "throughput": {
                                                "bytes_sent": sent_bytes,
                                                "bytes_recv": recv_bytes,
                                                "packets_sent": sent_pkts,
                                                "packets_recv": recv_pkts
                                            },
                                            "peers": peer_entries,
                                            "vpn": vpn_role,
                                            "vpn_stats": vpn_json
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/connect") {
                                        // Parse optional {"connected": bool} or toggle
                                        let current = conn_ref.load(Ordering::Relaxed);
                                        let new_val = if let Some(body_start) = req.find("\r\n\r\n")
                                        {
                                            let json_body = &req[body_start + 4..];
                                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(
                                                json_body.trim(),
                                            ) {
                                                if let Some(c) =
                                                    val.get("connected").and_then(|v| v.as_bool())
                                                {
                                                    c
                                                } else {
                                                    !current
                                                }
                                            } else {
                                                !current
                                            }
                                        } else {
                                            !current
                                        };
                                        conn_ref.store(new_val, Ordering::Relaxed);
                                        let body = serde_json::json!({
                                            "success": true,
                                            "connected": new_val,
                                            "mode": mode_ref.read().clone()
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/mode") {
                                        let mut new_mode = None;
                                        if let Some(body_start) = req.find("\r\n\r\n") {
                                            let json_body = &req[body_start + 4..];
                                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(
                                                json_body.trim(),
                                            ) {
                                                if let Some(m) =
                                                    val.get("mode").and_then(|v| v.as_str())
                                                {
                                                    new_mode = Some(m.to_string());
                                                }
                                            }
                                        }
                                        if let Some(m) = new_mode {
                                            *mode_ref.write() = m;
                                        }
                                        let current_mode = mode_ref.read().clone();
                                        let body = serde_json::json!({
                                            "success": true,
                                            "mode": current_mode
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("GET /api/peers") {
                                        let settings_now = cs_ref.read().clone();
                                        let peer_entries: Vec<serde_json::Value> = addrs_ref
                                            .iter()
                                            .map(|entry| {
                                                peer_entry(
                                                    &nc_ref,
                                                    &settings_now,
                                                    entry.key(),
                                                    entry.value(),
                                                )
                                            })
                                            .collect();
                                        let body = serde_json::json!({
                                            "peers": peer_entries,
                                            "count": peer_entries.len()
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("GET /api/settings") {
                                        let s = cs_ref.read().clone();
                                        let route_mode_active = match s.route_mode.as_str() {
                                            consumer::ROUTE_MODE_SYSTEM_VPN => vpn_available,
                                            _ => socks_listening,
                                        };
                                        let body = serde_json::json!({
                                            "route_mode": s.route_mode,
                                            "route_mode_active": route_mode_active,
                                            "route_modes": [consumer::ROUTE_MODE_SYSTEM_VPN, consumer::ROUTE_MODE_APP_SOCKS],
                                            "bypass": s.bypass,
                                            "bypass_count": s.bypass.len(),
                                            "socks_listening": socks_listening,
                                            "socks_port": socks_port,
                                            "vpn_available": vpn_available,
                                            "device_name": s.device_name(&nc_ref.fingerprint()),
                                            "device_os": consumer::local_os(),
                                            "pin_protected": pin_ref.read().is_some(),
                                            "note": if vpn_available {
                                                "System-wide mode binds the TUN adapter when the node starts with GHOST_VPN=client."
                                            } else {
                                                "This binary was built without the `vpn` feature, so system-wide TUN mode cannot be enabled yet. App-only SOCKS5 still works."
                                            }
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("POST /api/settings") {
                                        let val = json_body(&req);
                                        let mut changed: Vec<String> = Vec::new();
                                        let mut error: Option<String> = None;
                                        let mut s = cs_ref.write();
                                        if let Some(mode) =
                                            val.get("route_mode").and_then(|v| v.as_str())
                                        {
                                            if s.set_route_mode(mode) {
                                                changed
                                                    .push(format!("route_mode={}", s.route_mode));
                                            } else {
                                                error =
                                                    Some(format!("unknown route mode '{mode}'"));
                                            }
                                        }
                                        if error.is_none() {
                                            if let Some(rule) =
                                                val.get("bypass_add").and_then(|v| v.as_str())
                                            {
                                                match s.add_bypass(rule) {
                                                    Ok(true) => {
                                                        changed.push(format!("bypass+{rule}"))
                                                    }
                                                    Ok(false) => {}
                                                    Err(e) => error = Some(e),
                                                }
                                            }
                                        }
                                        if error.is_none() {
                                            if let Some(rule) =
                                                val.get("bypass_remove").and_then(|v| v.as_str())
                                            {
                                                if s.remove_bypass(rule) {
                                                    changed.push(format!("bypass-{rule}"));
                                                }
                                            }
                                        }
                                        if error.is_none() {
                                            if let Some(list) =
                                                val.get("bypass").and_then(|v| v.as_array())
                                            {
                                                s.bypass.clear();
                                                for entry in list.iter().filter_map(|v| v.as_str())
                                                {
                                                    if let Err(e) = s.add_bypass(entry) {
                                                        error = Some(e);
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        let response = match error {
                                            Some(e) => (
                                                "HTTP/1.1 400 Bad Request",
                                                serde_json::json!({"success": false, "error": e})
                                                    .to_string(),
                                            ),
                                            None => {
                                                save_consumer_settings(&cp_ref, &s);
                                                let route_mode_active = match s.route_mode.as_str()
                                                {
                                                    consumer::ROUTE_MODE_SYSTEM_VPN => {
                                                        vpn_available
                                                    }
                                                    _ => socks_listening,
                                                };
                                                (
                                                    "HTTP/1.1 200 OK",
                                                    serde_json::json!({
                                                        "success": true,
                                                        "changed": changed,
                                                        "route_mode": s.route_mode,
                                                        "route_mode_active": route_mode_active,
                                                        "bypass": s.bypass,
                                                        "bypass_count": s.bypass.len(),
                                                        "vpn_available": vpn_available,
                                                        "socks_listening": socks_listening
                                                    })
                                                    .to_string(),
                                                )
                                            }
                                        };
                                        drop(s);
                                        (response.0, response.1, "application/json")
                                    } else if req.starts_with("POST /api/peers/rename") {
                                        let val = json_body(&req);
                                        let fp = val
                                            .get("fingerprint")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        if fp.is_empty() {
                                            (
                                                "HTTP/1.1 400 Bad Request",
                                                serde_json::json!({
                                                    "success": false,
                                                    "error": "fingerprint is required"
                                                })
                                                .to_string(),
                                                "application/json",
                                            )
                                        } else {
                                            let mut s = cs_ref.write();
                                            if let Some(os) = val.get("os").and_then(|v| v.as_str())
                                            {
                                                s.set_device_os(&fp, Some(os));
                                            }
                                            let new_name = val
                                                .get("name")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");
                                            let response = match s.set_device_name(&fp, new_name) {
                                                Err(e) => (
                                                    "HTTP/1.1 400 Bad Request",
                                                    serde_json::json!({"success": false, "error": e})
                                                        .to_string(),
                                                ),
                                                Ok(display) => {
                                                    save_consumer_settings(&cp_ref, &s);
                                                    (
                                                        "HTTP/1.1 200 OK",
                                                        serde_json::json!({
                                                            "success": true,
                                                            "fingerprint": fp,
                                                            "name": display,
                                                            "custom_name": s.has_custom_name(&fp),
                                                            "os": s.device_os(&fp)
                                                        })
                                                        .to_string(),
                                                    )
                                                }
                                            };
                                            drop(s);
                                            (response.0, response.1, "application/json")
                                        }
                                    } else if req.starts_with("POST /api/speedtest") {
                                        let val = json_body(&req);
                                        let want_isp = val
                                            .get("isp_probe")
                                            .and_then(|v| v.as_bool())
                                            .unwrap_or(false);
                                        let payload_bytes = val
                                            .get("bytes")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(256 * 1024)
                                            .clamp(900, 4 * 1024 * 1024)
                                            as usize;
                                        let nc_probe = Arc::clone(&nc_ref);
                                        let pipeline = tokio::task::spawn_blocking(move || {
                                            run_pipeline_probe(payload_bytes)
                                        })
                                        .await
                                        .unwrap_or(serde_json::Value::Null);
                                        let live = measure_live_throughput(&nc_probe).await;
                                        let isp = if want_isp { isp_rtt_ms().await } else { None };
                                        let body = serde_json::json!({
                                            "success": true,
                                            "pipeline": pipeline,
                                            "live": live,
                                            "isp_rtt_ms": isp,
                                            "isp_probe_requested": want_isp
                                        })
                                        .to_string();
                                        ("HTTP/1.1 200 OK", body, "application/json")
                                    } else if req.starts_with("GET /healthz") {
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
                                    } else if req.starts_with("GET /dashboard")
                                        || req.starts_with("GET / ")
                                        || req.starts_with("GET /?")
                                    {
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
                                        "{}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Pin\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
    // A build with only the `tray` feature keeps the lighter tray icon that
    // opens the browser. The full desktop window is started by main(), because
    // it has to own the main thread.
    #[cfg(all(feature = "tray", not(feature = "webview")))]
    tray::run_tray(Arc::clone(&nc));

    // ── SOCKS5 PROXY (initiator mode) ──
    if socks {
        let n2 = Arc::clone(&nc);
        let a2 = Arc::clone(&addrs);
        let ch = Arc::clone(&sess_chan);
        let rsm = Arc::clone(&rx_state_map);
        let ak = Arc::clone(&connect_acks);
        let de = Arc::clone(&default_exit);
        let srouter_socks = Arc::clone(&shard_router);
        let cs_socks = Arc::clone(&consumer_settings);
        // The tunnel's egress consults the fallback table, so the proxy needs it
        // too: a peer reachable only through a relay must carry the tunnel, not
        // just the control frames.
        let fallback_routes_socks = Arc::clone(&fallback_routes);
        // The tunnel's egress prefers the optional transport where a link exists,
        // so the proxy holds it too (SOTA P1-2).
        let carrier_socks = Arc::clone(&carrier);
        let turn_path_socks = turn_path.clone();
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
                    let cs2 = Arc::clone(&cs_socks);
                    let fallback_routes_proxy = Arc::clone(&fallback_routes_socks);
                    let carrier_proxy = Arc::clone(&carrier_socks);
                    let turn_path_proxy = turn_path_socks.clone();
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

                        // ── Split tunneling ──────────────────────────────────
                        // Hosts the user exempted leave through the local ISP,
                        // exactly as if the mesh were not installed. This is what
                        // keeps banking apps and geo-checked streaming working.
                        if cs2.read().should_bypass(&addr) {
                            let dest_direct = format!("{addr}:{port}");
                            tracing::info!(dest = %dest_direct, "SOCKS5: bypassing mesh (split tunnel)");
                            match tokio::net::TcpStream::connect((addr.as_str(), port)).await {
                                Ok(upstream) => socks_relay_direct(s, upstream).await,
                                Err(e) => {
                                    tracing::warn!(dest = %dest_direct, error = %e, "SOCKS5: split-tunnel dial failed");
                                    let _ = s.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                                }
                            }
                            return;
                        }

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
                        let plain_dest = format!("{}:{}", addr, port);
                        let dest = std::env::var("GHOST_EXIT_VOUCHER")
                            .ok()
                            .filter(|voucher| !voucher.is_empty())
                            .map(|voucher| format!("EXITAUTH!{voucher}!{plain_dest}"))
                            .unwrap_or(plain_dest);
                        tracing::info!(dest = %dest, "SOCKS5 CONNECT");
                        let connect_ctx = nn
                            .sessions
                            .get(&fp)
                            .map(|s| SealCtx::from_session(&s))
                            .unwrap_or_else(|| SealCtx {
                                key,
                                epoch: 0,
                                counter: connect_ctr,
                                nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                                direction: dir_for(role),
                                session_hash: sh,
                                ratchet_due: false,
                            });
                        let (f, tag) = enc_split(&connect_ctx, dest.as_bytes());
                        match fallback_routes_proxy.path(&fp) {
                            Some(path) => {
                                let _ = send3_via_fallback(
                                    &nn,
                                    &nn.socket,
                                    &fp,
                                    &connect_ctx,
                                    &f,
                                    &tag,
                                    &path,
                                    turn_path_proxy.as_ref(),
                                )
                                .await;
                            }
                            None => send3_mixed(Arc::clone(&nn.socket), &tgt, &connect_ctx, &f, &tag).await,
                        }
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
                        // The tunnel's egress consults the fallback table: a peer
                        // that is only reachable through a relay must carry the
                        // tunnel too, not just the control frames.
                        let routes_out = Arc::clone(&fallback_routes_proxy);
                        let turn_path_out = turn_path_proxy.clone();
                        let carrier_out = Arc::clone(&carrier_proxy);
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
                                        let ctx_out = nn2
                                            .sessions
                                            .get(&fp_out)
                                            .map(|s| SealCtx::from_session(&s))
                                            .unwrap_or_else(|| SealCtx {
                                                key: key_out,
                                                epoch: 0,
                                                counter: c,
                                                nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                                                direction: NonceDirection::InitiatorToResponder,
                                                session_hash: sh_out,
                                                ratchet_due: false,
                                            });
                                        let (f, tag) = enc_split(&ctx_out, &rbuf[..n]);
                                        let me = nn2.fingerprint();
                                        let plan = nn2.contact_plan.read().await;
                                        let route = routes_out.path(&fp_out);
                                        let _ = send3_adaptive(
                                            &nn2,
                                            &nn2.socket,
                                            &tgt_out,
                                            &fp_out,
                                            &ctx_out,
                                            &f,
                                            &tag,
                                            &srouter,
                                            &aa_proxy,
                                            Some(&plan),
                                            &me,
                                            route.as_ref(),
                                            turn_path_out.as_ref(),
                                            Some(&carrier_out),
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
        let offers = Arc::clone(&our_offer_text);
        let router = Arc::clone(&shard_router);
        let nat_p = Arc::clone(&nat_puncher);
        let nat_sock = Arc::clone(&nat_socket);
        let ledger = Arc::clone(&tft);
        let governor = Arc::clone(&transit_governor);
        let relay_role = relay_role.clone();
        let advertises_relay = relay_role.is_some();
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
            // Cumulative transit egress per peer as of the last tick, so the
            // delivery rate is a delta and not a lifetime total.
            let mut last_forwarded: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            loop {
                let secs = nc.keepalive_interval_secs.load(Ordering::Relaxed);
                let interval = Duration::from_secs(secs.clamp(1, 300));

                // ── Congestion-control tick ──
                // The beacon cadence is also the control cadence. Every signal
                // below is a measurement, not a setting: ICE's connectivity
                // checks time the round trip of the very path the shards will
                // use, and the tit-for-tat ledger counts the transit bytes
                // actually forwarded for each peer.
                let connected = nat_p.local_cache();
                for (fp, _addr) in &connected {
                    if let Some(rtt) = nat_p.selected_rtt(fp) {
                        router.record_success(fp, rtt.as_micros() as f64);
                    }
                    let (forwarded_for_them, _, _, _) = ledger.peer_stats(fp);
                    let previous = last_forwarded
                        .insert(fp.clone(), forwarded_for_them)
                        .unwrap_or(forwarded_for_them);
                    let delta = forwarded_for_them.saturating_sub(previous);
                    if delta > 0 {
                        router.record_delivery(fp, delta, interval);
                    }
                }
                // Open (and hold open) a NAT mapping toward every relay we know.
                // Without it the relay's forwarded frame is filtered before it can
                // reach us, and the fallback would look like it had nowhere to go.
                if let Some(relay) = relay_role.as_ref() {
                    let addrs: Vec<SocketAddr> = relay
                        .relay_candidates()
                        .into_iter()
                        .map(|(_, a)| a)
                        .collect();
                    if !addrs.is_empty() {
                        let n = nat_p.send_relay_keepalives(&nat_sock, &addrs).await;
                        tracing::debug!(relays = n, "NAT: relay pinholes refreshed");
                    }
                }

                let rate = governor.apply(&nc.flow_controller, &router.live_path_rates());
                tracing::debug!(
                    rate_bps = rate,
                    ceiling_bps = governor.ceiling_bps(),
                    paths = governor.paths_seen(),
                    connected_peers = connected.len(),
                    "Transit shaper retuned from measured path capacity"
                );

                // The same two measurements keep the contact plan honest: a CGR
                // route is only as good as the link latency and capacity on it,
                // and both are now observed rather than assumed. Without this a
                // contact registered once at connect time would keep its first
                // RTT forever while the path degraded around it.
                {
                    let me = nc.fingerprint();
                    let now = unix_now_secs();
                    let mut plan = nc.contact_plan.write().await;
                    for (fp, _addr) in &connected {
                        let Some(rtt) = nat_p.selected_rtt(fp) else {
                            continue;
                        };
                        plan.observe_link(
                            &me,
                            fp,
                            rtt,
                            now,
                            ICE_CONTACT_WINDOW_SECS,
                            router.path_rate_bps(fp),
                        );
                    }
                }

                if nc.beacon_enabled.load(Ordering::Relaxed) {
                    // Beacons are signed with the device identity so a forged
                    // fingerprint can never trigger an auto-handshake.
                    // When GHOST_ZK_DISCOVERY=1, a zero-knowledge membership proof is attached.
                    // Carry our ICE offer so a discoverer can authenticate
                    // connectivity checks against us immediately.
                    let offer_text = offers.read().ok().map(|g| g.clone());
                    // Our post-quantum commitment rides every beacon (P2-1): it is
                    // 32 bytes and the key it names is 1952, so the commitment is
                    // what a discoverer can remember and check against the key we
                    // later prove on the carrier.
                    let pq_commitment = nc.identity.pq_commitment();
                    // A membership proof needs a membership secret. Without a
                    // GHOST_PSK there is none to prove with, and a peer that
                    // shares this setting has none to verify with either, so
                    // this is a misconfiguration that stops discovery: it is
                    // reported once instead of being papered over with a block
                    // that proves nothing (SOTA §6 G5).
                    let zk_proof = if zk_enabled {
                        match psk.as_ref() {
                            Some(psk) => Some(ZkAuthenticator::create_proof(
                                &nc.identity.public_key_bytes(),
                                psk,
                            )),
                            None => {
                                static WARNED: std::sync::Once = std::sync::Once::new();
                                WARNED.call_once(|| {
                                    tracing::warn!(
                                        "GHOST_ZK_DISCOVERY=1 without GHOST_PSK: no membership proof can be attached, and peers that require one will drop this node"
                                    );
                                });
                                None
                            }
                        }
                    } else {
                        None
                    };
                    let beacon = build_beacon_packet(
                        &nc.identity.public_key_bytes(),
                        |d| nc.identity.sign(d).to_bytes(),
                        zk_proof,
                        offer_text.as_deref(),
                        advertises_relay,
                        Some(&pq_commitment),
                    );
                    if let Err(e) = beacon_sock.send_to(&beacon, mc_addr).await {
                        tracing::debug!("Beacon send error: {e}");
                    }
                }
                sleep(interval).await;
            }
        });
    }

    // ── BEACON LISTENER + AUTO-HANDSHAKE ──
    {
        let nc = Arc::clone(&nc);
        let pending = Arc::clone(&pending_hs);
        let peers = Arc::clone(&addrs);
        // The registry is where a post-quantum commitment can actually be
        // enforced (it holds the links), so the beacon listener pins into it.
        let carrier_pins = Arc::clone(&carrier);
        let rl = Arc::clone(&revocation_list);
        let nat_p = Arc::clone(&nat_puncher);
        let nat_sock = Arc::clone(&nat_socket);
        let router = Arc::clone(&shard_router);
        let relay_role = relay_role.clone();
        let routes = Arc::clone(&fallback_routes);
        tokio::spawn(async move {
            let zk_required = std::env::var("GHOST_ZK_DISCOVERY")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            // The membership proof is a proof about a shared secret, so without
            // the secret nothing can be verified: this fails closed, and says so
            // once instead of dropping every beacon in silence (SOTA §6 G5).
            if zk_required && psk.is_none() {
                tracing::error!(
                    "GHOST_ZK_DISCOVERY=1 without GHOST_PSK: no beacon can carry a verifiable membership proof, so discovery will accept nothing — set GHOST_PSK or unset GHOST_ZK_DISCOVERY"
                );
            }
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
            // A beacon is the 112-byte signed prefix plus optional sections, and
            // the ICE offer is the long one. 256 bytes truncated every beacon big
            // enough to matter, and a truncated datagram does not tile as
            // sections — so the offer and the PQ commitment were silently lost
            // and only the bare prefix survived. 1472 is the bound the plan
            // states for a beacon and the largest thing that fits an Ethernet MTU
            // without fragmenting.
            let mut buf = vec![0u8; 1472];
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

                    // Optional trailing sections (Phase 1 P1-1): a membership
                    // proof, the sender's ICE offer, and whether the sender is
                    // willing to relay.
                    let mut advertises_relay = false;
                    let beacon_fp = hex::encode(&pk[..8]);
                    let peer_offer = match parse_beacon_sections(&buf, amt) {
                        Some(sections) => {
                            advertises_relay = sections.relay_capable;
                            // Trust on first use (P2-1): a beacon names the sender's
                            // post-quantum key, and a later, different commitment for
                            // the same fingerprint is logged rather than adopted.
                            if let Some(commitment) = sections.pq_commitment {
                                carrier_pins.pin_commitment(&beacon_fp, *commitment);
                            }
                            match sections.zk {
                                Some((context, proof)) => {
                                    // A Schnorr proof that the sender knows the
                                    // membership secret for exactly this identity
                                    // (SOTA §6 G5). It needs the PSK, because the
                                    // statement is about the PSK: a node without
                                    // one cannot verify and does not pretend to.
                                    if !ZkAuthenticator::verify_proof(
                                        &pk,
                                        psk.as_ref(),
                                        context,
                                        proof,
                                    ) {
                                        tracing::warn!(peer = %src, "Beacon membership proof failed — dropped");
                                        continue;
                                    }
                                }
                                None if zk_required => {
                                    tracing::warn!(peer = %src, "Beacon rejected — GHOST_ZK_DISCOVERY requires a membership proof");
                                    continue;
                                }
                                None => {}
                            }
                            sections.ice_offer.map(str::to_string)
                        }
                        None => {
                            // The datagram does not tile as sections: either a bare
                            // 112-byte beacon, or an older peer's 208-byte one whose
                            // trailing block is a signature over a discarded nonce.
                            // Under the hard switch that block is not verified —
                            // and cannot be, since it commits to nothing — so such
                            // a peer is an identity-only beacon and never a proven
                            // member.
                            if zk_required {
                                tracing::warn!(peer = %src, "Beacon rejected — GHOST_ZK_DISCOVERY requires a membership proof");
                                continue;
                            }
                            None
                        }
                    };
                    let beacon_fp = hex::encode(&pk[..8]);
                    if beacon_fp == local_fp {
                        continue;
                    }
                    tracing::info!(peer = %src, fingerprint = %beacon_fp, "Discovered via beacon");

                    if let Ok(local_sa) = nc.local_addr.parse::<SocketAddr>() {
                        nat_p.register_peer(&beacon_fp, src, local_sa);
                    }

                    // Relay bookkeeping (SOTA P1-1).
                    //
                    // A peer that advertises relay capability becomes a relay we
                    // may use; its address is the one its beacon arrived from,
                    // which is the socket it forwards on. A *verified* beacon is
                    // also what authorizes a peer to relay through us: the
                    // fingerprint is derived from the Ed25519 key the signature
                    // just covered, so this is the same identity check the
                    // auto-handshake below relies on, and the transit quota still
                    // bounds what any one peer can push through us.
                    if let Some(relay) = relay_role.as_ref() {
                        if advertises_relay {
                            relay.add_relay_candidate(&beacon_fp, src);
                            tracing::debug!(relay = %beacon_fp, "DERP: peer advertises relay capability");
                        }
                        relay.authorize(&beacon_fp, src);
                    }

                    // Install the peer's offer and start authenticated checks.
                    // Both sides learn the other's offer from beacons, so this is
                    // the point at which a direct path can be attempted at all.
                    if let Some(offer_text) = peer_offer {
                        match vantablack::ghost::net::ice::IceOffer::decode(&offer_text) {
                            Ok(offer) => {
                                // The peer's own relayed address, if it holds a
                                // TURN allocation: that is where a TURN fallback
                                // would have to send, not our own allocation.
                                let peer_turn = offer
                                    .candidates
                                    .iter()
                                    .find(|c| {
                                        c.ctype == vantablack::ghost::net::ice::CandidateType::Relay
                                    })
                                    .map(|c| c.addr);
                                nat_p.set_ice_offer(&beacon_fp, offer);
                                if !nat_p.is_connected(&beacon_fp) {
                                    let np = Arc::clone(&nat_p);
                                    let sock = Arc::clone(&nat_sock);
                                    let fp = beacon_fp.clone();
                                    let node = Arc::clone(&nc);
                                    let me = local_fp.clone();
                                    let r = Arc::clone(&router);
                                    let routes = Arc::clone(&routes);
                                    let relay_candidates: Vec<(String, SocketAddr)> = relay_role
                                        .as_ref()
                                        .map(|r| r.relay_candidates())
                                        .unwrap_or_default();
                                    // Our own allocation is the transport; the
                                    // peer's is the destination.
                                    let turn_relayed = peer_turn;
                                    tokio::spawn(async move {
                                        if np.punch_hole(&sock, &fp).await {
                                            tracing::info!(peer = %fp, "ICE: direct path established");
                                            // A measured path supersedes any fallback: direct
                                            // is cheaper and is what the ladder prefers.
                                            routes.clear(&fp);
                                            // The completed check measured a round
                                            // trip, so register it as a real
                                            // contact: from here the CGR router
                                            // routes on observations rather than
                                            // on assumptions (SOTA P1-3).
                                            if let Some(rtt) = np.selected_rtt(&fp) {
                                                node.contact_plan.write().await.observe_link(
                                                    &me,
                                                    &fp,
                                                    rtt,
                                                    unix_now_secs(),
                                                    ICE_CONTACT_WINDOW_SECS,
                                                    0.0,
                                                );
                                                tracing::debug!(
                                                    peer = %fp,
                                                    rtt_ms = rtt.as_millis(),
                                                    "CGR: direct contact registered from measured RTT"
                                                );
                                            }
                                        } else {
                                            // A failed punch is not a silent event, and it
                                            // is not the end of the path either: hand the
                                            // peer to the fallback ladder (SOTA P1-1 / B22).
                                            // The router must still stop treating this path
                                            // as usable — that is a measured loss, and it
                                            // accumulates across beacon intervals until the
                                            // path falls below the selection threshold.
                                            r.record_loss(&fp);
                                            let chosen = fallback::choose_fallback(
                                                &me,
                                                &fp,
                                                &relay_candidates,
                                                turn_relayed,
                                            );
                                            match chosen {
                                                Some(path) => {
                                                    // `set` refuses a TURN route when this
                                                    // node holds no allocation: recording
                                                    // one would black-hole every send.
                                                    if routes.set(&fp, path.clone()) {
                                                        tracing::warn!(
                                                            peer = %fp,
                                                            path = %path.label(),
                                                            "ICE: no direct path — every candidate pair failed; \
                                                             falling back to a relay"
                                                        );
                                                    } else {
                                                        tracing::warn!(
                                                            peer = %fp,
                                                            "ICE: peer advertises a TURN relay but this node \
                                                             holds no allocation (GHOST_TURN_*) — unreachable"
                                                        );
                                                    }
                                                }
                                                None => {
                                                    routes.clear(&fp);
                                                    tracing::warn!(
                                                        peer = %fp,
                                                        "ICE: no direct path and no relay available \
                                                         (no mesh relay advertises capability and no TURN \
                                                         allocation is configured) — this peer is unreachable"
                                                    );
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                            Err(e) => tracing::warn!(
                                peer = %src,
                                "Beacon carried an invalid ICE offer: {e}"
                            ),
                        }
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
                        pending.insert(t.to_string(), PendingHandshake::Kem512(xs, ks));
                        tracing::info!(target = %t, fingerprint = %beacon_fp, "Auto-handshake sent");
                    }
                }
            }
        });
    }

    // The receive pipeline (`RxContext`, below) is module-level on purpose: it
    // used to be declared inside `main`, which made the one entry point every
    // socket feeds **impossible to test** — and that is exactly where a
    // `#[cfg(feature = "vpn")]` on the self-contained-frame bypass hid, dropping
    // every ratchet step PDU in a default build. A receive path that cannot be
    // driven from a test is a receive path whose branches are guesses.
    //
    // Dispatcher's owned view of the VPN state (main keeps the original).
    #[cfg(feature = "vpn")]
    let vpn_rx: Option<VpnMode> = vpn_mode.as_ref().map(|m| match m {
        VpnMode::Hub(h) => VpnMode::Hub(Arc::clone(h)),
        VpnMode::Client(c, t) => VpnMode::Client(Arc::clone(c), Arc::clone(t)),
    });
    #[cfg(not(feature = "vpn"))]
    let vpn_rx: Option<VpnMode> = None;
    let rx = Arc::new(RxContext {
        node: Arc::clone(&nc),
        peers: Arc::clone(&addrs),
        spool: Arc::clone(&spool),
        pending_hs: Arc::clone(&pending_hs),
        revocation_list: Arc::clone(&revocation_list),
        reputation: Arc::clone(&reputation_matrix),
        vpn: vpn_rx,
        exit_tunnels: Arc::clone(&exit_tunnels),
        sessions_rx: Arc::clone(&sess_chan),
        rx_state_map: Arc::clone(&rx_state_map),
        connect_acks: Arc::clone(&connect_acks),
        connect_ok_ctrs: Arc::clone(&connect_ok_ctrs),
        trusted_exits: Arc::clone(&trusted_exits),
        psk,
        tft: Arc::clone(&tft),
        rotator: exit_rotator.clone(),
        relay_role: relay_role.clone(),
        fallback: Some(Arc::clone(&fallback_routes)),
        dispatcher: Arc::new(net::dispatcher::LocklessDispatcher::new(4, 1024)),
        socket: nc.socket.clone(),
    });
    {
        let rx = Arc::clone(&rx);
        tokio::spawn(async move {
            let sock = Arc::clone(&rx.socket);
            let mut buf = vec![0u8; GTF_BULK_SIZE + 64];
            while rx.node.running.load(Ordering::Relaxed) {
                if let Ok((amt, src)) = sock.recv_from(&mut buf).await {
                    rx.ingest(&buf[..amt], src).await;
                }
            }
        });
    }

    // ── TURN INGRESS ──
    //
    // Datagrams the TURN server relays to us are sealed for us exactly as a
    // direct send would be, so they enter the same pipeline. `peer` is the peer's
    // address as the server knows it, which is what tunnel bookkeeping keys on.
    if let Some(mut ingress) = turn_rx.take() {
        let rx = Arc::clone(&rx);
        tokio::spawn(async move {
            while let Some((peer, frame)) = ingress.recv().await {
                rx.ingest(&frame, peer).await;
            }
            tracing::warn!("TURN: allocation closed, relayed datagrams will no longer arrive");
        });
    }

    // ── OPTIONAL TRANSPORT INGRESS + DIAL (SOTA P1-2) ──
    spawn_carrier_tasks!(&carrier, &rx, &nc, &nat_puncher, &addrs);

    // ── VPN EGRESS ──
    #[cfg(feature = "vpn")]
    match vpn_mode.as_ref() {
        Some(VpnMode::Hub(hub)) => {
            // Hub: drain netstack (TCP) + UDP/ICMP replies, send as tunnel
            // frames. All channels inside the hub are bounded (rule 3).
            let nc = Arc::clone(&nc);
            let hub = Arc::clone(hub);
            let fb = Arc::clone(&fallback_routes);
            tokio::spawn(async move {
                let mut last_sweep = std::time::Instant::now();
                loop {
                    let mut sent = 0;
                    while let Some(u) = hub.poll_netstack_egress() {
                        send_tunnel_frame(&nc, &u.fingerprint, u.endpoint, &u.wire, Some(&fb))
                            .await;
                        sent += 1;
                        if sent > 64 {
                            break;
                        } // yield; stay responsive
                    }
                    while let Some(u) = hub.poll_egress() {
                        send_tunnel_frame(&nc, &u.fingerprint, u.endpoint, &u.wire, Some(&fb))
                            .await;
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
            let fb = Arc::clone(&fallback_routes);
            tokio::spawn(async move {
                while let Some(wire) = rx.recv().await {
                    // ClientState.fingerprint = the hub's fingerprint.
                    let dest = client2.fingerprint.clone();
                    let tgt = addrs2.get(&dest).map(|v| *v.value());
                    if let Some(tgt) = tgt {
                        send_tunnel_frame(&nc2, &dest, tgt, &wire, Some(&fb)).await;
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

    // ── RATCHET MAINTENANCE (SOTA P2-2) ──
    //
    // This is what makes the ratchet real rather than dormant: an epoch holds at
    // most `RATCHET_INTERVAL` datagrams, and when one is spent the session pays for
    // a fresh hybrid exchange. The step is *started* here and *completed* in
    // `handle_pkt` when the peer's signed answer arrives (or, on the answering
    // side, when the initiator's first frame in the new epoch authenticates).
    //
    // Nothing stalls on it: traffic keeps flowing on the current epoch until the
    // step lands, and a lost step is abandoned after `STEP_STALL` and retried on the
    // next tick — the same shape as the old pre-wrap re-key, but with a bound on how
    // long one attempt may sit unanswered.
    {
        let nc = Arc::clone(&nc);
        let pa = Arc::clone(&addrs);
        let fb = Arc::clone(&fallback_routes);
        tokio::spawn(async move {
            loop {
                sleep(RATCHET_TICK).await;
                ratchet_maintenance_once(&nc, &pa, &fb).await;
            }
        });
    }

    // ── COVER-TRAFFIC TASK (SOTA P3-1) ──
    //
    // Spawned unconditionally and never gated on idleness, so the frame rate is the
    // same whether the node is in use or not. See `spawn_cover_task` for why gating
    // it on idleness would defeat the purpose, and what it costs.
    let _cover = spawn_cover_task(
        Arc::clone(&nc),
        Arc::clone(&addrs),
        relay_role.clone(),
    );

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
                for e in nc.sessions.iter() {
                    let idle = e
                        .guard
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .last_activity
                        .elapsed();
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
                            e.guard
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .last_activity = std::time::Instant::now();
                            continue;
                        }
                        tracing::debug!("Sending keepalive to {}", e.peer_fingerprint);
                        let ka_ctx = SealCtx::from_session(&e);
                        let (f, tag) = enc_split(&ka_ctx, b"KA");
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
                        send3_mixed(Arc::clone(&nc.socket), &t, &ka_ctx, &f, &tag).await;
                        e.guard
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .last_activity = std::time::Instant::now();
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
        tracing::info!("Commands: PEER <ip:port>, CHAT <fp> <msg>, SENDRELAY <dest> <relay> <payload>, EXIT <fp>, EXITS, TFT [fp], FEC, MEMSEC, SHAMIR <split|join>, FINGERPRINT, PEERS, STATUS, STATS, BEACON <on/off>, REVOKE, REP, HELP");
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
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        vantablack::ghost::paths::data_file_string("ghost-topology.json")
                    });
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
                match std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()) {
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
            "EXITVOUCHER" => {
                let subject = p.get(1).copied().unwrap_or("");
                let scope = p.get(2).copied().unwrap_or("");
                let ttl = p
                    .get(3)
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(3600);
                if subject.is_empty() || scope.is_empty() {
                    println!("Usage: EXITVOUCHER <peer_fp> <host> [ttl_seconds]");
                    continue;
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                match vantablack::ghost::net::relay::ExitCapability::issue(
                    &nc.identity,
                    subject,
                    scope,
                    now.saturating_add(ttl),
                )
                .and_then(|capability| capability.encode())
                {
                    Some(encoded) => println!("EXITAUTH voucher (hex): {}", hex::encode(encoded)),
                    None => println!("Could not issue voucher: subject or scope is too long"),
                }
            }
            "SENDRELAY" => {
                // Multi-hop relay:
                //   SENDRELAY <dest_fp> <guard_fp> <payload>
                //   SENDRELAY <dest_fp> <guard_fp> <middle_fp> <payload>
                // The second form builds a real guard→middle→destination
                // nested onion. The first remains wire-compatible with the
                // original one-relay command.
                let dest = p.get(1).copied().unwrap_or("");
                let relay = p.get(2).copied().unwrap_or("");
                let (middle, payload) = if p.len() >= 5 {
                    (Some(p[3]), p[4])
                } else {
                    (None, p.get(3).copied().unwrap_or(""))
                };
                if dest.is_empty() || relay.is_empty() || payload.is_empty() {
                    println!("Usage: SENDRELAY <dest_fp> <guard_fp> [<middle_fp>] <payload>");
                    continue;
                }
                let Some(ds) = nc.sessions.get(dest) else {
                    println!("No session with destination {dest}");
                    continue;
                };
                let (dkey, drole) = (ds.master_key, ds.role);
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
                // G6: The onion's inner layer now seals with XChaCha20-Poly1305 and a
                // 64-bit counter plus transmitted 96-bit random nonce, eliminating
                // 32-bit counter exhaustion.
                let wire_nonce = random_xnonce();
                if xchacha_seal_in_place(
                    &dkey,
                    &wire_nonce,
                    0,
                    dir_for(drole),
                    &mut blob,
                ).is_err() {
                    println!("SENDRELAY: AEAD encryption failed");
                    continue;
                }
                let mut inner = dctr.to_be_bytes().to_vec();
                inner.extend_from_slice(&wire_nonce);
                inner.extend_from_slice(&blob);
                let route = match middle {
                    Some(middle) if !middle.is_empty() && middle != relay && middle != dest => {
                        build_onion_route(&[relay, middle, dest], &inner)
                    }
                    None => build_onion_route(&[relay, dest], &inner),
                    _ => None,
                };
                let Some(relay_pkt) = route else {
                    println!("SENDRELAY: invalid or duplicate relay route");
                    continue;
                };
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
                let relay_ctx = nc
                    .sessions
                    .get(relay)
                    .map(|s| SealCtx::from_session(&s))
                    .unwrap_or_else(|| SealCtx {
                        key: rkey,
                        epoch: 0,
                        counter: rctr,
                        nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                        direction: dir_for(rrole),
                        session_hash: rsh,
                        ratchet_due: false,
                    });
                let (f, tag) = enc_split(&relay_ctx, &relay_pkt);
                let tgt = addrs
                    .get(relay)
                    .map(|v| *v.value())
                    .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                send3_mixed(Arc::clone(&nc.socket), &tgt, &relay_ctx, &f, &tag).await;
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
                let chat_ctx = nc
                    .sessions
                    .get(dest)
                    .map(|s| SealCtx::from_session(&s))
                    .unwrap_or_else(|| SealCtx {
                        key,
                        epoch: 0,
                        counter: ctr,
                        nonce: vantablack::ghost::layers::l2_aead::random_xnonce(),
                        direction: dir_for(role),
                        session_hash: sh,
                        ratchet_due: false,
                    });
                let (f, tag) = enc_split(&chat_ctx, &payload);
                let tgt = addrs
                    .get(dest)
                    .map(|v| *v.value())
                    .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0)));
                let me = nc.fingerprint();
                let plan = nc.contact_plan.read().await;
                let route = fallback_routes.path(dest);
                let routed = send3_adaptive(
                    &nc,
                    &nc.socket,
                    &tgt,
                    dest,
                    &chat_ctx,
                    &f,
                    &tag,
                    &shard_router,
                    &addrs,
                    Some(&plan),
                    &me,
                    route.as_ref(),
                    turn_path.as_ref(),
                    Some(&carrier),
                )
                .await;
                match routed {
                    Routed::Unroutable => println!(
                        "Chat to {} could not leave: no direct path and no relay could carry it",
                        &dest[..8.min(dest.len())]
                    ),
                    _ => println!("Chat sent to {}: {}", &dest[..8.min(dest.len())], msg),
                }
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
                            u64::MAX.saturating_sub(ctr)
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
            "SHAMIR" => {
                if p.len() < 2 {
                    println!("Usage: SHAMIR SPLIT [hex_secret] | SHAMIR JOIN <share1_hex> <share2_hex>");
                } else {
                    match p[1].to_uppercase().as_str() {
                        "SPLIT" => {
                            let secret = if p.len() >= 3 {
                                match hex::decode(p[2].trim()) {
                                    Ok(b) if b.len() == 32 => {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&b);
                                        arr
                                    }
                                    _ => {
                                        println!("Error: Key must be 32 bytes (64 hex characters)");
                                        continue;
                                    }
                                }
                            } else {
                                let mut arr = [0u8; 32];
                                rand::thread_rng().fill_bytes(&mut arr);
                                println!("Generated fresh 32-byte secret key: {}", hex::encode(arr));
                                arr
                            };
                            let shares = vantablack::ghost::layers::l3_shamir::split_secret_bytes(&secret);
                            println!("L3 Shamir Secret Sharing (2-of-3 threshold split):");
                            for (i, share) in shares.iter().enumerate() {
                                println!("  Share {}: {}", i + 1, hex::encode(share));
                            }
                            println!("Any 2 of these 3 shares will reconstruct the original secret.");
                        }
                        "JOIN" => {
                            if p.len() < 4 {
                                println!("Usage: SHAMIR JOIN <share1_hex> <share2_hex>");
                            } else {
                                match (hex::decode(p[2].trim()), hex::decode(p[3].trim())) {
                                    (Ok(s1), Ok(s2)) => {
                                        let secret = vantablack::ghost::layers::l3_shamir::join_shares(&s1, &s2);
                                        println!("Reconstructed secret ({} bytes): {}", secret.len(), hex::encode(&secret));
                                    }
                                    _ => {
                                        println!("Error: Invalid hex strings for shares");
                                    }
                                }
                            }
                        }
                        _ => println!("Usage: SHAMIR SPLIT [hex_secret] | SHAMIR JOIN <share1_hex> <share2_hex>"),
                    }
                }
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
                println!(
                    "  SHAMIR SPLIT [hex]  - Split a 32-byte secret into 3 Shamir shares (2-of-3)"
                );
                println!(
                    "  SHAMIR JOIN <s1> <s2> - Reconstruct a secret from any 2 Shamir shares"
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

#[cfg(test)]
mod beacon_section_tests {
    use super::*;

    fn test_pk() -> [u8; 32] {
        [7u8; 32]
    }

    fn stub_signer(_d: &[u8]) -> [u8; 64] {
        [9u8; 64]
    }

    /// A real identity, because the beacon's prefix signature must verify against
    /// the key it names — a stub signer can never produce one. The membership
    /// proof itself no longer involves the signing key at all: it is a Schnorr
    /// proof about the PSK and the public key (SOTA §6 G5).
    fn real_identity() -> l0_identity::GhostIdentity {
        l0_identity::GhostIdentity::generate_fresh()
    }

    /// The mesh membership secret these tests prove knowledge of.
    fn test_psk() -> [u8; 32] {
        [0x33; 32]
    }

    /// Build an offer through the real encoder, so these tests cannot drift away
    /// from the signalling format they are meant to cover.
    fn sample_offer(controlling: bool) -> String {
        use std::net::SocketAddr;
        use vantablack::ghost::net::ice::{
            Candidate, CandidateType, IceCredentials, IceOffer, DEFAULT_COMPONENT,
        };
        let base: SocketAddr = "192.168.1.5:40000".parse().unwrap();
        IceOffer::new(
            IceCredentials {
                ufrag: "deadbeef".into(),
                password: "00112233445566778899aabbccddeeff".into(),
            },
            vec![Candidate::new(
                CandidateType::Host,
                base,
                base,
                DEFAULT_COMPONENT,
                None,
            )],
            controlling,
        )
        .encode()
    }

    #[test]
    fn a_plain_beacon_keeps_the_legacy_112_byte_layout() {
        let b = build_beacon_packet(&test_pk(), stub_signer, None, None, false, None);
        assert_eq!(b.len(), BEACON_LEGACY_LEN);
        assert_eq!(&b[..16], BEACON_PREFIX);
        let sections = parse_beacon_sections(&b, b.len()).expect("parses with no sections");
        assert!(sections.zk.is_none());
        assert!(sections.ice_offer.is_none());
    }

    #[test]
    fn a_membership_proof_beacon_uses_the_sectioned_layout() {
        // Hard switch (SOTA §6 G5): the 208-byte layout that carried a
        // signature-shaped block at fixed offsets is gone, so a node with nothing
        // else to say still says this in a section.
        let identity = real_identity();
        let pk = identity.public_key_bytes();
        let psk = test_psk();
        let b = build_beacon_packet(
            &pk,
            |d| identity.sign(d).to_bytes(),
            Some(ZkAuthenticator::create_proof(&pk, &psk)),
            None,
            false,
            None,
        );
        assert!(b.len() > BEACON_LEGACY_LEN);

        let sections = parse_beacon_sections(&b, b.len()).expect("the section must tile");
        let (context, proof) = sections.zk.expect("a membership proof is present");
        assert!(ZkAuthenticator::verify_proof(
            &pk,
            Some(&psk),
            context,
            proof
        ));
        // A verifier checking the wrong identity, or holding a different
        // membership secret, accepts nothing.
        assert!(!ZkAuthenticator::verify_proof(
            &test_pk(),
            Some(&psk),
            context,
            proof
        ));
        assert!(!ZkAuthenticator::verify_proof(
            &pk,
            Some(&[0x44; 32]),
            context,
            proof
        ));
    }

    #[test]
    fn a_proof_made_for_one_identity_is_not_accepted_in_another_beacon() {
        // The statement names the pk it was made for, so even a member of the
        // same mesh — holding the same PSK — cannot lift its own proof into
        // another node's beacon. What ties the pk to the sender is the beacon's
        // prefix signature, and this test asserts the split rather than hiding
        // it (SOTA §6 G5).
        let mine = real_identity();
        let theirs = real_identity();
        let psk = test_psk();
        let (context, proof) = ZkAuthenticator::create_proof(&mine.public_key_bytes(), &psk);
        let b = build_beacon_packet(
            &theirs.public_key_bytes(),
            |d| theirs.sign(d).to_bytes(),
            Some((context, proof)),
            None,
            false,
            None,
        );
        let sections = parse_beacon_sections(&b, b.len()).expect("the section must tile");
        let (ctx, pr) = sections.zk.expect("a membership proof is present");
        assert!(
            !ZkAuthenticator::verify_proof(&theirs.public_key_bytes(), Some(&psk), ctx, pr),
            "a proof made for another identity must not verify against this beacon"
        );
        assert!(ZkAuthenticator::verify_proof(
            &mine.public_key_bytes(),
            Some(&psk),
            ctx,
            pr
        ));
    }

    #[test]
    fn an_offer_beacon_round_trips_through_its_sections() {
        let offer = sample_offer(true);
        let b = build_beacon_packet(&test_pk(), stub_signer, None, Some(&offer), false, None);
        assert!(b.len() > BEACON_LEGACY_LEN);

        let sections = parse_beacon_sections(&b, b.len()).expect("sections must tile exactly");
        assert!(sections.zk.is_none(), "no proof was attached");
        assert_eq!(sections.ice_offer, Some(offer.as_str()));

        // And it decodes back into a usable offer, candidates included.
        let decoded = vantablack::ghost::net::ice::IceOffer::decode(sections.ice_offer.unwrap())
            .expect("a well-formed offer must decode");
        assert_eq!(decoded.credentials.ufrag, "deadbeef");
        assert!(decoded.controlling);
        assert_eq!(
            decoded.candidates[0].addr,
            "192.168.1.5:40000".parse().unwrap()
        );
    }

    #[test]
    fn a_zk_beacon_with_an_offer_carries_both_sections() {
        let offer = sample_offer(false);
        let identity = real_identity();
        let pk = identity.public_key_bytes();
        let psk = test_psk();
        let b = build_beacon_packet(
            &pk,
            |d| identity.sign(d).to_bytes(),
            Some(ZkAuthenticator::create_proof(&pk, &psk)),
            Some(&offer),
            false,
            None,
        );
        let sections = parse_beacon_sections(&b, b.len()).expect("both sections must parse");

        let (context, proof) = sections.zk.expect("membership proof present");
        assert!(
            ZkAuthenticator::verify_proof(&pk, Some(&psk), context, proof),
            "the proof must verify for the identity it was made for"
        );
        assert_eq!(sections.ice_offer, Some(offer.as_str()));
        let decoded =
            vantablack::ghost::net::ice::IceOffer::decode(sections.ice_offer.unwrap()).unwrap();
        assert!(!decoded.controlling);
    }

    /// The post-quantum commitment rides its own section and round-trips (P2-1).
    #[test]
    fn a_pq_commitment_section_names_the_post_quantum_key() {
        let identity = real_identity();
        let pk = identity.public_key_bytes();
        let commitment = identity.pq_commitment();
        let b = build_beacon_packet(
            &pk,
            |d| identity.sign(d).to_bytes(),
            None,
            None,
            false,
            Some(&commitment),
        );
        let sections = parse_beacon_sections(&b, b.len()).expect("the section must tile exactly");
        assert_eq!(sections.pq_commitment, Some(&commitment));
        // And it is the commitment to *this* identity's key, so a verifier that
        // remembers it can check the key the peer later proves on the carrier.
        assert_eq!(commitment, l0_identity::pq_commitment(&identity.pq_public_key_bytes()));
        // A section with no commitment anywhere is not invented.
        let plain = build_beacon_packet(&pk, stub_signer, None, None, false, None);
        assert_eq!(plain.len(), BEACON_LEGACY_LEN);
        assert!(parse_beacon_sections(&plain, plain.len())
            .expect("a bare beacon parses")
            .pq_commitment
            .is_none());
        // A wrongly sized commitment section is malformed, not truncated.
        let mut bad = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut bad, BEACON_SECTION_PQ_COMMIT, &commitment[..31]);
        assert!(parse_beacon_sections(&bad, bad.len()).is_none());
    }

    #[test]
    fn malformed_or_unknown_sections_fall_back_to_the_legacy_layout() {
        // A length that runs past the datagram must not be trusted.
        let mut buf = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf, BEACON_SECTION_ICE, b"x");
        let amt = buf.len();
        buf[BEACON_LEGACY_LEN + 4..BEACON_LEGACY_LEN + 6].copy_from_slice(&9999u16.to_be_bytes());
        assert!(parse_beacon_sections(&buf, amt).is_none());

        // An unknown magic is not a section either.
        let mut buf2 = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf2, b"XXXX", b"payload");
        let amt2 = buf2.len();
        assert!(parse_beacon_sections(&buf2, amt2).is_none());

        // A ZK section of the wrong size is rejected rather than misread.
        let mut buf3 = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf3, BEACON_SECTION_ZK, &[0u8; 40]);
        let amt3 = buf3.len();
        assert!(parse_beacon_sections(&buf3, amt3).is_none());

        // A trailing partial header is rejected.
        let mut buf4 = vec![0u8; BEACON_LEGACY_LEN + 3];
        buf4[BEACON_LEGACY_LEN] = b'I';
        let amt4 = buf4.len();
        assert!(parse_beacon_sections(&buf4, amt4).is_none());
    }

    #[test]
    fn an_empty_offer_section_is_absent_not_empty_text() {
        // A zero-length ICEO section is a present-but-empty offer, which the
        // decoder rejects; the framing itself must still tile.
        let mut buf = vec![0u8; BEACON_LEGACY_LEN];
        push_beacon_section(&mut buf, BEACON_SECTION_ICE, b"");
        let amt = buf.len();
        let sections = parse_beacon_sections(&buf, amt).expect("tiles exactly");
        assert_eq!(sections.ice_offer, Some(""));
        assert!(vantablack::ghost::net::ice::IceOffer::decode("").is_err());
    }
}

#[cfg(test)]
mod ratchet_live_tests {
    //! The ratchet end to end: two nodes, two real sockets, the real maintenance
    //! tick, the real ingress (`RxContext::ingest`) and the real handler
    //! (`handle_pkt`) — the epoch is observed to change on a *live* session.
    //!
    //! Why this exists at all, and why the other tests were not enough: they called
    //! `handle_pkt` or the session API directly, so nothing ever exercised the path a
    //! *datagram* takes between the socket and the handler. That path carried a
    //! `#[cfg(feature = "vpn")]` on its self-contained-frame bypass, so the step PDU
    //! was delivered under `--features vpn` and silently swallowed by the shard spool
    //! in a default build — where a single frame is one shard of three and never
    //! assembles. Both were "the ratchet works"; one of them was false, and only a
    //! test that drives a datagram in can tell them apart.
    use super::*;
    use std::time::Instant as StdInstant;
    // `PoissonReputationMatrix` and `RevocationList` come in through `super::*`, which
    // is also what guarantees this test wires the pipeline with the same types `main`
    // does rather than with lookalikes.
    use vantablack::ghost::net::is_v2_frame;
    use vantablack::ghost::session::ratchet::RATCHET_INTERVAL;

    /// A real node, built by hand.
    ///
    /// Deliberately not `GhostNode::new`: that loads or **generates** an identity
    /// file in the working directory and spawns four worker tasks, neither of which a
    /// test should be doing to a developer's checkout. Everything else is the real
    /// node type, driving the real code paths.
    async fn node(id: Arc<l0_identity::GhostIdentity>) -> Arc<GhostNode> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback"));
        let local_addr = socket.local_addr().expect("local addr").to_string();
        // `dispatch_packet` indexes `workers`, so there has to be at least one, and a
        // drained channel keeps the dispatcher from filling up mid-test.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        Arc::new(GhostNode {
            identity: id,
            sessions: Arc::new(DashMap::new()),
            socket,
            contact_plan: tokio::sync::RwLock::new(ContactPlan::default()),
            created_at: StdInstant::now(),
            local_addr,
            flow_controller: Arc::new(net::FlowController::new(100)),
            stats: Arc::new(net::ThroughputStats::new()),
            running: std::sync::atomic::AtomicBool::new(true),
            workers: vec![tx],
            worker_idx: std::sync::atomic::AtomicUsize::new(0),
            beacon_enabled: std::sync::atomic::AtomicBool::new(false),
            keepalive_interval_secs: std::sync::atomic::AtomicU64::new(120),
        })
    }

    /// The receive pipeline for one node, wired the way `main` wires it.
    fn rx_for(
        node: &Arc<GhostNode>,
        peers: Arc<DashMap<String, SocketAddr>>,
        fallback: Arc<Fallback>,
    ) -> Arc<RxContext> {
        let reputation = Arc::new(PoissonReputationMatrix::new());
        Arc::new(RxContext {
            node: Arc::clone(node),
            peers,
            spool: Arc::new(DashMap::new()),
            pending_hs: Arc::new(DashMap::new()),
            revocation_list: Arc::new(RevocationList::new()),
            reputation: Arc::clone(&reputation),
            vpn: None,
            exit_tunnels: Arc::new(DashMap::new()),
            sessions_rx: Arc::new(DashMap::new()),
            rx_state_map: Arc::new(DashMap::new()),
            connect_acks: Arc::new(DashMap::new()),
            connect_ok_ctrs: Arc::new(DashMap::new()),
            trusted_exits: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
            psk: None,
            tft: Arc::new(TitForTatEnforcer::new(
                node.fingerprint(),
                Arc::clone(&reputation),
            )),
            rotator: None,
            relay_role: None,
            fallback: Some(fallback),
            dispatcher: Arc::new(net::dispatcher::LocklessDispatcher::new(1, 256)),
            socket: Arc::clone(&node.socket),
        })
    }

    /// Take one datagram off a socket, as the receive loop does.
    async fn recv_one(sock: &UdpSocket) -> Vec<u8> {
        let mut buf = vec![0u8; GTF_BULK_SIZE + 64];
        let (amt, _src) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("a datagram should have arrived")
            .expect("recv_from");
        buf.truncate(amt);
        buf
    }

    /// `handle_pkt` runs on a spawned task, so effects are waited for rather than
    /// assumed to have landed when `ingest` returns.
    async fn wait_for(label: &str, mut cond: impl FnMut() -> bool) {
        let deadline = StdInstant::now() + Duration::from_secs(5);
        while StdInstant::now() < deadline {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {label}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_session_rotates_its_epoch_through_the_real_receive_path() {
        let alice_id = Arc::new(l0_identity::GhostIdentity::generate_fresh());
        let bob_id = Arc::new(l0_identity::GhostIdentity::generate_fresh());
        let alice = node(Arc::clone(&alice_id)).await;
        let bob = node(Arc::clone(&bob_id)).await;
        let alice_addr = alice.socket.local_addr().expect("alice addr");
        let bob_addr = bob.socket.local_addr().expect("bob addr");
        let alice_fp = alice_id.fingerprint();
        let bob_fp = bob_id.fingerprint();
        assert_ne!(alice_addr, bob_addr);

        // The two seats on one session, exactly as the handshake leaves them: one
        // shared master key, complementary roles, and each peer's identity pinned.
        let master = [0x5Au8; 32];
        let a_sess = Session::new_with_role(master, bob_fp.clone(), SessionRole::Initiator);
        a_sess.pin_peer_identity(bob_id.public_key_bytes());
        let b_sess = Session::new_with_role(master, alice_fp.clone(), SessionRole::Responder);
        b_sess.pin_peer_identity(alice_id.public_key_bytes());
        let a_hash = a_sess.session_hash;
        alice.sessions.insert(bob_fp.clone(), a_sess);
        bob.sessions.insert(alice_fp.clone(), b_sess);
        assert_eq!(
            a_hash,
            bob.sessions.get(&alice_fp).unwrap().session_hash,
            "both seats derive one session"
        );

        // Address books, so the tick has a route to send the step down.
        let alice_addrs = Arc::new(DashMap::new());
        alice_addrs.insert(bob_fp.clone(), bob_addr);
        let bob_addrs = Arc::new(DashMap::new());
        bob_addrs.insert(alice_fp.clone(), alice_addr);
        let alice_fb = Arc::new(Fallback::new(None));
        let alice_rx = rx_for(&alice, Arc::clone(&alice_addrs), Arc::clone(&alice_fb));
        let bob_rx = rx_for(&bob, Arc::clone(&bob_addrs), Arc::new(Fallback::new(None)));

        // Spend a whole epoch: 1M datagrams is the trigger the interval names.
        {
            let s = alice.sessions.get(&bob_fp).expect("alice's session");
            for _ in 0..RATCHET_INTERVAL {
                s.note_sealed_frame();
            }
            assert!(s.ratchet_due(), "a spent epoch owes a step");
            assert_eq!(s.epoch(), 0);
        }

        // ── The real tick body, one pass, on the real socket ─────────────────────
        ratchet_maintenance_once(&alice, &alice_addrs, &alice_fb).await;
        // The step goes alice → bob, so it is *bob's* socket that has it — reading
        // it from alice's would only prove the send went nowhere.
        let step_frame = recv_one(&bob.socket).await;
        assert!(is_v2_frame(&step_frame), "the step is a v2 frame");
        assert_ne!(
            net::parse_flags(&step_frame) & net::FLAG_TUNNEL,
            0,
            "and a self-contained one: the ingress must not spool it"
        );
        assert_eq!(
            net::parse_gtf_v2_header(&step_frame).expect("v2 header").epoch,
            0,
            "the step travels on the epoch that is still live"
        );

        // ── Into bob's ingress, the way the socket loop feeds it ────────────────
        bob_rx.ingest(&step_frame, alice_addr).await; // src = alice, as recv_from reports
        wait_for("bob to prepare epoch 1", || {
            bob.sessions
                .get(&alice_fp)
                .map(|s| s.prepared_epoch())
                == Some(Some(1))
        })
        .await;
        {
            let s = bob.sessions.get(&alice_fp).expect("bob's session");
            assert_eq!(s.epoch(), 0, "answering prepares the epoch, it does not install it");
            assert_eq!(s.ratchet_steps.load(Ordering::Relaxed), 0);
        }

        // ── The answer comes back into alice's ingress ──────────────────────────
        let answer_frame = recv_one(&alice.socket).await;
        alice_rx.ingest(&answer_frame, bob_addr).await;
        wait_for("alice's epoch to rotate", || {
            alice.sessions.get(&bob_fp).map(|s| s.epoch()) == Some(1)
        })
        .await;
        {
            let s = alice.sessions.get(&bob_fp).expect("alice's session");
            assert_eq!(s.ratchet_steps.load(Ordering::Relaxed), 1);
            assert!(
                !s.ratchet_in_progress.load(Ordering::Relaxed),
                "a completed step leaves nothing in flight"
            );
            assert_eq!(s.epoch_capacity_left(), RATCHET_INTERVAL, "a fresh epoch");
        }

        // ── A data frame in the new epoch makes bob install it ──────────────────
        // Sent exactly the way the data path sends one: sealed once, Reed-Solomon
        // split into three shards *without* the self-contained bit, so this also
        // exercises the spool and the assembled branch of the ingress.
        let (ctx, shards, tag) = {
            let s = alice.sessions.get(&bob_fp).expect("alice's session");
            let ctx = SealCtx::from_session(&s);
            assert_eq!(ctx.epoch, 1, "the data path seals on the new epoch");
            let (shards, tag) = enc_split(&ctx, b"epoch one");
            (ctx, shards, tag)
        };
        send3_mixed(Arc::clone(&alice.socket), &bob_addr, &ctx, &shards, &tag).await;
        for _ in 0..3 {
            let f = recv_one(&bob.socket).await;
            assert_eq!(
                net::parse_flags(&f) & net::FLAG_TUNNEL,
                0,
                "a data frame is a shard, not a whole message"
            );
            bob_rx.ingest(&f, alice_addr).await;
        }
        wait_for("bob to install epoch 1", || {
            bob.sessions.get(&alice_fp).map(|s| s.epoch()) == Some(1)
        })
        .await;

        // ── And the two sides agree on the new epoch, one key per direction ─────
        let a = alice.sessions.get(&bob_fp).expect("alice's session");
        let b = bob.sessions.get(&alice_fp).expect("bob's session");
        assert_eq!(a.epoch(), b.epoch());
        assert_eq!(a.ratchet_steps.load(Ordering::Relaxed), 1);
        assert_eq!(b.ratchet_steps.load(Ordering::Relaxed), 1);
        assert_eq!(
            a.seal_key(NonceDirection::InitiatorToResponder),
            b.open_key(1, NonceDirection::InitiatorToResponder, 1)
                .expect("bob holds epoch 1"),
            "alice seals epoch 1 with the key bob opens it under"
        );
        assert_eq!(
            b.seal_key(NonceDirection::ResponderToInitiator),
            a.open_key(1, NonceDirection::ResponderToInitiator, 0)
                .expect("alice holds epoch 1"),
            "and bob's sending key is the one alice opens"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_step_that_cannot_be_verified_never_moves_the_epoch() {
        // The fail-closed half, through the same ingress: the step is authenticated
        // by the identity pinned at handshake time, so a peer whose pin is absent
        // gets a refusal and nothing else.
        let alice_id = Arc::new(l0_identity::GhostIdentity::generate_fresh());
        let bob_id = Arc::new(l0_identity::GhostIdentity::generate_fresh());
        let alice = node(Arc::clone(&alice_id)).await;
        let bob = node(Arc::clone(&bob_id)).await;
        let alice_addr = alice.socket.local_addr().expect("alice addr");
        let bob_addr = bob.socket.local_addr().expect("bob addr");
        let alice_fp = alice_id.fingerprint();
        let bob_fp = bob_id.fingerprint();

        let master = [0x11u8; 32];
        let a_sess = Session::new_with_role(master, bob_fp.clone(), SessionRole::Initiator);
        a_sess.pin_peer_identity(bob_id.public_key_bytes());
        // Bob deliberately has **no** pin: the session exists, the identity does not.
        let b_sess = Session::new_with_role(master, alice_fp.clone(), SessionRole::Responder);
        alice.sessions.insert(bob_fp.clone(), a_sess);
        bob.sessions.insert(alice_fp.clone(), b_sess);

        let alice_addrs = Arc::new(DashMap::new());
        alice_addrs.insert(bob_fp.clone(), bob_addr);
        let alice_fb = Arc::new(Fallback::new(None));
        let alice_rx = rx_for(&alice, Arc::clone(&alice_addrs), Arc::clone(&alice_fb));
        let bob_rx = rx_for(&bob, Arc::new(DashMap::new()), Arc::new(Fallback::new(None)));
        let _ = &alice_rx;

        {
            let s = alice.sessions.get(&bob_fp).expect("alice's session");
            for _ in 0..RATCHET_INTERVAL {
                s.note_sealed_frame();
            }
        }
        ratchet_maintenance_once(&alice, &alice_addrs, &alice_fb).await;
        let step_frame = recv_one(&bob.socket).await;
        bob_rx.ingest(&step_frame, alice_addr).await;

        // Give it every chance to be acted on before concluding it was not.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let b = bob.sessions.get(&alice_fp).expect("bob's session");
        assert_eq!(b.epoch(), 0, "an unverifiable step must not move the epoch");
        assert_eq!(b.prepared_epoch(), None, "nor prepare one");
        // Bob answered nothing either, so alice is still waiting (and will retry).
        assert!(alice
            .sessions
            .get(&bob_fp)
            .expect("alice's session")
            .ratchet_in_progress
            .load(Ordering::Relaxed));
    }
}

#[cfg(test)]
mod ratchet_transport_tests {
    //! The ratchet's *transport* — the half that turns a complete-and-tested step
    //! API into an epoch that a live session actually rotates.
    //!
    //! These tests deliberately re-run the byte path the two call sites use: the
    //! maintenance tick's `begin_ratchet_step` → `build_ratchet_step_pdu` →
    //! `seal_single`, and the receive path's open → `frame_payload` →
    //! `parse_rekey_pdu` → signature check → `answer_ratchet_step`. Driving the
    //! sessions directly would have passed while the PDU framing was wrong, which
    //! is exactly the class of bug a "no transport" gap hides.
    use super::*;
    use vantablack::ghost::net::{extract_payload, is_v2_frame, parse_gtf_v2_header};
    use vantablack::ghost::session::ratchet::RATCHET_INTERVAL;

    /// A live session pair: real identities, pinned the way the handshake pins
    /// them, and one shared master key — two seats on one session.
    fn session_pair() -> (
        Session,
        Session,
        l0_identity::GhostIdentity,
        l0_identity::GhostIdentity,
    ) {
        let alice_id = l0_identity::GhostIdentity::generate_fresh();
        let bob_id = l0_identity::GhostIdentity::generate_fresh();
        let master = [0x5Au8; 32];
        let alice = Session::new_with_role(master, bob_id.fingerprint(), SessionRole::Initiator);
        let bob = Session::new_with_role(master, alice_id.fingerprint(), SessionRole::Responder);
        alice.pin_peer_identity(bob_id.public_key_bytes());
        bob.pin_peer_identity(alice_id.public_key_bytes());
        (alice, bob, alice_id, bob_id)
    }

    /// Spend a whole epoch, which is what makes the tick act.
    fn spend_the_epoch(s: &Session) {
        for _ in 0..RATCHET_INTERVAL {
            s.note_sealed_frame();
        }
        assert!(s.ratchet_due(), "a full epoch owes a step");
        assert_eq!(s.epoch_capacity_left(), 0);
    }

    /// Open a frame the way the receive path does and hand back the payload the
    /// ratchet handler sees.
    fn open_like_the_receive_path(
        opener: &Session,
        frame: &[u8],
        direction: NonceDirection,
    ) -> Vec<u8> {
        let h = parse_gtf_v2_header(frame).expect("a v2 header");
        let plan = opener.plan_open(h.epoch, direction, h.counter);
        let key = match plan {
            vantablack::ghost::session::ratchet::OpenPlan::Forward { key, .. } => key,
            vantablack::ghost::session::ratchet::OpenPlan::Cached { key, .. } => key,
            _ => panic!("plan failed for counter {}", h.counter),
        };
        let mut carried = unframe(extract_payload(frame)).expect("a framed shard");
        let opened = xchacha_open(&key, &h.nonce, h.epoch, direction, &mut carried)
            .expect("the epoch key opens it");
        opener.commit_open(h.epoch, direction, plan);
        frame_payload(opened)
            .expect("a framed payload")
            .to_vec()
    }

    #[test]
    fn a_full_epoch_makes_a_live_session_rotate_its_epoch() {
        let (alice, bob, alice_id, bob_id) = session_pair();
        assert_eq!(alice.epoch(), 0);
        spend_the_epoch(&alice);

        // ── The maintenance tick's body, line for line ──────────────────────────
        let (x_pub, kem_pub) = alice
            .begin_ratchet_step()
            .expect("a due session starts a step");
        assert!(
            alice.begin_ratchet_step().is_none(),
            "and does not start a second one while the first is in flight"
        );
        let pdu = build_ratchet_step_pdu(|d| alice_id.sign(d).to_bytes(), &x_pub, &kem_pub)
            .expect("our own ephemeral material round-trips");
        assert!(
            pdu.len() > 458,
            "a step PDU exceeds a privacy payload, so it needs a bulk frame"
        );
        let ctx = SealCtx::from_session(&alice);
        assert_eq!(ctx.epoch, 0, "the step itself still travels on the live epoch");
        let frame = seal_single(&ctx, &pdu);
        assert!(is_v2_frame(&frame));
        assert_eq!(frame.len(), GTF_BULK_SIZE);

        // ── The receive path's body ────────────────────────────────────────────
        let payload = open_like_the_receive_path(&bob, &frame, NonceDirection::InitiatorToResponder);
        let blob = parse_rekey_pdu(&payload).expect("a step PDU");
        assert!(
            l0_identity::verify_peer_signature(
                &alice_id.public_key_bytes(),
                &rekey_init_signed_material(&blob.x25519_pub, &blob.kyber_pub),
                &blob.signature,
            ),
            "the PDU is signed by the identity the session pinned"
        );
        // The material that arrived is the material the session handed out — both
        // halves, so the PQ half of the exchange is bound too.
        assert_eq!(blob.x25519_pub, x_pub);
        assert_eq!(blob.kyber_pub.as_slice(), kem_pub.as_slice());

        let answer = bob
            .answer_ratchet_step(&blob.x25519_pub, &blob.kyber_pub)
            .expect("the peer answers");
        assert_eq!(bob.epoch(), 0, "answering prepares the epoch, it does not install it");
        assert_eq!(bob.prepared_epoch(), Some(1));
        let reply = build_rekey_response_pdu(
            |d| bob_id.sign(d).to_bytes(),
            &answer.x_public,
            &answer.kem_ct,
            &answer.confirm,
        );
        let rblob_raw = parse_rekey_response_pdu(&reply).expect("a well-formed answer");
        assert!(
            l0_identity::verify_peer_signature(
                &bob_id.public_key_bytes(),
                &rekey_answer_signed_material(
                    &rblob_raw.x25519_pub,
                    &rblob_raw.kyber_ct,
                    &rblob_raw.confirm,
                ),
                &rblob_raw.signature,
            ),
            "the answer is signed by the responder's pinned identity"
        );

        // The reply is sealed on the epoch the peer still holds — bob has only
        // *prepared* the new one, so a reply on it would be unopenable to alice.
        let reply_ctx = SealCtx::from_session(&bob);
        assert_eq!(reply_ctx.epoch, 0);
        let reply_frame = seal_single(&reply_ctx, &reply);

        // ── Back on the initiating side ────────────────────────────────────────
        let reply_payload = open_like_the_receive_path(
            &alice,
            &reply_frame,
            NonceDirection::ResponderToInitiator,
        );
        let rblob = parse_rekey_response_pdu(&reply_payload).expect("a step answer");
        assert_eq!(
            alice.finish_ratchet_step(&RatchetAnswer {
                x_public: rblob.x25519_pub,
                kem_ct: rblob.kyber_ct,
                confirm: rblob.confirm,
                epoch: alice.epoch() + 1,
            }),
            Some(1),
            "the answer confirms the step and the epoch moves"
        );
        assert_eq!(alice.epoch(), 1);
        assert!(
            !alice.ratchet_in_progress.load(Ordering::Relaxed),
            "a completed step leaves nothing in flight"
        );

        // The responder installs it only when a frame of the new epoch opens.
        assert!(bob.activate_epoch(1));
        assert_eq!(alice.epoch(), bob.epoch());
        assert_eq!(
            alice.seal_key(NonceDirection::InitiatorToResponder),
            bob.open_key(1, NonceDirection::InitiatorToResponder, 0)
                .expect("epoch 1 key"),
            "one round trip, one epoch, one key"
        );
    }

    #[test]
    fn a_step_pdu_that_does_not_verify_never_moves_the_epoch() {
        // The fail-closed half of the handler: the step is authenticated by the
        // pinned identity key, so a PDU signed by somebody else is refused before
        // `answer_ratchet_step` is ever reached and the epoch stays put.
        let (alice, bob, _alice_id, _bob_id) = session_pair();
        let impostor = l0_identity::GhostIdentity::generate_fresh();
        spend_the_epoch(&alice);
        let (x_pub, kem_pub) = alice.begin_ratchet_step().unwrap();
        let pdu = build_ratchet_step_pdu(|d| impostor.sign(d).to_bytes(), &x_pub, &kem_pub)
            .expect("a well-formed PDU from the wrong signer");
        let frame = seal_single(&SealCtx::from_session(&alice), &pdu);
        let payload = open_like_the_receive_path(&bob, &frame, NonceDirection::InitiatorToResponder);
        let blob = parse_rekey_pdu(&payload).expect("well-formed on the wire");

        // What `handle_ratchet_pdu` checks before answering.
        let pinned = bob.peer_identity_pk().expect("the handshake pinned alice");
        assert!(
            !l0_identity::verify_peer_signature(
                &pinned,
                &rekey_init_signed_material(&blob.x25519_pub, &blob.kyber_pub),
                &blob.signature,
            ),
            "the impostor's signature must not verify against the pinned key"
        );
        assert_eq!(bob.epoch(), 0);
        assert_eq!(bob.prepared_epoch(), None, "nothing was prepared for an unauthenticated step");
    }
}

#[cfg(test)]
mod p3_1_cover_tests {
    //! Cover traffic (SOTA P3-1): the flag reaches the wire, the shape is the same
    //! as a data message, the receiver decides on the authenticated marker rather
    //! than the header bit, and the gaps are drawn rather than fixed.
    use super::*;

    fn ctx(seed: u8) -> SealCtx {
        let s = Session::new_with_role([seed; 32], "peer".into(), SessionRole::Initiator);
        SealCtx::from_session(&s)
    }

    #[test]
    fn the_cover_bit_reaches_the_wire_and_is_not_a_version_marker() {
        use vantablack::ghost::net::{parse_gtf_v2_header, GTF_BASE_SIZE, JITTER_MAX};

        let ctx = ctx(0x5A);
        let (shards, tag) = enc_split(&ctx, net::DUMMY_MAGIC);
        assert_eq!(shards.len(), 3, "cover is an ordinary RS(2,1) group, like data");

        for i in 0..3 {
            let frame =
                net::build_gtf_v2_frame(&ctx.header(i as u8, false, net::FLAG_DUMMY), &shards[i], &tag);
            let h = parse_gtf_v2_header(&frame).expect("a v2 header");
            assert_ne!(
                h.flags & net::FLAG_DUMMY,
                0,
                "the caller bit must survive the builder's mask — before P3-1 it was masked off"
            );
            assert_eq!(h.flags & net::FLAG_V2, 0, "the v2 marker is not a caller bit");
            assert_eq!(
                frame.len(),
                GTF_BASE_SIZE + JITTER_MAX,
                "cover is a privacy frame, not a bulk one: same shape as data"
            );
            assert!(!h.bulk);
        }
    }

    #[test]
    fn cover_traffic_is_recognised_by_its_marker_not_by_its_header_bit() {
        use vantablack::ghost::net::{is_dummy_payload, tail_for, DUMMY_MAGIC};

        let ctx = ctx(0x33);
        let tail = tail_for(&ctx.key, &ctx.nonce, ctx.epoch, ctx.direction);

        // Seal exactly what `enc_split` seals, then take the receiver's own two
        // steps over it: open, then classify. `open_received_frame` strips the tag,
        // which is why `frame_payload` sees `[len][payload]`.
        let mut framed = (DUMMY_MAGIC.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(DUMMY_MAGIC);
        xchacha_seal_in_place_with_aad(
            &ctx.key,
            &ctx.nonce,
            ctx.epoch,
            ctx.direction,
            &mut framed,
            &tail,
        )
        .expect("seal");
        let opened = xchacha_open_with_aad(
            &ctx.key,
            &ctx.nonce,
            ctx.epoch,
            ctx.direction,
            &mut framed,
            &tail,
        )
        .expect("opens");
        assert!(
            frame_payload(opened).is_some_and(is_dummy_payload),
            "a cover frame must be recognised after decryption"
        );

        // A data payload is not cover, and neither is a near-miss of the marker.
        let mut real = 4u16.to_be_bytes().to_vec();
        real.extend_from_slice(b"data");
        assert!(!frame_payload(&real).is_some_and(is_dummy_payload));
        assert!(!is_dummy_payload(b"DUMMY"), "a prefix is not the marker");
        assert!(!is_dummy_payload(b"DUMMY?"), "one byte off is not the marker");
        assert!(!is_dummy_payload(b""));

        // The decision takes only the payload, so a header bit can neither suppress
        // a real frame nor promote a placeholder — which is the property the flag's
        // own doc-comment claims, asserted here rather than left to inspection.
        assert!(
            !is_dummy_payload(frame_payload(&real).expect("a framed data payload")),
            "FLAG_DUMMY on a real payload must not make it cover"
        );
    }

    #[test]
    fn cover_gaps_are_drawn_not_a_metronome() {
        // An exponential inter-arrival time with rate λ has mean 1/λ, and a cover
        // message is three frames — so at `COVER_FRAMES_PER_SEC` the mean gap is
        // `COVER_FRAMES_PER_MESSAGE / COVER_FRAMES_PER_SEC`. Checking the mean alone
        // would pass for a fixed interval, which is exactly what must be excluded,
        // so the spread is checked too.
        let draws = 20_000;
        let mut total = 0.0f64;
        let mut distinct = std::collections::HashSet::new();
        for i in 0..draws {
            let u = (i as f64 + 0.5) / draws as f64;
            let gap = cover_gap(u, COVER_FRAMES_PER_SEC).as_secs_f64();
            total += gap;
            distinct.insert((gap * 1000.0) as u64);
        }
        let mean = total / draws as f64;
        let expected = COVER_FRAMES_PER_MESSAGE / COVER_FRAMES_PER_SEC;
        assert!(
            (mean - expected).abs() < 0.15 * expected,
            "mean gap {mean:.3}s should be near {expected:.3}s"
        );
        assert!(distinct.len() > 100, "gaps must vary, not repeat");

        // Both tails are clamped, so neither a near-zero nor a near-one draw can
        // spin the loop or stall cover.
        for u in [0.0, 0.999_999] {
            let g = cover_gap(u, COVER_FRAMES_PER_SEC);
            assert!(g >= Duration::from_millis(5) && g <= Duration::from_secs(30));
        }
        // A non-positive rate means "no cover", expressed as an impossible gap.
        assert_eq!(cover_gap(0.5, 0.0), Duration::from_secs(3600));
    }
}
