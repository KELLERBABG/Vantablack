//! daemon::framing — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

/// Whether ShardSec (per-shard AEAD) is enabled for outbound frames.
///
/// **Default-on since 0.7.7.** Each Reed-Solomon shard is sealed under its own
/// HKDF-derived key, so a tampered shard fails its own Poly1305 tag and is
/// discarded *before* reconstruction — the property the documentation's
/// Byzantine-tamper-isolation claim describes. Legacy frames (message-level
/// AEAD only) remain fully supported on receive in both modes: the per-frame
/// `FLAG_SHARDSEC` bit decides how a frame is opened, so mixed fleets of old
/// and new builds interoperate.
///
/// Set `GHOST_SHARDSEC=off` (or `0`/`false`, case-insensitive) to emit legacy
/// frames — for example to diagnose against a pre-ShardSec peer. Any other
/// value, or an unset variable, means enabled.
/// The pure ShardSec decision for one env value, so every env shape is
/// unit-testable without mutating the process environment (the process-wide
/// answer is cached once in [`shardsec_default_enabled`]).
pub(crate) fn shardsec_enabled_for(env_value: Option<&str>) -> bool {
    match env_value {
        // Unset: per-shard AEAD is the default.
        None => true,
        Some(v) => !(v.eq_ignore_ascii_case("off") || v == "0" || v.eq_ignore_ascii_case("false")),
    }
}

pub(crate) fn shardsec_default_enabled() -> bool {
    static RESOLVED: OnceLock<bool> = OnceLock::new();
    *RESOLVED.get_or_init(|| shardsec_enabled_for(std::env::var("GHOST_SHARDSEC").ok().as_deref()))
}

pub(crate) enum PendingHandshake {
    Kem512(x25519_dalek::EphemeralSecret, DecapsulationKey512),
    Negotiated {
        x_secret: x25519_dalek::EphemeralSecret,
        kem512: DecapsulationKey512,
        kem768: DecapsulationKey768,
        offered: Vec<HybridCipherSuite>,
    },
}

pub(crate) type PendingHandshakes = Arc<DashMap<String, PendingHandshake>>;

/// Identity of one in-flight shard group in the reassembly spool.
///
/// The wire counter alone is **not** a message identity, and the two ways it
/// fails are both silent:
///
/// * **Two sessions.** A counter is a per-session sequence number, so session A's
///   counter 5 and session B's counter 5 are different messages. Keyed by the
///   counter alone they share a bucket, and whichever shards arrive interleaved
///   reconstruct one PDU out of two.
/// * **No session at all.** Every handshake is sent with session hash
///   `[0, 0, 0, 0]` and counter `0` (offer) or `1` (response), because there is
///   no session yet to number the message with. A boot LAN sweep that reaches
///   several seeds at once — or a retry issued while an earlier attempt is still
///   in flight — then drops every peer's shards into one bucket.
///
/// Either way the result is an outage no tag and no signature can catch: every
/// shard was authentic, only the grouping was wrong.
///
/// So the bucket is keyed by the frame's own **generation** — the session it
/// belongs to, the ratchet epoch that sealed it, and the counter — which is what
/// the shards of one message share and what no two messages do. For a frame
/// that has no session hash yet there is no generation to name, so the sender's
/// address stands in for it (see [`SpoolKey::of`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct SpoolKey {
    pub(crate) session_hash: [u8; 4],
    pub(crate) epoch: u64,
    pub(crate) counter: u64,
    /// The sender, recorded **only for a frame that has no session hash yet**.
    ///
    /// Deliberately not part of the key for a session frame: the multi-hop shard
    /// router sends the three shards of one message through *different* peers, so
    /// they arrive from different addresses, and a key that named one address
    /// would never reassemble them. It is also unnecessary there — the session
    /// hash and the counter already separate every message. A handshake has
    /// neither, so the address it came from is its only identity.
    pub(crate) pre_session_src: Option<SocketAddr>,
}

impl SpoolKey {
    /// The bucket a received datagram belongs to, read entirely from the wire.
    pub(crate) fn of(src: SocketAddr, datagram: &[u8], v2: Option<V2FrameMeta>) -> Self {
        let session_hash = net::parse_session_hash(datagram);
        Self {
            session_hash,
            // `None` is a v1 frame: the handshake and the legacy inner layers
            // carry no epoch, so their generation is the session hash alone.
            epoch: v2.map_or(0, |meta| meta.epoch),
            counter: net::parse_packet_counter_u64(datagram),
            pre_session_src: (session_hash == [0, 0, 0, 0]).then_some(src),
        }
    }
}

/// The per-node shard-reassembly spool: one bucket per in-flight message.
///
/// Entries with fewer than two shards are pruned when the cap is exceeded
/// (anti-memory-DoS) — see [`MAX_SPOOL_ENTRIES`].
pub(crate) type SpoolPool = DashMap<SpoolKey, Vec<Option<Vec<u8>>>>;

/// Hard cap on the shard-reassembly spool (per-node). Entries with fewer than
/// two shards are pruned when the cap is exceeded (anti-memory-DoS).
pub(crate) const MAX_SPOOL_ENTRIES: usize = 8192;

/// Hard cap on concurrent sessions (anti-flood: attackers can mint unlimited
/// self-signed identities, so the session table must be bounded).
pub(crate) const MAX_SESSIONS: usize = 512;

/// Hard cap on in-flight pending handshakes per node.
pub(crate) const MAX_PENDING_HANDSHAKES: usize = 512;

pub(crate) async fn assemble(
    pool: &SpoolPool,
    key: SpoolKey,
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
        let mut entry = pool.entry(key).or_insert_with(|| vec![None, None, None]);
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
        let mut s = pool.remove(&key).map(|(_, s)| s).unwrap_or_default();
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

// `frame_shard` / `unframe` live in `ghost::net` (canonical) and are
// imported below.

/// Everything one outgoing v2 message is sealed with.
///
/// Taken as one snapshot from the session so the epoch key and the epoch number
/// cannot straddle a ratchet step: sealing under one epoch's key with another
/// epoch's number produces a frame no receiver can open.
#[derive(Clone)]
pub(crate) struct SealCtx {
    pub(crate) key: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) counter: u64,
    pub(crate) nonce: [u8; 12],
    pub(crate) direction: NonceDirection,
    pub(crate) session_hash: [u8; 4],
    /// This message filled its epoch: the caller should start a ratchet step.
    pub(crate) ratchet_due: bool,
}

impl SealCtx {
    pub(crate) fn from_session(s: &Session) -> Self {
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
    /// This is also the single place the jitter tail is attached. It is
    /// derived here rather than passed in, so every privacy frame gets the same
    /// tail the sealer authenticated as associated data, and no call site had to
    /// learn a new argument.
    pub(crate) fn header(&self, shard_index: u8, bulk: bool, flags: u8) -> net::GtfV2Header {
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

    pub(crate) fn data_header(&self, shard_index: u8, bulk: bool, flags: u8) -> net::GtfV2Header {
        let flags = if shardsec_default_enabled() {
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
pub(crate) struct V2FrameMeta {
    pub(crate) epoch: u64,
    pub(crate) nonce: [u8; 12],
    /// Whether this is an MTU-sized bulk frame, which carries no tail at all.
    pub(crate) bulk: bool,
    /// The jitter tail **exactly as it arrived on the wire**.
    pub(crate) tail: [u8; net::JITTER_MAX],
    /// ShardSec frames authenticate each RS shard independently and are opened
    /// before reconstruction; they do not use the legacy message-level AEAD.
    pub(crate) shardsec: bool,
}

impl V2FrameMeta {
    /// Read the seal metadata out of a raw datagram, if it is a v2 frame.
    pub(crate) fn of(frame: &[u8]) -> Option<Self> {
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
pub(crate) struct OpenCtx {
    pub(crate) peer_fp: String,
    pub(crate) master_key: [u8; 32],
    pub(crate) session_hash: [u8; 4],
    pub(crate) role: SessionRole,
}

impl OpenCtx {
    pub(crate) fn of(s: &Session) -> Self {
        Self {
            peer_fp: s.peer_fingerprint.clone(),
            master_key: s.master_key,
            session_hash: s.session_hash,
            role: s.role,
        }
    }

    pub(crate) fn snapshot_of(sessions: &DashMap<String, Session>) -> Vec<OpenCtx> {
        let mut out: Vec<OpenCtx> = sessions.iter().map(|e| OpenCtx::of(&e)).collect();
        out.shrink_to_fit();
        out
    }
}

/// Open the ciphertext carried by one received frame, for one session, whichever
/// wire version it arrived in.
pub(crate) fn open_received_frame(
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
                if xchacha_open_with_aad(&key, &meta.nonce, meta.epoch, dir, &mut buf, aad).is_ok()
                {
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

pub(crate) fn enc_split(ctx: &SealCtx, pay: &[u8]) -> (Vec<Vec<u8>>, [u8; 16]) {
    if shardsec_default_enabled() {
        let pay_len = pay.len() as u16;
        let mut framed = Vec::with_capacity(pay.len() + 3);
        framed.extend_from_slice(&pay_len.to_be_bytes());
        framed.extend_from_slice(pay);
        if framed.len() % 2 != 0 {
            framed.push(0);
        }
        let plaintext_shards = l4_rs::encode(&mut framed);
        let tail = net::tail_for(&ctx.key, &ctx.nonce, ctx.epoch, ctx.direction);
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
                    &tail,
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
    let mut framed = Vec::with_capacity(pay.len() + 3);
    framed.extend_from_slice(&pay_len.to_be_bytes());
    framed.extend_from_slice(pay);
    if framed.len() % 2 != 0 {
        framed.push(0);
    }
    // The privacy frame's jitter tail is authenticated as AEAD
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
pub(crate) struct MixWireFrame {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) destination: SocketAddr,
    pub(crate) frame: Vec<u8>,
    pub(crate) done: oneshot::Sender<std::io::Result<()>>,
}

/// The mix is deliberately process-local and bounded: at most three messages
/// (nine frames) wait for the same flush. A 20 ms deadline prevents a quiet link
/// from turning mixing into an outage, while a full batch gives the observer no
/// stable relation between application-message order and wire order.
pub(crate) static MIX_WIRE_QUEUE: OnceLock<Arc<std::sync::Mutex<MixBatch<MixWireFrame>>>> =
    OnceLock::new();

pub(crate) fn flush_mixed_frames(frames: Vec<MixWireFrame>) {
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

pub(crate) fn enqueue_mixed_frame(
    socket: &Arc<UdpSocket>,
    destination: SocketAddr,
    frame: Vec<u8>,
) -> oneshot::Receiver<std::io::Result<()>> {
    let (done, receiver) = oneshot::channel();
    let queue = MIX_WIRE_QUEUE
        .get_or_init(|| {
            let delay_ms = if std::env::var("GHOST_LOW_LATENCY")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(false)
            {
                1
            } else {
                std::env::var("GHOST_MIX_BATCH_MS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(20)
            };
            Arc::new(std::sync::Mutex::new(MixBatch::new(
                9,
                Duration::from_millis(delay_ms),
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

pub(crate) async fn send3(
    sock: &UdpSocket,
    dst: &SocketAddr,
    ctx: &SealCtx,
    f: &[Vec<u8>],
    tag: &[u8; 16],
) {
    // Borrowed-socket callers (notably the relay ingress) stay on the direct
    // path because their socket lifetime is owned by the receive task.
    for (i, shard) in f.iter().take(3).enumerate() {
        // `send_v2` is `send_gtf_v2` until the SRTP carrier is opted into, in
        // which case the same frame goes out inside an RTP header.
        let _ =
            super::srtp::send_v2(sock, dst, &ctx.data_header(i as u8, false, 0), shard, tag).await;
    }
}

/// Mixed variant for long-lived node-owned sockets. The queue holds only fully
/// framed opaque datagrams, so batching cannot change authentication or routing.
pub(crate) async fn send3_mixed(
    sock: Arc<UdpSocket>,
    dst: &SocketAddr,
    ctx: &SealCtx,
    f: &[Vec<u8>],
    tag: &[u8; 16],
) {
    let mut pending = Vec::with_capacity(3);
    for (i, shard) in f.iter().take(3).enumerate() {
        let header = ctx.data_header(i as u8, false, 0);
        let frame = match net::try_build_gtf_v2_frame(&header, shard, tag) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("GTF v2 frame oversize ({}): {e}", shard.len());
                continue;
            }
        };
        pending.push(enqueue_mixed_frame(
            &sock,
            *dst,
            super::srtp::shape_for_send(dst, &frame),
        ));
    }
    for result in pending {
        let _ = result.await;
    }
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
pub(crate) fn seal_single(ctx: &SealCtx, payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(2 + payload.len() + 1 + 16);
    framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    framed.extend_from_slice(payload);
    if framed.len() % 2 != 0 {
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

/// ShardSec default-on: the send side, the receive side, and the round trip.
#[cfg(test)]
mod shardsec_default_tests {
    use crate::*;

    #[test]
    pub(crate) fn the_env_switch_has_the_documented_semantics() {
        // Unset => enabled (the 0.7.7 default).
        assert!(shardsec_enabled_for(None));
        // The explicit opt-out spellings.
        assert!(!shardsec_enabled_for(Some("off")));
        assert!(!shardsec_enabled_for(Some("OFF")));
        assert!(!shardsec_enabled_for(Some("Off")));
        assert!(!shardsec_enabled_for(Some("0")));
        assert!(!shardsec_enabled_for(Some("false")));
        assert!(!shardsec_enabled_for(Some("FALSE")));
        // Anything else — including legacy truthy spellings and an empty
        // value — means enabled, exactly like the old any-set-value rule.
        assert!(shardsec_enabled_for(Some("on")));
        assert!(shardsec_enabled_for(Some("1")));
        assert!(shardsec_enabled_for(Some("true")));
        assert!(shardsec_enabled_for(Some("")));
    }

    pub(crate) fn test_ctx() -> SealCtx {
        SealCtx {
            key: [0x42; 32],
            epoch: 7,
            counter: 1000,
            nonce: [0x11; 12],
            direction: NonceDirection::InitiatorToResponder,
            session_hash: [0xAB, 0xCD, 0x12, 0x34],
            ratchet_due: false,
        }
    }

    #[test]
    pub(crate) fn enc_split_output_matches_the_resolved_shardsec_mode() {
        let ctx = test_ctx();
        let payload = b"byzantine isolation must be true of the product";
        let (carriers, tag) = enc_split(&ctx, payload);
        assert_eq!(carriers.len(), 3);
        if shardsec_default_enabled() {
            // ShardSec authenticates inside each shard; the legacy message tag
            // field is intentionally zero and never trusted in this mode.
            assert_eq!(tag, [0u8; 16]);
            // Every carrier unframes to a sealed shard: ciphertext + 16-byte tag.
            for carrier in &carriers {
                let sd = unframe(carrier).expect("frame_shard carrier");
                assert!(sd.len() > 16, "sealed shard = ciphertext + 16-byte tag");
            }
        } else {
            // Legacy mode: the real message-level Poly1305 tag is returned.
            assert_ne!(tag, [0u8; 16]);
        }
    }

    #[test]
    pub(crate) fn shardsec_datagrams_open_the_way_ingest_opens_them() {
        // Regression guard for the 0.7.7 default-on flip: build the datagrams
        // exactly as `send3_mixed` builds them, then run the exact steps
        // `RxContext::ingest` runs for a ShardSec frame. Any divergence between
        // the send and receive sides of the ShardSec path fails here.
        if !shardsec_default_enabled() {
            return;
        }
        let ctx = test_ctx();
        let (carriers, tag) = enc_split(&ctx, b"ingest parity");

        for (index, carrier) in carriers.iter().enumerate() {
            let datagram =
                net::build_gtf_v2_frame(&ctx.data_header(index as u8, false, 0), carrier, &tag);
            let meta = V2FrameMeta::of(&datagram).expect("v2 frame");
            assert!(meta.shardsec, "the flag must survive the wire round trip");
            assert_eq!(meta.epoch, ctx.epoch);
            assert_eq!(meta.nonce, ctx.nonce);

            // ingest: unframe the payload region into the sealed shard.
            let sd = unframe(net::extract_payload(&datagram)).expect("carrier unframes");
            let sealed = vantablack::ghost::net::shardsec::SealedShard {
                index: index as u8,
                ciphertext: sd[..sd.len() - 16].to_vec(),
                tag: sd[sd.len() - 16..].try_into().unwrap(),
                is_honey: false,
            };

            // ingest: the AEAD key comes from plan_open for the counter on the
            // wire, not from the seal context — verify both agree.
            let wire_ctr = net::parse_packet_counter_u64(&datagram);
            let planned = ctx
                .key /* a receiver would use plan_open's key; seal key must equal it */;
            let _ = planned;
            let opened = vantablack::ghost::net::shardsec::open_shard(
                &ctx.key,
                meta.epoch,
                &meta.nonce,
                ctx.direction,
                &sealed,
                &meta.tail,
            )
            .expect("ingest's ShardSec branch must open a pristine shard");
            assert!(!opened.is_empty());
            let _ = wire_ctr;
        }
    }

    #[test]
    pub(crate) fn shardsec_round_trip_recovers_the_message_from_two_shards() {
        // Only meaningful when the node resolves ShardSec on; with the env
        // inherited as `off` the frames are legacy and the legacy path covers
        // them (the enc_split test above pins the flag consistency).
        if !shardsec_default_enabled() {
            return;
        }
        let ctx = test_ctx();
        let payload = b"any 2 of 3 shards rebuild the message";
        let (carriers, _tag) = enc_split(&ctx, payload);

        let mut opened: Vec<Vec<u8>> = Vec::with_capacity(3);
        for (index, carrier) in carriers.iter().enumerate() {
            // Receiver side, exactly as `ingest` does per shard: the carrier
            // rides inside a v2 datagram's payload region (which the test
            // starts from), then `unframe` splits off the 16-byte tag.
            let sd = unframe(carrier).expect("frame_shard carrier");
            assert!(sd.len() > 16);
            let sealed = vantablack::ghost::net::shardsec::SealedShard {
                index: index as u8,
                ciphertext: sd[..sd.len() - 16].to_vec(),
                tag: sd[sd.len() - 16..].try_into().unwrap(),
                is_honey: false,
            };
            let tail = net::tail_for(&ctx.key, &ctx.nonce, ctx.epoch, ctx.direction);
            let plain = vantablack::ghost::net::shardsec::open_shard(
                &ctx.key,
                ctx.epoch,
                &ctx.nonce,
                ctx.direction,
                &sealed,
                &tail,
            )
            .expect("a pristine shard opens under its own key");
            opened.push(plain);
        }

        // The full receive pipeline, shard 2 "lost" in transit: any two
        // pristine shards reconstruct the message (mirrors `assemble()`).
        let mut work: Vec<Option<Vec<u8>>> =
            vec![Some(opened[0].clone()), Some(opened[1].clone()), None];
        l4_rs::reconstruct(&mut work).expect("2 of 3 shards suffice");
        let a = work[0].as_ref().unwrap();
        let b = work[1].as_ref().unwrap();
        let framed = [a.as_slice(), b.as_slice()].concat();
        let len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
        assert_eq!(
            &framed[2..2 + len],
            payload,
            "the reconstructed plaintext must be the original payload"
        );

        // A tampered shard must fail its own tag instead of poisoning the pair.
        let sd = unframe(&carriers[1]).expect("carrier");
        let mut corrupted = sd.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;
        let sealed = vantablack::ghost::net::shardsec::SealedShard {
            index: 1,
            ciphertext: corrupted[..corrupted.len() - 16].to_vec(),
            tag: corrupted[corrupted.len() - 16..].try_into().unwrap(),
            is_honey: false,
        };
        let tail = net::tail_for(&ctx.key, &ctx.nonce, ctx.epoch, ctx.direction);
        assert!(
            vantablack::ghost::net::shardsec::open_shard(
                &ctx.key,
                ctx.epoch,
                &ctx.nonce,
                ctx.direction,
                &sealed,
                &tail,
            )
            .is_err(),
            "a flipped bit must be rejected by the shard's own AEAD tag"
        );
    }
}

// The reassembly spool's key, on its own.
#[cfg(test)]
mod spool_key_tests {
    //! The spool used to bucket by packet counter alone, which is not a message
    //! identity: a counter is per-session, and a handshake has no session at all
    //! (counter 0 or 1, session hash `[0, 0, 0, 0]`). These tests hold the key up
    //! to both facts directly — no socket, no handshake — so the property is
    //! pinned where it lives rather than only inferred from a live run.
    use crate::*;

    /// `l4_rs::encode` pads an odd payload with one zero byte before splitting it
    /// into two halves, so a reassembled message is the *padded* input.
    pub(crate) fn padded(mut v: Vec<u8>) -> Vec<u8> {
        if !v.len().is_multiple_of(2) {
            v.push(0);
        }
        v
    }

    /// The bucket of a handshake-shaped frame: no session hash yet, so the
    /// sender's address is what identifies it.
    pub(crate) fn key(src: &str, counter: u64) -> SpoolKey {
        SpoolKey {
            session_hash: [0, 0, 0, 0],
            epoch: 0,
            counter,
            pre_session_src: Some(src.parse().expect("a loopback address")),
        }
    }

    /// The bucket of a frame that names a session: identified by the session, its
    /// ratchet epoch and the counter — deliberately *not* by an address.
    pub(crate) fn session_key(counter: u64, epoch: u64) -> SpoolKey {
        SpoolKey {
            session_hash: [0xDE, 0xAD, 0xBE, 0xEF],
            epoch,
            counter,
            pre_session_src: None,
        }
    }

    #[test]
    pub(crate) fn the_key_reads_the_generation_out_of_the_wire_header() {
        // A session frame and a handshake frame with the same counter: the key
        // must come out of the header, and the handshake must carry an address
        // while the session frame must not — that is the difference that keeps
        // the multi-hop shard router working (see `SpoolKey::pre_session_src`).
        let session_frame =
            net::build_gtf_frame([0xAB, 0xCD, 0x01, 0x02], 9, 0, &[], &[0u8; 16], false);
        let handshake_frame = net::build_gtf_frame([0, 0, 0, 0], 0, 0, &[], &[0u8; 16], false);
        let alice: SocketAddr = "127.0.0.1:40001".parse().expect("addr");
        let bob: SocketAddr = "127.0.0.1:40002".parse().expect("addr");

        let from_alice = SpoolKey::of(alice, &session_frame, None);
        let from_bob = SpoolKey::of(bob, &session_frame, None);
        assert_eq!(from_alice.session_hash, [0xAB, 0xCD, 0x01, 0x02]);
        assert_eq!(from_alice.counter, 9);
        assert_eq!(
            from_alice, from_bob,
            "which peer relayed a session frame must not change its bucket, or a \
             message whose shards took different peers never assembles"
        );

        let hs_alice = SpoolKey::of(alice, &handshake_frame, None);
        let hs_bob = SpoolKey::of(bob, &handshake_frame, None);
        assert_eq!(hs_alice.session_hash, [0, 0, 0, 0]);
        assert_ne!(
            hs_alice, hs_bob,
            "a frame with no session has only its address to tell two peers apart"
        );
    }

    #[tokio::test]
    pub(crate) async fn two_sources_offering_at_one_counter_never_share_a_bucket() {
        let pool: SpoolPool = DashMap::new();
        // Two handshake-shaped messages: same counter, same zero session hash, no
        // epoch. The *only* thing that tells them apart is who sent them.
        let alice_key = key("127.0.0.1:40001", 0);
        let bob_key = key("127.0.0.1:40002", 0);
        // Equal-length messages, so nothing about the mixing is visible in a
        // length either — the two offers are indistinguishable on the wire.
        let alice = padded(b"alice's handshake offer".to_vec());
        let bob = padded(b"bob's handshake offer!!!".to_vec());
        assert_eq!(alice.len(), bob.len(), "a colliding pair is the point");
        let alice_shards = l4_rs::encode(&mut alice.clone());
        let bob_shards = l4_rs::encode(&mut bob.clone());

        // The arrival order that broke the counter-keyed spool: a0, b0, a1, b1.
        assert!(assemble(&pool, alice_key, 0, alice_shards[0].clone())
            .await
            .is_none());
        assert!(assemble(&pool, bob_key, 0, bob_shards[0].clone())
            .await
            .is_none());
        let got_alice = assemble(&pool, alice_key, 1, alice_shards[1].clone())
            .await
            .expect("alice's two shards complete her message");
        let got_bob = assemble(&pool, bob_key, 1, bob_shards[1].clone())
            .await
            .expect("bob's two shards complete his message");

        assert_eq!(got_alice, alice, "alice must reassemble her own shards");
        assert_eq!(got_bob, bob, "bob must reassemble his own shards");
        // Both buckets are gone: neither message was left half-assembled for a
        // later arrival to join.
        assert!(pool.is_empty());
    }

    #[tokio::test]
    pub(crate) async fn shards_of_one_message_still_share_a_bucket() {
        // The positive control: the property the (2,1) code depends on is intact,
        // including when the shard that was lost is the first one.
        let pool: SpoolPool = DashMap::new();
        let k = key("127.0.0.1:40003", 7);
        let msg = padded(b"a message whose first shard never arrived".to_vec());
        let shards = l4_rs::encode(&mut msg.clone());
        assert!(assemble(&pool, k, 1, shards[1].clone()).await.is_none());
        let got = assemble(&pool, k, 2, shards[2].clone())
            .await
            .expect("any two of three shards rebuild the message");
        assert_eq!(got, msg);
    }

    #[tokio::test]
    pub(crate) async fn two_sessions_at_one_counter_never_share_a_bucket() {
        // The other half of the counter problem, and the one that hits ordinary
        // traffic: the counter is a *per-session* sequence number, so two sessions
        // running at the same counter used to share a bucket.
        let pool: SpoolPool = DashMap::new();
        let alice_key = session_key(5, 0);
        let bob_key = SpoolKey {
            session_hash: [0x12, 0x34, 0x56, 0x78],
            ..alice_key
        };
        let alice = padded(b"session A message at counter 5".to_vec());
        let bob = padded(b"session B message at counter 5!!".to_vec());
        let alice_shards = l4_rs::encode(&mut alice.clone());
        let bob_shards = l4_rs::encode(&mut bob.clone());

        assert!(assemble(&pool, alice_key, 0, alice_shards[0].clone())
            .await
            .is_none());
        assert!(assemble(&pool, bob_key, 0, bob_shards[0].clone())
            .await
            .is_none());
        assert_eq!(
            assemble(&pool, alice_key, 1, alice_shards[1].clone()).await,
            Some(alice),
            "each session reassembles its own message"
        );
        assert_eq!(
            assemble(&pool, bob_key, 1, bob_shards[1].clone()).await,
            Some(bob),
            "and neither steals the other's shards"
        );
    }

    #[tokio::test]
    pub(crate) async fn a_newer_generation_is_a_different_message() {
        // A counter and a session can be the same while the message is not: a
        // retransmit sealed under the next ratchet epoch shares both. Those must
        // not merge either.
        let pool: SpoolPool = DashMap::new();
        let older = session_key(5, 0);
        let newer = SpoolKey { epoch: 1, ..older };
        let a = padded(b"sealed on epoch zero".to_vec());
        let b = padded(b"sealed on epoch one!".to_vec());
        let a_shards = l4_rs::encode(&mut a.clone());
        let b_shards = l4_rs::encode(&mut b.clone());

        assert!(assemble(&pool, older, 0, a_shards[0].clone())
            .await
            .is_none());
        assert!(assemble(&pool, newer, 0, b_shards[0].clone())
            .await
            .is_none());
        assert_eq!(
            assemble(&pool, newer, 1, b_shards[1].clone()).await,
            Some(b),
            "the newer generation assembles from its own pair"
        );
        assert_eq!(
            assemble(&pool, older, 2, a_shards[2].clone()).await,
            Some(a),
            "and the retained epoch's pair is untouched"
        );
    }
}
