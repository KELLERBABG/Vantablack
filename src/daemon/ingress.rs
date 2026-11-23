//! daemon::ingress — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

/// Per-direction receive state: next expected counter + reorder buffer.
#[derive(Default)]
pub(crate) struct RxState {
    pub(crate) next: Option<u64>,
    pub(crate) buf: BTreeMap<u64, Vec<u8>>,
}

/// An active exit-side tunnel: decrypted remote data flows through `out_tx`.
pub(crate) struct ExitTunnel {
    pub(crate) out_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub(crate) rx: RxState,
    pub(crate) session_hash: [u8; 4],
}

pub(crate) type ExitTunnels = Arc<DashMap<String, ExitTunnel>>;
/// Initiator side: per-(session, stream) channel delivering decrypted exit data.
pub(crate) type SessionChannels = Arc<DashMap<([u8; 4], u32), mpsc::UnboundedSender<Vec<u8>>>>;
/// Initiator side: per-(session, stream) "CONNECT OK" flags.
pub(crate) type ConnectAcks = Arc<DashMap<([u8; 4], u32), bool>>;
/// Initiator side: the exit's OK counter per (session, stream) — anchors the reorder
/// buffer so out-of-order tunnel frames are buffered, not dropped.
pub(crate) type ConnectOkCtrs = Arc<DashMap<([u8; 4], u32), u64>>;
/// Initiator side: per-(session, stream) reorder state for exit data.
pub(crate) type RxStateMap = Arc<DashMap<([u8; 4], u32), RxState>>;

pub(crate) fn exit_tunnel_key(_src: &SocketAddr, sh: &[u8; 4], stream_id: u32) -> String {
    format!("{}|{}", hex::encode(sh), stream_id)
}

/// Direction our own sends take, given our role in the session.
pub(crate) fn dir_for(role: SessionRole) -> NonceDirection {
    match role {
        SessionRole::Initiator => NonceDirection::InitiatorToResponder,
        SessionRole::Responder => NonceDirection::ResponderToInitiator,
    }
}

/// True if the payload looks like a "host:port" SOCKS5 CONNECT destination
/// (optionally framed with STREAM!<stream_id>! or EXITAUTH!<voucher>!).
pub(crate) fn looks_like_dest(p: &[u8]) -> bool {
    let s = String::from_utf8_lossy(p);
    let target = if let Some(rest) = s.strip_prefix("STREAM!") {
        match rest.split_once('!') {
            Some((_sid, tgt)) => tgt,
            None => return false,
        }
    } else {
        &s
    };
    let target = if let Some(rest) = target.strip_prefix("EXITAUTH!") {
        match rest.split_once('!') {
            Some((_voucher, tgt)) => tgt,
            None => return false,
        }
    } else {
        target
    };
    match target.rsplit_once(':') {
        Some((h, port)) => !h.is_empty() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

// The tunnel egress path below is vpn-gated, so its encrypt helper carries the
// same cfg: to the default feature set the name is unused (an ungated import
// warns, and fails under `-D warnings`), while the vpn feature set must resolve
// it. Removing the import to silence the default build breaks the vpn build.
#[cfg(feature = "vpn")]
use vantablack::ghost::layers::l2_aead::encrypt_in_place_with_context;

#[cfg(feature = "vpn")]
/// Outer-wire send of a VPN payload: [len u16][GVPN1][tunnel datagram]
/// encrypted with the SESSION key (direction-bound nonce) and sent as ONE
/// bulk GTF frame with the tunnel flag set. Returns on missing session.
pub(crate) async fn send_tunnel_frame(
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
    if sess.is_v1_wire() {
        let ctr = sess.tx_counter.fetch_add(1, Ordering::Relaxed) as u32;
        let sh = sess.session_hash;
        let key = sess.master_key;
        let dir = sess.role.seal_direction();
        drop(sess);

        let mut payload = VPN_PAYLOAD_MAGIC.to_vec();
        payload.extend_from_slice(tunnel_wire);
        let mut framed = Vec::with_capacity(2 + payload.len() + 1 + 16);
        framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        framed.extend_from_slice(&payload);
        if framed.len() % 2 != 0 {
            framed.push(0);
        }
        encrypt_in_place_with_context(&key, ctr, &sh, dir, &mut framed);
        let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
        let framed = frame_shard(&framed);
        let mut frame = net::build_gtf_frame(sh, ctr, 0, &framed, &tag, true);
        frame[net::OFFSET_FLAGS] |= 0x02; // FLAG_TUNNEL
        tracing::info!(peer = %peer_fp, %endpoint, len = frame.len(), ctr, "VPN egress GTF frame sent to client");
        nc.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        nc.stats
            .bytes_sent
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
        let _ = nc.socket.send_to(&frame, endpoint).await;
        return;
    }
    // The epoch key and a fresh 96-bit nonce replace the counter-derived
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
    let mut framed = Vec::with_capacity(2 + payload.len() + 1 + 16);
    framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    framed.extend_from_slice(&payload);
    if framed.len() % 2 != 0 {
        framed.push(0);
    }
    xchacha_seal_in_place(&ctx.key, &ctx.nonce, ctx.epoch, ctx.direction, &mut framed)
        .expect("sealing an owned buffer cannot fail");
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
    // The bulk payload region holds a [len u16][bytes] shard (exactly what
    // frame_shard produces and the receive path's unframe() consumes).
    let framed = frame_shard(&framed);
    let frame = net::build_gtf_v2_frame(&ctx.header(0, true, net::FLAG_TUNNEL), &framed, &tag);
    nc.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
    nc.stats
        .bytes_sent
        .fetch_add(frame.len() as u64, Ordering::Relaxed);
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
        Some(FallbackPath::Skywave { nvis_freq_khz }) => {
            tracing::debug!(
                peer = %peer_fp,
                freq_khz = nvis_freq_khz,
                "VPN egress: routing tunnel packet across Skywave NVIS carrier"
            );
            if let Some(bridge) = net::sdr_bridge::SkywaveBridge::global() {
                if let Err(e) = bridge.transmit(&frame).await {
                    tracing::warn!(
                        peer = %peer_fp,
                        error = %e,
                        "VPN egress: skywave transmit failed — frame dropped"
                    );
                }
            } else {
                tracing::warn!(peer = %peer_fp, "VPN egress: skywave route with no bridge — frame dropped");
            }
        }
        Some(FallbackPath::Masque { peer }) => {
            // A MASQUE stream to the peer is a direct path; if it closed between
            // the route being chosen and this send, fall back to the socket
            // rather than dropping the frame.
            if !super::try_send_masque(&peer, &frame) {
                let _ = super::srtp::send_raw(&nc.socket, &endpoint, &frame).await;
            }
        }
        Some(FallbackPath::Direct) | None => {
            let _ = super::srtp::send_raw(&nc.socket, &endpoint, &frame).await;
        }
    }
}

/// Strip the 2-byte length prefix (plus optional parity pad) from a decrypted frame.
pub(crate) fn frame_payload(pt: &[u8]) -> Option<&[u8]> {
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
pub(crate) struct RxContext {
    pub(crate) node: Arc<GhostNode>,
    pub(crate) peers: Arc<DashMap<String, SocketAddr>>,
    pub(crate) spool: Arc<SpoolPool>,
    pub(crate) pending_hs: PendingHandshakes,
    pub(crate) revocation_list: Arc<RevocationList>,
    pub(crate) reputation: Arc<PoissonReputationMatrix>,
    pub(crate) vpn: Option<VpnMode>,
    pub(crate) exit_tunnels: ExitTunnels,
    pub(crate) sessions_rx: SessionChannels,
    pub(crate) rx_state_map: RxStateMap,
    pub(crate) connect_acks: ConnectAcks,
    pub(crate) connect_ok_ctrs: ConnectOkCtrs,
    pub(crate) trusted_exits: Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
    pub(crate) psk: Option<[u8; 32]>,
    pub(crate) tft: Arc<TitForTatEnforcer>,
    pub(crate) rotator: Option<Arc<ExitIpRotator>>,
    pub(crate) relay_role: Option<Arc<DerpRelay>>,
    /// Which peers need a relay, and the allocation that carries them.
    pub(crate) fallback: Option<Arc<Fallback>>,
    pub(crate) dispatcher: Arc<net::dispatcher::LocklessDispatcher>,
    /// The socket replies leave from. For a datagram the TURN server relayed to us
    /// this is still the mesh socket: the peer reached us through the relay, so its
    /// next frame arrives the same way, and the data path back to it is routed by
    /// the fallback table rather than by this address.
    pub(crate) socket: Arc<UdpSocket>,
    /// True while the user has the mesh activated in the control center.
    pub(crate) connected: Arc<std::sync::atomic::AtomicBool>,
    /// NAT hole-puncher for installing ICE offers received via PEX v2.
    pub(crate) nat_puncher: Option<Arc<vantablack::ghost::net::mesh::NatHolePuncher>>,
    /// Verified v2 peer descriptors learned from cache, mailbox, or PEX v2.
    pub(crate) known_descriptors:
        Option<Arc<DashMap<String, vantablack::ghost::net::discovery::PeerDescriptorV2>>>,
}

impl RxContext {
    /// Pipe one received datagram into the tunnel.
    pub(crate) async fn ingest(&self, datagram: &[u8], src: SocketAddr) {
        if !self.connected.load(Ordering::Relaxed) {
            return;
        }
        // SRTP carrier: a datagram shaped as RTP is unwrapped before anything
        // else reads it, so a frame carried inside media is indistinguishable
        // downstream from one that arrived plain. The unwrap is validated by an
        // inner GTFv2 parse, so plain traffic is never reinterpreted.
        let datagram = super::srtp::unshape_if_shaped(datagram).unwrap_or(datagram);
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
        // The frame is decoded through the *version-aware* extractors.
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
                // Emergency diffusion (`exp_diffusion`): an envelope is handled
                // before anything else reads the payload, and `handle` returns
                // `true` only when it really was one.
                if super::tunnel::handle(self, &sd, src).await {
                    return;
                }
                if super::diffusion::handle(self, &sd, src).await {
                    return;
                }
                self.deliver(ctr, v2, sd, src, None).await;
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
                    is_honey: false,
                }
            };
            // All shards of one message share ONE wire counter (they are pieces
            // of one AEAD ciphertext under one seal), so a shard is *opened*
            // with the chain's key for that counter but must NOT consume a
            // chain position per shard — committing on every shard would make
            // shards 1 and 2 look like replays of counter 0 and fail their own
            // tags. The single commit happens per assembled message in
            // `handle_pkt`'s ShardSec branch (see `wire_session_hash`).
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
                        &key,
                        meta.epoch,
                        &meta.nonce,
                        direction,
                        &sealed,
                        &meta.tail,
                    ) {
                        // Deliberately NO `sess.commit_open` here — see the
                        // comment above. The message-level commit in
                        // `handle_pkt` advances the chain exactly once.
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
            if let Some(r) = assemble(
                &self.spool,
                SpoolKey::of(src, datagram, v2),
                si,
                plain_shard,
            )
            .await
            {
                if super::tunnel::handle(self, &r, src).await {
                    return;
                }
                if super::diffusion::handle(self, &r, src).await {
                    return;
                }
                self.deliver(ctr, v2, r, src, Some(net::parse_session_hash(datagram)))
                    .await;
            }
            return;
        }
        // This path runs concurrently: `assemble` is what decides which of the (up
        // to) three carriers completes a frame, and it takes the reconstructed
        // ciphertext forward exactly once.
        if let Some(r) = assemble(&self.spool, SpoolKey::of(src, datagram, v2), si, sd).await {
            if std::env::var("GGN_DEBUG_RX").is_ok() {
                tracing::info!("assembled frame ctr={ctr} si={si} len={}", r.len());
            }
            if super::tunnel::handle(self, &r, src).await {
                return;
            }
            if super::diffusion::handle(self, &r, src).await {
                return;
            }
            // The legacy path's frames were opened by `open_received_frame` at
            // the candidates loop, but the hash still names the session; keep
            // the wire value so both modes behave identically downstream.
            self.deliver(ctr, v2, r, src, Some(net::parse_session_hash(datagram)))
                .await;
        } else if std::env::var("GGN_DEBUG_RX").is_ok() {
            tracing::info!("assemble dropped ctr={ctr} si={si}");
        }
    }

    /// Hand a decrypted-frame candidate to `handle_pkt` on its own task.
    ///
    /// Spawned rather than awaited: `handle_pkt` can block on session locks and
    /// tunnel writes, and the receive loop must stay able to read the socket while
    /// that happens.
    pub(crate) async fn deliver(
        &self,
        ctr: u64,
        v2: Option<V2FrameMeta>,
        payload: Vec<u8>,
        src: SocketAddr,
        // The session hash **as it arrived on the wire**, parsed from the raw
        // datagram in `ingest`. Downstream, `data` is already-opened plaintext,
        // so `parse_session_hash(data)` would read garbage — which is exactly
        // what silently disabled the ShardSec branch of `handle_pkt` until the
        // wire hash was threaded through here.
        wire_session_hash: Option<[u8; 4]>,
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
        let nat_puncher = self.nat_puncher.clone();
        let known_descriptors = self.known_descriptors.clone();
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
                wire_session_hash,
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
                nat_puncher.as_ref(),
                known_descriptors.as_ref(),
            )
            .await;
        });
    }
}

pub(crate) const MAX_REORDER_BUF: usize = 32;
pub(crate) const MAX_REORDER_GAP: u64 = 64;

pub(crate) fn rx_push(state: &mut RxState, ctr: u64, payload: Vec<u8>) -> Vec<Vec<u8>> {
    let Some(next) = state.next else {
        state.next = Some(ctr + 1);
        return vec![payload];
    };
    if ctr < next {
        return Vec::new();
    }
    state.buf.insert(ctr, payload);
    if state.buf.len() >= MAX_REORDER_BUF || ctr.saturating_sub(next) >= MAX_REORDER_GAP {
        if let Some(&first_available) = state.buf.keys().next() {
            if first_available > next {
                state.next = Some(first_available);
            }
        }
    }
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
