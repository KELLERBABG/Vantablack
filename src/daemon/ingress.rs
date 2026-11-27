//! daemon::ingress — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

#[derive(Default)]
pub(crate) struct RxState {
    pub(crate) next: Option<u64>,
    pub(crate) buf: BTreeMap<u64, Vec<u8>>,
}

pub(crate) struct ExitTunnel {
    pub(crate) out_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub(crate) rx: RxState,
    pub(crate) session_hash: [u8; 4],
}

pub(crate) type ExitTunnels = Arc<DashMap<String, ExitTunnel>>;
pub(crate) type SessionChannels = Arc<DashMap<([u8; 4], u32), mpsc::UnboundedSender<Vec<u8>>>>;
pub(crate) type ConnectAcks = Arc<DashMap<([u8; 4], u32), bool>>;
pub(crate) type ConnectOkCtrs = Arc<DashMap<([u8; 4], u32), u64>>;
pub(crate) type RxStateMap = Arc<DashMap<([u8; 4], u32), RxState>>;

pub(crate) fn exit_tunnel_key(_src: &SocketAddr, sh: &[u8; 4], stream_id: u32) -> String {
    format!("{}|{}", hex::encode(sh), stream_id)
}

pub(crate) fn dir_for(role: SessionRole) -> NonceDirection {
    match role {
        SessionRole::Initiator => NonceDirection::InitiatorToResponder,
        SessionRole::Responder => NonceDirection::ResponderToInitiator,
    }
}

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

#[cfg(feature = "vpn")]
use vantablack::ghost::layers::l2_aead::encrypt_in_place_with_context;

#[cfg(feature = "vpn")]
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
    let ctx = SealCtx::from_session(&sess);
    drop(sess);
    if ctx.ratchet_due {
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
    let framed = frame_shard(&framed);
    let frame = net::build_gtf_v2_frame(&ctx.header(0, true, net::FLAG_TUNNEL), &framed, &tag);
    nc.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
    nc.stats
        .bytes_sent
        .fetch_add(frame.len() as u64, Ordering::Relaxed);
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
            if !super::try_send_masque(&peer, &frame) {
                let _ = super::srtp::send_raw(&nc.socket, &endpoint, &frame).await;
            }
        }
        Some(FallbackPath::Direct) | None => {
            let _ = super::srtp::send_raw(&nc.socket, &endpoint, &frame).await;
        }
    }
}

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
    pub(crate) fallback: Option<Arc<Fallback>>,
    pub(crate) dispatcher: Arc<net::dispatcher::LocklessDispatcher>,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) connected: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) nat_puncher: Option<Arc<vantablack::ghost::net::mesh::NatHolePuncher>>,
    pub(crate) known_descriptors:
        Option<Arc<DashMap<String, vantablack::ghost::net::discovery::PeerDescriptorV2>>>,
}

impl RxContext {
    pub(crate) async fn ingest(&self, datagram: &[u8], src: SocketAddr) {
        if !self.connected.load(Ordering::Relaxed) {
            return;
        }
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
        let _ = self.dispatcher.dispatch(datagram, src);
        let ctr = net::parse_packet_counter_u64(datagram);
        let v2 = V2FrameMeta::of(datagram);
        if net::parse_flags(datagram) & net::FLAG_TUNNEL != 0 {
            if let Some(sd) = unframe(net::extract_payload(datagram)) {
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
            self.deliver(ctr, v2, r, src, Some(net::parse_session_hash(datagram)))
                .await;
        } else if std::env::var("GGN_DEBUG_RX").is_ok() {
            tracing::info!("assemble dropped ctr={ctr} si={si}");
        }
    }

    pub(crate) async fn deliver(
        &self,
        ctr: u64,
        v2: Option<V2FrameMeta>,
        payload: Vec<u8>,
        src: SocketAddr,
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
