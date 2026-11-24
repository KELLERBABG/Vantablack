//! daemon::relay_fallback — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

/// Global per-source-IP WAN rate limiter for `ctr == 0` handshakes, beacons, and STUN (C4).
pub(crate) fn wan_rate_limiter() -> &'static vantablack::ghost::net::relay::WanRateLimiter {
    static LIMITER: std::sync::OnceLock<vantablack::ghost::net::relay::WanRateLimiter> =
        std::sync::OnceLock::new();
    LIMITER.get_or_init(vantablack::ghost::net::relay::WanRateLimiter::default)
}

/// How a message actually left this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Routed {
    Direct,
    /// The optional transport carried it.
    ///
    /// Distinct from `Direct` because it is a different carrier over the same
    /// measured path: QUIC's own loss recovery and congestion control carry the
    /// frames instead of the UDP shard path.
    Carrier,
    /// The HPEB bond carried a carrier per physical interface (Phase 5).
    ///
    /// Distinct from both `Direct` and `Carrier`: the frames left from separate
    /// sockets pinned to separate interfaces, so the redundancy is physical rather
    /// than a property of one link's recovery.
    Bonded,
    MeshRelay,
    Turn,
    /// The atmospheric ionospheric skywave carrier (ABOS) carried it.
    Skywave,
    /// The peer's own HTTP/3 MASQUE endpoint carried it (Phase 4).
    Masque,
    /// No session with the chosen relay, or no allocation: nothing carried it.
    Unroutable,
}

/// Hand one already-built GTF datagram to a relay peer, wrapped in a blind
/// envelope addressed to `target_fp` (B22).
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
pub(crate) async fn send_datagram_via_relay(
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
    // One seal snapshot per forward, shared by whichever framing the
    // envelope needs — a single bulk frame or three bulk shards of one ciphertext.
    let ctx = SealCtx::from_session(&sess);
    drop(sess);

    if envelope.len() + 2 <= net::V2_MAX_BULK_PAYLOAD_LEN {
        let frame = seal_single(&ctx, &envelope);
        return match super::srtp::send_raw(sock, relay_addr, &frame).await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(relay = %relay_fp, "fallback: relay send failed: {e}");
                false
            }
        };
    }

    let (carriers, tag) = enc_split(&ctx, &envelope);
    let mut ok = true;
    for (i, carrier) in carriers.iter().take(3).enumerate() {
        let header = ctx.data_header(i as u8, true, 0);
        if let Err(e) = super::srtp::send_v2(sock, relay_addr, &header, carrier, &tag).await {
            tracing::warn!(relay = %relay_fp, "fallback: relay send failed: {e}");
            ok = false;
        }
    }
    ok
}

/// Send 3 RS shards using adaptive multi-path routing when alternative peer routes exist.
///
/// `route` is the peer's fallback when it has no direct path. When it
/// is set, multi-path selection is skipped — deliberately. The carriers must all
/// travel the one route the relay carries, and spreading them across *other*
/// peers would send them to machines that hold no session with the target.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send3_adaptive(
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
    // The optional transport, when this build and this run have one.
    carrier: Option<&Arc<net::carrier::Carrier>>,
) -> Routed {
    vantablack::ghost::v2::racs::note_real_sent();
    if ctx.ratchet_due {
        // Due, not broken: the epoch is full and the *next* step is
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
        // A REALITY front stream reaches the peer itself over TLS, so it is a
        // direct path: relaying frames it could carry would add a third party to
        // a path that does not need one. The route entry stays in the table — it
        // is what the peer falls back to if the stream closes.
        if !carried_by_front(primary_dst, &ctx.session_hash) {
            return send3_via_fallback(nc, sock, primary_fp, ctx, f, tag, path, turn).await;
        }
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
    // Resolve primary_fp's direct destination without scattering shards
    // encrypted under primary_fp's session key to unrelated peers (A3 Phase 1).
    let target_addr = if primary_dst.port() != 0 {
        *primary_dst
    } else {
        all_peers
            .get(primary_fp)
            .map(|entry| *entry.value())
            .unwrap_or(*primary_dst)
    };
    // HPEB (Phase 5): with two or more interfaces bound, the three carriers leave
    // by separate paths instead of one. The carriers are the same bytes this
    // function would otherwise send, so a peer's spool rebuilds them exactly as
    // it does for a single-socket send.
    if f.len() >= 3 {
        let frames: Vec<Vec<u8>> = (0..3)
            .map(|i| net::build_gtf_v2_frame(&ctx.data_header(i as u8, false, 0), &f[i], tag))
            .collect();
        // The shard stamps the port the mesh socket is really bound to, so the
        // peer's reply reaches this node even on a dynamic or port-0 bind.
        let src_port = super::bonding::mesh_local_port(&nc.socket);
        if let Some(carried) =
            super::bonding::send_carriers(primary_fp, target_addr, &frames, src_port).await
        {
            tracing::debug!(
                peer = %primary_fp,
                interfaces = %carried.join(","),
                "HPEB: carriers sent over separate interfaces"
            );
            return Routed::Bonded;
        }
    }
    let _ = plan;
    let _fitness = router.path_fitness(primary_fp);
    // A3 Phase 2: Divergent Multi-Carrier RS Sharding.
    // When GHOST_DIVERGENT_SHARDS=1 and at least 2 distinct healthy carrier peers
    // have live sessions, send shard 0 directly to primary_fp and wrap shards 1 & 2
    // in BLND! envelopes addressed to primary_fp via two distinct carriers.
    let divergent_enabled = std::env::var("GHOST_DIVERGENT_SHARDS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if divergent_enabled && f.len() >= 3 {
        let mut carriers: Vec<(String, SocketAddr)> = all_peers
            .iter()
            .filter(|e| {
                let fp = e.key().as_str();
                fp != primary_fp
                    && fp != me
                    && nc.sessions.contains_key(fp)
                    && router.path_fitness(fp) >= 0.3
            })
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        carriers.sort_by(|a, b| a.0.cmp(&b.0));
        if carriers.len() >= 2 {
            let _ = super::srtp::send_v2(
                sock,
                &target_addr,
                &ctx.data_header(0, false, 0),
                &f[0],
                tag,
            )
            .await;
            for (shard_idx, (carrier_fp, carrier_addr)) in
                [(1usize, &carriers[0]), (2usize, &carriers[1])]
            {
                let datagram = net::build_gtf_v2_frame(
                    &ctx.data_header(shard_idx as u8, false, 0),
                    &f[shard_idx],
                    tag,
                );
                if !send_datagram_via_relay(
                    nc,
                    sock,
                    carrier_fp,
                    carrier_addr,
                    primary_fp,
                    &datagram,
                )
                .await
                {
                    let _ = super::srtp::send_v2(
                        sock,
                        &target_addr,
                        &ctx.data_header(shard_idx as u8, false, 0),
                        &f[shard_idx],
                        tag,
                    )
                    .await;
                }
            }
            return Routed::Direct;
        }
    }
    let routes = router.assign_shards_to_primary(primary_fp, f.len());
    let mut disjoint_constraint = net::orbit::DisjointRouteConstraint::new();

    if sock.local_addr().ok() == nc.socket.local_addr().ok() {
        // Long-lived node-owned socket: preserve the cross-message mix queue
        // while delivering all 3 RS shards strictly to primary_fp.
        send3_mixed(Arc::clone(&nc.socket), &target_addr, ctx, f, tag).await;
    } else {
        for route in routes {
            let idx = route.shard_index as usize;
            if idx >= f.len()
                || !disjoint_constraint.reserve_plane(net::orbit::OrbitalPlane::Ground)
            {
                continue;
            }
            if let Err(error) = super::srtp::send_v2(
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
    }
    Routed::Direct
}

/// Whether a REALITY front stream already carries this peer.
///
/// Always `false` without the feature, so a build that has no front keeps the
/// routing it had: a fallback route is used whenever one is recorded.
fn carried_by_front(dst: &SocketAddr, session: &[u8; 4]) -> bool {
    if super::masque_carries(dst, session) {
        return true;
    }
    #[cfg(feature = "reality-front")]
    {
        super::reality_front::carries(dst, session)
    }
    #[cfg(not(feature = "reality-front"))]
    {
        let _ = (dst, session);
        false
    }
}

/// Ship the three RS carriers over the optional transport, spread across every
/// live local path (B23).
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
pub(crate) async fn send3_via_carrier(
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

/// Build the optional-transport registry.
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
pub(crate) fn build_carrier(nc: &Arc<GhostNode>) -> Arc<net::carrier::Carrier> {
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
    let carrier =
        match vantablack::ghost::net::quic::QuicTransport::listen(bind, Arc::clone(&nc.identity)) {
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
        tracing::info!(
            paths = added,
            "QUIC: multipath enabled; shards spread across local paths"
        );
    }
    carrier
}

/// A build with no optional transport compiled in.
#[cfg(not(feature = "quic"))]
pub(crate) fn build_carrier(_nc: &Arc<GhostNode>) -> Arc<net::carrier::Carrier> {
    Arc::new(net::carrier::Carrier::disabled())
}

/// The QUIC ingress + dial tasks, spawned where the receive pipeline lives.
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

pub(crate) use spawn_carrier_tasks;

/// Peers an operator declares reachable *only* over the skywave carrier.
///
/// A comma-separated list of fingerprints. A declaration rather than a
/// measurement: a pinned peer is never checked, and its route is never cleared,
/// because the reason for the declaration — an RF-only site, a severed IP path,
/// a link that must not be used — does not go away when a candidate pair
/// happens to answer.
pub const SKYWAVE_ONLY_ENV: &str = "GHOST_SKYWAVE_ONLY";

/// How many hex digits a fingerprint has: first 8 bytes of an identity key.
pub(crate) const FINGERPRINT_HEX_LEN: usize = 16;

/// Split a [`SKYWAVE_ONLY_ENV`] value into accepted fingerprints and entries
/// that cannot name a peer, returned as `(accepted, rejected)`.
///
/// Anything that is not 16 hex digits is reported rather than ignored: a typo
/// that silently pinned nothing would leave an operator believing the peer is
/// on the radio when it is not.
pub fn parse_skywave_only(spec: &str) -> (Vec<String>, Vec<String>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for raw in spec.split(',') {
        let fp = raw.trim().to_ascii_lowercase();
        if fp.is_empty() {
            continue;
        }
        if fp.len() == FINGERPRINT_HEX_LEN && fp.bytes().all(|b| b.is_ascii_hexdigit()) {
            accepted.push(fp);
        } else {
            rejected.push(fp);
        }
    }
    (accepted, rejected)
}

/// The route a radio-only declaration resolves to: the fallback ladder, asked
/// with every terrestrial rung withheld (no relay candidates, no TURN
/// allocation).
///
/// Deliberately the same ladder a failed direct check calls, so an operator can
/// only ever *pre-empt* its answer — never record a route the ladder would not
/// itself have chosen. `None` means the ladder has nothing to offer this peer,
/// which here means the skywave rung is unarmed.
pub(crate) fn skywave_only_route(
    our_fp: &str,
    peer_fp: &str,
    nvis_freq_khz: Option<u32>,
) -> Option<FallbackPath> {
    fallback::choose_fallback_with_skywave(our_fp, peer_fp, &[], None, nvis_freq_khz)
        .filter(|path| matches!(path, FallbackPath::Skywave { .. }))
}

/// Apply the declarations in `spec` to the route table, returning how many took
/// effect.
///
/// A declaration that cannot be honoured is refused out loud and changes
/// nothing: a peer cannot be pinned to a carrier that is not running, and
/// recording the route anyway would black-hole every frame addressed to it.
pub(crate) fn install_skywave_only(
    pinned: &DashSet<String>,
    routes: &Fallback,
    our_fp: &str,
    spec: &str,
    nvis_freq_khz: Option<u32>,
) -> usize {
    let (accepted, rejected) = parse_skywave_only(spec);
    for value in rejected {
        tracing::warn!(
            value = %value,
            "{SKYWAVE_ONLY_ENV} entry is not a 16-digit hex fingerprint — ignored"
        );
    }
    let mut applied = 0;
    for peer_fp in accepted {
        match skywave_only_route(our_fp, &peer_fp, nvis_freq_khz) {
            Some(path) => {
                if routes.set(&peer_fp, path.clone()) {
                    pinned.insert(peer_fp.clone());
                    applied += 1;
                    tracing::info!(
                        peer = %peer_fp,
                        path = %path.label(),
                        freq_khz = nvis_freq_khz.unwrap_or(0),
                        "{SKYWAVE_ONLY_ENV}: peer pinned to the skywave carrier — no direct, \
                         relay or TURN route may carry it"
                    );
                }
            }
            None => tracing::warn!(
                peer = %peer_fp,
                "{SKYWAVE_ONLY_ENV} names a peer, but the fallback ladder cannot offer it the \
                 skywave rung (is the carrier armed? GHOST_SKYWAVE=1) — no route pinned"
            ),
        }
    }
    applied
}

/// Ship the three carriers to a peer whose direct checks failed.
///
/// One datagram per carrier, each inside its own envelope: the relay forwards
/// datagrams it cannot read, and the target reassembles the three it receives
/// into the same ciphertext a direct send would have produced.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send3_via_fallback(
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
    for (i, shard) in f.iter().take(3).enumerate() {
        let datagram = net::build_gtf_v2_frame(&ctx.data_header(i as u8, false, 0), shard, tag);
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
            FallbackPath::Masque { peer } => {
                // A MASQUE stream to the peer itself. If it closed between the
                // route being chosen and this send, the shard is not carried and
                // the caller reports the route unroutable rather than silently
                // claiming delivery.
                super::try_send_masque(peer, &datagram)
            }
            FallbackPath::Skywave { nvis_freq_khz } => {
                tracing::info!(
                    peer = %target_fp,
                    freq_khz = nvis_freq_khz,
                    "fallback: routing datagram across Skywave NVIS carrier"
                );
                // In-simulation carrier: the frame enters the bridge (full ABOS
                // DSP chain under `--features sdr`, virtual UDP carrier otherwise).
                match net::sdr_bridge::SkywaveBridge::global() {
                    Some(bridge) => match bridge.process_and_send(&datagram).await {
                        Ok(_) => true,
                        Err(e) => {
                            tracing::warn!(
                                peer = %target_fp,
                                error = %e,
                                "fallback: skywave transmit failed — datagram dropped"
                            );
                            false
                        }
                    },
                    None => {
                        tracing::warn!(
                            peer = %target_fp,
                            "fallback: skywave route selected but no bridge is running"
                        );
                        false
                    }
                }
            }
        };
        shipped &= ok;
    }
    if !shipped {
        return Routed::Unroutable;
    }
    match path {
        FallbackPath::MeshRelay { .. } => Routed::MeshRelay,
        FallbackPath::Turn { .. } => Routed::Turn,
        FallbackPath::Skywave { .. } => Routed::Skywave,
        FallbackPath::Masque { .. } => Routed::Masque,
        FallbackPath::Direct => Routed::Unroutable,
    }
}

#[cfg(test)]
mod skywave_only_tests {
    //! `GHOST_SKYWAVE_ONLY`: a declaration that a peer has no usable IP path.
    //!
    //! The invariant under test is that the declaration is resolved *through the
    //! ladder* with the terrestrial rungs withheld, so it can only pre-empt the
    //! answer a total direct/relay/TURN failure would have produced — and that a
    //! declaration which cannot be honoured is refused rather than recorded.
    use crate::*;

    #[test]
    pub(crate) fn only_a_sixteen_digit_hex_fingerprint_names_a_peer() {
        let (accepted, rejected) =
            parse_skywave_only(" aabbccddeeff0011 , deadbeef, 00ff00ff00ff00ff ");
        assert_eq!(accepted, vec!["aabbccddeeff0011", "00ff00ff00ff00ff"]);
        assert_eq!(
            rejected,
            vec!["deadbeef"],
            "a short prefix is a typo, not a peer: it must be reported, never silently ignored"
        );

        // Case is not significant (fingerprints are lower-case hex on the wire),
        // an empty list declares nothing, and an empty entry is not an error.
        let (accepted, rejected) = parse_skywave_only("AABBCCDDEEFF0011,,  ");
        assert_eq!(accepted, vec!["aabbccddeeff0011"]);
        assert!(rejected.is_empty());
        assert!(parse_skywave_only("").0.is_empty());

        // Non-hex of the right length cannot be a fingerprint either.
        let (accepted, rejected) = parse_skywave_only("gggggggggggggggg");
        assert!(accepted.is_empty());
        assert_eq!(rejected.len(), 1);
    }

    #[test]
    pub(crate) fn the_declaration_resolves_to_the_ladder_s_skywave_rung() {
        // Armed carrier, no relay candidate and no TURN allocation: the third and
        // last rung is the only one left, which is exactly the state a total
        // direct/relay/TURN failure leaves the ladder in.
        assert_eq!(
            skywave_only_route("aaaa0000aaaa0000", "bbbb1111bbbb1111", Some(5350)),
            Some(FallbackPath::Skywave {
                nvis_freq_khz: 5350
            })
        );
        // An unarmed carrier is not a route: the peer cannot be pinned to a radio
        // that is not running, and the caller must say so out loud.
        assert_eq!(
            skywave_only_route("aaaa0000aaaa0000", "bbbb1111bbbb1111", None),
            None
        );
    }

    #[test]
    pub(crate) fn an_applied_declaration_pins_the_route_and_is_remembered() {
        let pinned: DashSet<String> = DashSet::new();
        let routes = Fallback::new(None);
        let applied = install_skywave_only(
            &pinned,
            &routes,
            "aaaa0000aaaa0000",
            "bbbb1111bbbb1111, CCCC2222CCCC2222, nope",
            Some(5350),
        );
        assert_eq!(applied, 2, "the short entry must not be pinned");
        assert!(pinned.contains("bbbb1111bbbb1111"));
        assert!(pinned.contains("cccc2222cccc2222"));
        assert_eq!(
            routes.path("bbbb1111bbbb1111"),
            Some(FallbackPath::Skywave {
                nvis_freq_khz: 5350
            })
        );

        // With the carrier unarmed nothing is pinned and, crucially, no route is
        // written: a route the ladder cannot serve would black-hole the peer.
        let pinned: DashSet<String> = DashSet::new();
        let routes = Fallback::new(None);
        assert_eq!(
            install_skywave_only(
                &pinned,
                &routes,
                "aaaa0000aaaa0000",
                "bbbb1111bbbb1111",
                None
            ),
            0
        );
        assert!(routes.path("bbbb1111bbbb1111").is_none());
        assert!(pinned.is_empty());
    }
}

#[cfg(test)]
mod wan_core_unit_tests {
    use crate::*;

    #[test]
    pub(crate) fn public_mode_fails_closed_on_trusted_exits_by_default() {
        // Public mode with no explicit GHOST_EXIT / GHOST_EXIT_ALLOWLIST must NOT insert "any".
        let (is_exit, exits) = resolve_trusted_exits("public", false, false, None);
        assert!(!is_exit);
        assert!(exits.is_empty());

        // Public mode with explicit GHOST_EXIT=1 opens exit.
        let (is_exit, exits) = resolve_trusted_exits("public", true, false, None);
        assert!(is_exit);
        assert!(exits.contains("any"));

        // Public mode with explicit allowlist only permits the allowlisted fingerprints.
        let (is_exit, exits) = resolve_trusted_exits("public", false, false, Some("fp1, fp2"));
        assert!(!is_exit);
        assert!(!exits.contains("any"));
        assert!(exits.contains("fp1"));
        assert!(exits.contains("fp2"));

        // Private/LAN mode preserves default open exit unless explicitly disabled.
        let (is_exit, exits) = resolve_trusted_exits("private", false, false, None);
        assert!(is_exit);
        assert!(exits.contains("any"));

        // Explicit off always disables exit even in private mode.
        let (is_exit, exits) = resolve_trusted_exits("private", false, true, None);
        assert!(!is_exit);
        assert!(exits.is_empty());
    }

    #[tokio::test]
    pub(crate) async fn send3_adaptive_delivers_all_3_shards_to_primary_fp_with_3_peers() {
        let nc = Arc::new(GhostNode::new("127.0.0.1:0").await.unwrap());
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer2_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer3_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let primary_addr = primary_sock.local_addr().unwrap();
        let peer2_addr = peer2_sock.local_addr().unwrap();
        let peer3_addr = peer3_sock.local_addr().unwrap();

        let all_peers: Arc<DashMap<String, SocketAddr>> = Arc::new(DashMap::new());
        all_peers.insert("primary_fp".to_string(), primary_addr);
        all_peers.insert("peer2_fp".to_string(), peer2_addr);
        all_peers.insert("peer3_fp".to_string(), peer3_addr);

        let router = vantablack::ghost::net::mesh::AdaptiveShardRouter::new();
        let ctx = SealCtx {
            key: [0x11; 32],
            epoch: 0,
            counter: 42,
            nonce: [0x22; 12],
            direction: NonceDirection::InitiatorToResponder,
            session_hash: [0xAA, 0xBB, 0xCC, 0xDD],
            ratchet_due: false,
        };
        let (shards, tag) = enc_split(&ctx, b"hello primary_fp");

        let routed = send3_adaptive(
            &nc,
            &send_sock,
            &primary_addr,
            "primary_fp",
            &ctx,
            &shards,
            &tag,
            &router,
            &all_peers,
            None,
            "me_fp",
            None,
            None,
            None,
        )
        .await;
        assert_eq!(routed, Routed::Direct);

        let mut received_indices = Vec::new();
        let mut buf = [0u8; 2048];
        for _ in 0..3 {
            let (amt, _) =
                tokio::time::timeout(Duration::from_secs(1), primary_sock.recv_from(&mut buf))
                    .await
                    .expect("primary_fp must receive all 3 shards")
                    .unwrap();
            assert!(amt >= net::MIN_FRAME_SIZE);
            received_indices.push(buf[net::OFFSET_SHARD_INDEX]);
        }
        received_indices.sort();
        assert_eq!(received_indices, vec![0, 1, 2]);

        // Unrelated peers must receive zero shards.
        assert!(
            tokio::time::timeout(Duration::from_millis(80), peer2_sock.recv_from(&mut buf))
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(80), peer3_sock.recv_from(&mut buf))
                .await
                .is_err()
        );
    }

    #[test]
    pub(crate) fn relay_beacon_port_section_overrides_ephemeral_source_port() {
        let identity = l0_identity::GhostIdentity::generate_fresh();
        let pk = identity.public_key_bytes();
        let pkt = build_beacon_packet(
            &pk,
            |d| identity.sign(d).to_bytes(),
            None,
            None,
            true,
            None,
            Some(55225),
        );
        let sections = parse_beacon_sections(&pkt, pkt.len()).expect("valid sectioned beacon");
        assert!(sections.relay_capable);
        assert_eq!(sections.mesh_port, Some(55225));
        let ephemeral_src: SocketAddr = "203.0.113.10:49876".parse().unwrap();
        let resolved = sections
            .mesh_port
            .filter(|&p| p != 0)
            .map(|p| SocketAddr::new(ephemeral_src.ip(), p))
            .unwrap_or(ephemeral_src);
        assert_eq!(
            resolved,
            "203.0.113.10:55225".parse::<SocketAddr>().unwrap()
        );
    }
}
