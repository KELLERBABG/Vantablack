//! daemon::discovery — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

pub(crate) fn is_virtual_or_link_local(ip: std::net::Ipv4Addr) -> bool {
    let oct = ip.octets();
    // Loopback or 0.0.0.0
    if oct[0] == 127 || oct[0] == 0 {
        return true;
    }
    // APIPA / link-local
    if oct[0] == 169 && oct[1] == 254 {
        return true;
    }
    // Vantablack mesh TUN overlay subnet (10.66.0.0/24)
    if oct[0] == 10 && oct[1] == 66 && oct[2] == 0 {
        return true;
    }
    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255) is heavily used by Hyper-V / WSL2 / Docker
    if oct[0] == 172 && (16..=31).contains(&oct[1]) {
        return true;
    }
    false
}

/// Best-effort LAN address of this machine, used to build the pairing URI and LAN discovery.
/// Queries OS routing table against public WAN endpoints first so any router subnet works,
/// while excluding virtual/overlay adapters (WSL/Hyper-V/Docker/TUN).
pub(crate) fn detect_lan_ip() -> String {
    let candidates = [
        "1.1.1.1:80",
        "8.8.8.8:80",
        "9.9.9.9:53",
        "192.168.1.1:80",
        "192.168.0.1:80",
        "10.0.0.1:80",
    ];

    let mut fallback_virtual = None;

    for target in &candidates {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(target).is_ok() {
                if let Ok(local) = sock.local_addr() {
                    if let std::net::IpAddr::V4(ipv4) = local.ip() {
                        if !is_virtual_or_link_local(ipv4) {
                            return ipv4.to_string();
                        } else if fallback_virtual.is_none()
                            && ipv4.octets()[0] != 127
                            && ipv4.octets()[0] != 0
                            && !(ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254)
                            && !(ipv4.octets()[0] == 10
                                && ipv4.octets()[1] == 66
                                && ipv4.octets()[2] == 0)
                        {
                            fallback_virtual = Some(ipv4.to_string());
                        }
                    }
                }
            }
        }
    }

    fallback_virtual.unwrap_or_else(|| "127.0.0.1".to_string())
}

pub(crate) fn record_active_peer(sa: SocketAddr) {
    let peers_cache = vantablack::ghost::paths::data_file("peers.cache");
    let addr_str = sa.to_string();
    if let Ok(mut current) = std::fs::read_to_string(&peers_cache) {
        if !current.contains(&addr_str) {
            if !current.ends_with('\n') && !current.is_empty() {
                current.push('\n');
            }
            current.push_str(&addr_str);
            current.push('\n');
            let _ = std::fs::write(&peers_cache, current);
        }
    } else {
        let _ = std::fs::write(&peers_cache, format!("{}\n", addr_str));
    }
}

/// True when this node opted into advertising home-exit service.
pub(crate) fn home_exit_enabled() -> bool {
    std::env::var("GHOST_HOME_EXIT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Map [`vantablack::ghost::net::mesh::NatType`] to the `PeerDescriptorV2` wire byte.
pub(crate) fn nat_type_to_wire(nt: vantablack::ghost::net::mesh::NatType) -> u8 {
    use vantablack::ghost::net::discovery::{
        NAT_CONE, NAT_DIRECT, NAT_RESTRICTED, NAT_SYMMETRIC, NAT_UNKNOWN,
    };
    use vantablack::ghost::net::mesh::NatType;
    match nt {
        NatType::Direct => NAT_DIRECT,
        NatType::Cone => NAT_CONE,
        NatType::Restricted => NAT_RESTRICTED,
        NatType::Symmetric => NAT_SYMMETRIC,
        NatType::Unknown => NAT_UNKNOWN,
    }
}

/// Front capability bits for a listener that is (or is not) running with (or
/// without) knock-only admission.
#[cfg(feature = "reality-front")]
fn front_caps(enabled: bool, knock_only: bool) -> u8 {
    use vantablack::ghost::net::discovery::{CAP_REALITY_FRONT, CAP_REALITY_FRONT_KNOCK};
    if !enabled {
        return 0;
    }
    CAP_REALITY_FRONT
        | if knock_only {
            CAP_REALITY_FRONT_KNOCK
        } else {
            0
        }
}

/// Build and sign this node's [`PeerDescriptorV2`] carrying current public endpoint,
/// LAN addresses, mesh port, NAT classification, capabilities, and `IceOffer`.
pub(crate) fn build_local_descriptor_v2(
    nc: &GhostNode,
    mesh_port: u16,
    relay_enabled: bool,
    exit_enabled: bool,
    vpn_hub: bool,
    offer_text: &std::sync::RwLock<String>,
) -> vantablack::ghost::net::discovery::PeerDescriptorV2 {
    use vantablack::ghost::net::discovery::{
        PeerDescriptorV2, CAP_EXIT, CAP_HOME_EXIT, CAP_QUIC, CAP_RELAY, CAP_VPN_HUB,
    };
    let wan_snap = vantablack::ghost::net::mesh::wan_telemetry_snapshot();
    let lan_ip: std::net::IpAddr = detect_lan_ip()
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let lan_sa = SocketAddr::new(lan_ip, mesh_port);
    // `GHOST_ADVERTISE_ADDR` is an operator override for nodes behind manual
    // port forwarding or a stable DNS name, and it is what makes several nodes
    // on one host testable: each can bind and advertise a distinct loopback
    // address, which `is_single_device_ip` correctly treats as separate peers.
    // Without it the public STUN address wins, which is right for real WAN use.
    let advertised_override = std::env::var("GHOST_ADVERTISE_ADDR")
        .ok()
        .and_then(|raw| match raw.trim().parse::<SocketAddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                tracing::warn!(value = %raw, error = %e, "GHOST_ADVERTISE_ADDR is not a socket address; ignoring");
                None
            }
        });
    let endpoint = advertised_override
        .or(wan_snap.public_addr)
        .unwrap_or(lan_sa);
    // With an explicit address, advertise exactly that candidate: the detected
    // LAN address is a different interface and is not reachable at that endpoint.
    let lan_candidates = if advertised_override.is_some() {
        vec![endpoint]
    } else {
        vec![lan_sa]
    };
    let mut caps = 0u8;
    if relay_enabled {
        caps |= CAP_RELAY;
    }
    if exit_enabled {
        caps |= CAP_EXIT;
        // Boomerang home exit (roadmap item 3). The capability is separate from
        // `CAP_EXIT` so a client can require a deliberately chosen residential
        // endpoint instead of accepting any exit. The flag is only ever set for a
        // node that actually runs exit service: advertising it otherwise would
        // be a promise the packet path cannot keep.
        if home_exit_enabled() {
            caps |= CAP_HOME_EXIT;
        }
    }
    if vpn_hub {
        caps |= CAP_VPN_HUB;
    }
    if cfg!(feature = "quic") {
        caps |= CAP_QUIC;
    }
    // Advertised only when this process actually runs the listener: a capability
    // bit is a promise the packet path has to be able to keep. A knock-only front
    // also says so, because a peer's dialer admits only by SNI label and would
    // otherwise burn a dial discovering that.
    #[cfg(feature = "reality-front")]
    {
        caps |= front_caps(
            super::reality_front::enabled(),
            super::reality_front::knock_only(),
        );
    }
    let ice_offer = offer_text
        .read()
        .ok()
        .map(|s| s.clone())
        .filter(|s| !s.is_empty());
    PeerDescriptorV2::sign_new(
        &nc.identity,
        &nc.identity.pq_public_key_bytes(),
        endpoint,
        lan_candidates,
        mesh_port,
        nat_type_to_wire(wan_snap.nat_type),
        caps,
        ice_offer,
    )
}

/// Persist all verified v2 peer descriptors in `known_descriptors` to `peers.bin`.
pub(crate) fn persist_peer_cache_v2(
    known_descriptors: &DashMap<String, vantablack::ghost::net::discovery::PeerDescriptorV2>,
) {
    let list: Vec<vantablack::ghost::net::discovery::PeerDescriptorV2> = known_descriptors
        .iter()
        .map(|e| e.value().clone())
        .collect();
    if list.is_empty() {
        return;
    }
    let path = vantablack::ghost::paths::data_file("peers.bin");
    if let Err(e) = vantablack::ghost::net::discovery::LocalPeerCache::save_v2(&path, &list) {
        tracing::debug!(error = %e, "Discovery Tier 1: failed to persist peers.bin v2");
    }
}

/// Install a verified [`PeerDescriptorV2`] into `known_descriptors`, `nat_puncher`,
/// `fallback_routes` / `known_relays`, and initiate handshake / ICE punch if not yet connected.
pub(crate) async fn install_peer_descriptor_v2(
    node: &Arc<GhostNode>,
    sock: &UdpSocket,
    peers: &DashMap<String, SocketAddr>,
    pending_hs: &PendingHandshakes,
    nat_puncher: Option<&vantablack::ghost::net::mesh::NatHolePuncher>,
    fallback: Option<&Fallback>,
    known_relays: Option<&DashMap<String, SocketAddr>>,
    known_descriptors: Option<
        &DashMap<String, vantablack::ghost::net::discovery::PeerDescriptorV2>,
    >,
    desc: vantablack::ghost::net::discovery::PeerDescriptorV2,
) {
    let fp = desc.fingerprint();
    if fp == node.fingerprint() || !desc.verify(86400 * 7) {
        return;
    }
    let is_relay = (desc.capabilities & vantablack::ghost::net::discovery::CAP_RELAY) != 0;
    let is_exit = (desc.capabilities & vantablack::ghost::net::discovery::CAP_EXIT) != 0;
    // Remember (or withdraw) this peer's home-exit advertisement. Only a signed
    // descriptor that carries `CAP_HOME_EXIT` becomes a selectable exit.
    vantablack::ghost::v2::boomerang::note_peer(&fp, desc.capabilities, &desc.endpoint.to_string());

    if let Some(kd) = known_descriptors {
        let should_insert = kd
            .get(&fp)
            .map(|old| desc.timestamp >= old.timestamp)
            .unwrap_or(true);
        if should_insert {
            kd.insert(fp.clone(), desc.clone());
        }
    }

    if let Some(np) = nat_puncher {
        if let Ok(local_sa) = node.local_addr.parse::<SocketAddr>() {
            np.register_peer(&fp, desc.endpoint, local_sa);
        }
        if let Some(offer_str) = &desc.ice_offer {
            if let Ok(offer) = vantablack::ghost::net::ice::IceOffer::decode(offer_str) {
                np.set_ice_offer(&fp, offer);
            }
        }
    }

    if is_relay {
        if let Some(kr) = known_relays {
            kr.insert(fp.clone(), desc.endpoint);
            let relay_count = kr.len();
            vantablack::ghost::net::mesh::update_wan_telemetry(|snap| {
                snap.relay_count = relay_count;
            });
        }
        if let Some(fb) = fallback {
            fb.record_relay(&fp, desc.endpoint);
        }
    }

    vantablack::ghost::net::mesh::update_peer_telemetry(&fp, |t| {
        t.is_exit = is_exit;
    });

    if !peers.contains_key(&fp) && !node.sessions.contains_key(&fp) {
        initiate_handshake(node, sock, desc.endpoint, pending_hs).await;
        for lan_ep in &desc.lan_endpoints {
            if *lan_ep != desc.endpoint {
                initiate_handshake(node, sock, *lan_ep, pending_hs).await;
            }
        }
        if let Some(np) = nat_puncher {
            if desc.ice_offer.is_some() && !np.is_connected(&fp) {
                let _ = np.punch_hole(sock, &fp).await;
            }
        }
    }
}

/// Sync per-peer WAN/transport telemetry from `nat_puncher` and `fallback_routes`
/// into the control-plane snapshot consumed by `GET /api/topology`.
pub(crate) fn sync_peer_topology_telemetry(
    addrs: &DashMap<String, SocketAddr>,
    nat_puncher: &vantablack::ghost::net::mesh::NatHolePuncher,
    fallback: &Fallback,
    known_descriptors: &DashMap<String, vantablack::ghost::net::discovery::PeerDescriptorV2>,
    trusted_exits: &std::sync::RwLock<std::collections::HashSet<String>>,
) {
    let exits_guard = trusted_exits.read().ok();
    let allow_all_exits = exits_guard
        .as_ref()
        .map(|s| s.contains("any"))
        .unwrap_or(false);

    for entry in addrs.iter() {
        let fp = entry.key();
        let addr = *entry.value();
        let raw_rtt = nat_puncher.selected_rtt(fp);
        let rtt_ms = raw_rtt.map(|d| (d.as_secs_f64() * 1000.0 * 100.0).round() / 100.0);
        let fb_path = fallback.path(fp);
        if let Some(rtt) = raw_rtt {
            if matches!(
                fb_path,
                Some(vantablack::ghost::net::fallback::FallbackPath::MeshRelay { .. })
            ) {
                vantablack::ghost::v2::chronos::observe_inner_rtt(rtt);
            } else {
                vantablack::ghost::v2::chronos::observe_outer_rtt(rtt);
            }
        }
        let desc_exit = known_descriptors
            .get(fp)
            .map(|d| (d.capabilities & vantablack::ghost::net::discovery::CAP_EXIT) != 0)
            .unwrap_or(false);
        let trusted_exit = exits_guard
            .as_ref()
            .map(|s| allow_all_exits || s.contains(fp))
            .unwrap_or(false);

        let (transport, via_relay_fp) = match fb_path {
            Some(vantablack::ghost::net::fallback::FallbackPath::MeshRelay {
                relay_fp, ..
            }) => ("mesh_relay", Some(relay_fp)),
            Some(vantablack::ghost::net::fallback::FallbackPath::Turn { .. }) => ("turn", None),
            Some(vantablack::ghost::net::fallback::FallbackPath::Skywave { .. }) => {
                ("skywave", None)
            }
            Some(vantablack::ghost::net::fallback::FallbackPath::Direct) | None => {
                let is_lan = match addr.ip() {
                    std::net::IpAddr::V4(v4) => {
                        v4.is_private() || v4.is_loopback() || v4.is_link_local()
                    }
                    std::net::IpAddr::V6(v6) => v6.is_loopback(),
                };
                if is_lan {
                    ("direct_lan", None)
                } else {
                    ("direct_wan_ice", None)
                }
            }
        };

        vantablack::ghost::net::mesh::update_peer_telemetry(fp, |t| {
            if rtt_ms.is_some() {
                t.rtt_ms = rtt_ms;
            }
            t.transport = Some(transport.to_string());
            t.via_relay_fp = via_relay_fp;
            if desc_exit || trusted_exit {
                t.is_exit = true;
            }
        });
    }
}

pub(crate) fn resolve_swarm_secret_for_discovery() -> Option<String> {
    let allow_public_genesis = std::env::var("GHOST_PUBLIC_GENESIS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let swarm_secret = match std::env::var("GHOST_SWARM_SECRET") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            if !allow_public_genesis {
                tracing::warn!(
                    "Discovery Tier 3: GHOST_SWARM_SECRET is unset; set GHOST_SWARM_SECRET for private meshes or GHOST_PUBLIC_GENESIS=1 for public genesis fallback"
                );
                return None;
            }
            "vantablack-genesis-v1".to_string()
        }
    };
    if let Err(e) = vantablack::ghost::net::discovery::validate_swarm_secret_policy(
        swarm_secret.as_bytes(),
        allow_public_genesis,
    ) {
        tracing::warn!(error = %e, "Discovery Tier 3: swarm secret rejected by policy");
        return None;
    }
    Some(swarm_secret)
}

/// Publish this node's signed [`PeerDescriptorV2`] to `GHOST_RENDEZVOUS_URL` and
/// fetch/install swarm peers via [`BlindMailboxClient`].
pub(crate) async fn blind_rendezvous_sync(
    rendezvous_url: &str,
    nc: &Arc<GhostNode>,
    addrs: &Arc<DashMap<String, SocketAddr>>,
    pending_hs: &PendingHandshakes,
    nat_puncher: &Arc<vantablack::ghost::net::mesh::NatHolePuncher>,
    fallback_routes: &Arc<Fallback>,
    known_relays: &Arc<DashMap<String, SocketAddr>>,
    known_descriptors: &Arc<DashMap<String, vantablack::ghost::net::discovery::PeerDescriptorV2>>,
    mesh_port: u16,
    relay_enabled: bool,
    exit_enabled: bool,
    vpn_hub: bool,
    offer_text: &Arc<std::sync::RwLock<String>>,
) {
    let client = match vantablack::ghost::net::discovery::BlindMailboxClient::new() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "Discovery Tier 3: failed to build BlindMailboxClient");
            return;
        }
    };
    let Some(swarm_secret) = resolve_swarm_secret_for_discovery() else {
        return;
    };
    let local_desc = build_local_descriptor_v2(
        nc,
        mesh_port,
        relay_enabled,
        exit_enabled,
        vpn_hub,
        offer_text,
    );
    if let Err(e) = client
        .publish_descriptor(rendezvous_url, swarm_secret.as_bytes(), &local_desc)
        .await
    {
        tracing::warn!(error = %e, "Discovery Tier 3: blind mailbox publish failed");
    }
    match client
        .fetch_descriptors(rendezvous_url, swarm_secret.as_bytes())
        .await
    {
        Ok(peers) => {
            let count = peers.len();
            for desc in peers {
                install_peer_descriptor_v2(
                    nc,
                    &nc.socket,
                    addrs,
                    pending_hs,
                    Some(nat_puncher.as_ref()),
                    Some(fallback_routes.as_ref()),
                    Some(known_relays.as_ref()),
                    Some(known_descriptors.as_ref()),
                    desc,
                )
                .await;
            }
            persist_peer_cache_v2(known_descriptors);
            tracing::info!(
                count,
                "Discovery Tier 3: synchronized blind rendezvous descriptors"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "Discovery Tier 3: blind mailbox fetch failed");
        }
    }
}

/// Send a Peer Exchange (PEX) gossip message to `dest_fp` over their session,
/// sending signed `GHOST_PEX2____` batches of `PeerDescriptorV2` when available
/// alongside backward-compatible `GHOST_PEX_____` v1 frames.
pub(crate) async fn send_pex(
    node: &Arc<GhostNode>,
    sock: &Arc<UdpSocket>,
    dest_fp: &str,
    peers: &Arc<DashMap<String, SocketAddr>>,
    known_descriptors: &DashMap<String, vantablack::ghost::net::discovery::PeerDescriptorV2>,
) {
    let Some(sess) = node.sessions.get(dest_fp) else {
        return;
    };
    let dest_addr = match peers.get(dest_fp).map(|v| *v) {
        Some(a) => a,
        None => return,
    };
    let ctx = SealCtx::from_session(&sess);
    drop(sess);

    // PEX v2: batches of signed PeerDescriptorV2 bounded to <= 2200B per frame.
    let v2_batch: Vec<Vec<u8>> = known_descriptors
        .iter()
        .filter(|e| e.key() != dest_fp)
        .take(MAX_PEX_PEERS)
        .map(|e| e.value().to_bytes())
        .collect();
    if !v2_batch.is_empty() {
        let mut payload_v2 = GHOST_PEX_V2_MAGIC.to_vec();
        payload_v2.push(0u8);
        let mut count_v2: u8 = 0;
        for raw in &v2_batch {
            let Ok(len_u16) = u16::try_from(raw.len()) else {
                continue;
            };
            if payload_v2.len() + 2 + raw.len() > 2200 && count_v2 > 0 {
                break;
            }
            payload_v2.extend_from_slice(&len_u16.to_be_bytes());
            payload_v2.extend_from_slice(raw);
            count_v2 = count_v2.saturating_add(1);
        }
        if count_v2 > 0 {
            payload_v2[GHOST_PEX_V2_MAGIC.len()] = count_v2;
            let (f, tag) = enc_split(&ctx, &payload_v2);
            send3_mixed(Arc::clone(sock), &dest_addr, &ctx, &f, &tag).await;
            tracing::debug!(to = %dest_fp, peers = count_v2, "PEX v2: sent signed descriptor batch");
        }
    }

    // Piggyback BTCr ticket wallet & Fleet revocation gossip over the same session.
    let btcr_batch = vantablack::ghost::v2::btcr::export_gossip_batch(16);
    if !btcr_batch.is_empty() {
        let mut msg = GHOST_BTCR_GOSSIP_MAGIC.to_vec();
        msg.extend_from_slice(&btcr_batch);
        let (f, tag) = enc_split(&ctx, &msg);
        send3_mixed(Arc::clone(sock), &dest_addr, &ctx, &f, &tag).await;
    }
    let rev_batch = vantablack::ghost::v2::fleet::export_gossip_revocation_batch();
    if !rev_batch.is_empty() {
        let mut msg = GHOST_FLEET_REVOKE_MAGIC.to_vec();
        msg.extend_from_slice(&rev_batch);
        let (f, tag) = enc_split(&ctx, &msg);
        send3_mixed(Arc::clone(sock), &dest_addr, &ctx, &f, &tag).await;
    }

    // Build legacy PEX v1 payload for backward compatibility: [GHOST_PEX_____][count u8][fp_hex 16B + addr_str + NUL ...]
    let mut payload = GHOST_PEX_MAGIC.to_vec();
    let peer_list: Vec<(String, SocketAddr)> = peers
        .iter()
        .filter(|e| e.key() != dest_fp)
        .take(MAX_PEX_PEERS)
        .map(|e| (e.key().clone(), *e.value()))
        .collect();
    if peer_list.is_empty() {
        return;
    }
    payload.push(peer_list.len() as u8);
    for (fp, addr) in &peer_list {
        let fp_bytes = fp.as_bytes();
        let fp_len = fp_bytes.len().min(16);
        let mut fp_buf = [0u8; 16];
        fp_buf[..fp_len].copy_from_slice(&fp_bytes[..fp_len]);
        payload.extend_from_slice(&fp_buf);
        let addr_str = addr.to_string();
        payload.extend_from_slice(addr_str.as_bytes());
        payload.push(0u8);
    }
    let (f, tag) = enc_split(&ctx, &payload);
    send3_mixed(Arc::clone(sock), &dest_addr, &ctx, &f, &tag).await;
    tracing::debug!(to = %dest_fp, peers = peer_list.len(), "PEX: sent peer list");
}

/// Broadcast an authenticated `GHOST_BYE_____` notification to all active peers
/// so they immediately evict our session and reroute traffic elsewhere, then
/// tear down local session/peer state.
pub(crate) fn broadcast_goodbye(nc: &GhostNode, addrs: &DashMap<String, SocketAddr>) {
    let targets: Vec<(String, SocketAddr)> = addrs
        .iter()
        .map(|e| (e.key().clone(), *e.value()))
        .collect();

    for (peer_fp, endpoint) in &targets {
        if let Some(sess) = nc.sessions.get(peer_fp) {
            if !sess.is_v1_wire() {
                let ctx = SealCtx::from_session(&sess);
                let frame = seal_single(&ctx, GHOST_BYE_MAGIC);
                super::srtp::try_send_raw(&nc.socket, endpoint, &frame);
                super::srtp::try_send_raw(&nc.socket, endpoint, &frame);
            }
        }
        tracing::info!(
            peer = %peer_fp,
            %endpoint,
            "Sent GHOST_BYE disconnect/reroute notification to mesh peer"
        );
    }

    nc.sessions.clear();
    addrs.clear();
}

/// Tier-1 authenticated peer cache loader (`peers.bin` v2 -> legacy v1 -> plaintext `peers.cache`).
pub(crate) fn load_tier1_peer_cache() -> (
    Vec<vantablack::ghost::net::discovery::PeerDescriptorV2>,
    Vec<SocketAddr>,
) {
    let peer_cache_path = vantablack::ghost::paths::data_file("peers.bin");
    if let Ok(v2_cached) =
        vantablack::ghost::net::discovery::LocalPeerCache::load_v2(&peer_cache_path)
    {
        if !v2_cached.is_empty() {
            tracing::info!(
                count = v2_cached.len(),
                "Discovery Tier 1: Loaded verified v2 peer descriptors from peers.bin"
            );
            return (v2_cached, Vec::new());
        }
    }
    if let Ok(v1_cached) = vantablack::ghost::net::discovery::LocalPeerCache::load(&peer_cache_path)
    {
        if !v1_cached.is_empty() {
            let addrs: Vec<SocketAddr> = v1_cached.iter().map(|p| p.endpoint).collect();
            tracing::info!(
                count = addrs.len(),
                "Discovery Tier 1: Loaded legacy v1 peer endpoints from peers.bin"
            );
            return (Vec::new(), addrs);
        }
    }
    let legacy_cache_path = vantablack::ghost::paths::data_file("peers.cache");
    if let Ok(raw) = std::fs::read_to_string(&legacy_cache_path) {
        let addrs: Vec<SocketAddr> = raw
            .lines()
            .filter_map(|l| l.trim().parse::<SocketAddr>().ok())
            .collect();
        if !addrs.is_empty() {
            tracing::info!(
                count = addrs.len(),
                "Discovery Tier 1: Loaded fallback peer endpoints from peers.cache"
            );
            return (Vec::new(), addrs);
        }
    }
    (Vec::new(), Vec::new())
}

/// Zero-Knowledge 3-Tier bootstrap: checks authenticated local disk cache (`peers.bin`)
/// first, then falls back to legacy HTTP bootstrap when `GHOST_RENDEZVOUS_URL` is unset.
pub(crate) async fn http_bootstrap(mesh_port: u16, node_fp: Option<&str>) -> Vec<SocketAddr> {
    // Tier 1: Local authenticated disk cache (zero network footprint)
    let (v2_cached, legacy_addrs) = load_tier1_peer_cache();
    if !v2_cached.is_empty() {
        return v2_cached.into_iter().map(|d| d.endpoint).collect();
    }
    if !legacy_addrs.is_empty() {
        return legacy_addrs;
    }
    if std::env::var("GHOST_RENDEZVOUS_URL")
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return Vec::new();
    }

    // Tier 3: Zero-knowledge blinded rendezvous discovery
    let Some(swarm_secret) = resolve_swarm_secret_for_discovery() else {
        return Vec::new();
    };
    let now_epoch_hour = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 3600;
    let epoch_key = vantablack::ghost::net::discovery::BlindRendezvous::derive_epoch_key(
        swarm_secret.as_bytes(),
        now_epoch_hour,
    );
    let slot_id = vantablack::ghost::net::discovery::BlindRendezvous::derive_slot_id(&epoch_key, 0);
    let _slot_hex = hex::encode(slot_id);

    let lan_ip = detect_lan_ip();
    let base_url =
        std::env::var("GHOST_BOOTSTRAP_URL").unwrap_or_else(|_| DEFAULT_BOOTSTRAP_URL.to_string());
    let mut url = base_url.replace("port=55225", &format!("port={}", mesh_port));
    if let Some(fp) = node_fp {
        let sep = if url.contains('?') { '&' } else { '?' };
        url.push_str(&format!("{}id={}&lan={}:{}", sep, fp, lan_ip, mesh_port));
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("HTTP bootstrap: failed to build client: {e}");
            return Vec::new();
        }
    };

    match client.get(&url).send().await {
        Ok(resp) => match resp.json::<Vec<String>>().await {
            Ok(addrs) => {
                let peers: Vec<SocketAddr> = addrs.iter().filter_map(|s| s.parse().ok()).collect();
                tracing::info!(
                    count = peers.len(),
                    "HTTP bootstrap: registered with tracker, learned peers"
                );
                peers
            }
            Err(e) => {
                tracing::warn!("HTTP bootstrap: JSON parse error: {e}");
                Vec::new()
            }
        },
        Err(e) => {
            tracing::warn!("HTTP bootstrap: request failed: {e}");
            Vec::new()
        }
    }
}

/// Autonomous LAN discovery sweep: broadcasts beacons to 255.255.255.255 on 2270 and mesh_port,
/// and actively probes all hosts in the local /24 subnet (and common home subnets).
pub(crate) async fn sweep_lan_subnet(
    nc: &Arc<GhostNode>,
    pending_hs: &Arc<DashMap<String, PendingHandshake>>,
    addrs: &Arc<DashMap<String, SocketAddr>>,
    mesh_port: u16,
) {
    let local_ip_str = detect_lan_ip();

    // Collect all local IPv4 addresses so we never probe ourselves.
    let local_ips: std::collections::HashSet<std::net::Ipv4Addr> = {
        let mut set = std::collections::HashSet::new();
        if let Ok(ip) = local_ip_str.parse::<std::net::Ipv4Addr>() {
            set.insert(ip);
        }
        for target in &[
            "1.1.1.1:80",
            "8.8.8.8:80",
            "9.9.9.9:53",
            "192.168.1.1:80",
            "192.168.0.1:80",
            "10.0.0.1:80",
        ] {
            if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
                if sock.connect(target).is_ok() {
                    if let Ok(la) = sock.local_addr() {
                        if let std::net::IpAddr::V4(v4) = la.ip() {
                            set.insert(v4);
                        }
                    }
                }
            }
        }
        set
    };

    let mut subnets_to_sweep: Vec<[u8; 3]> = Vec::new();

    for &ip in &local_ips {
        if !is_virtual_or_link_local(ip) {
            let oct = ip.octets();
            let sn = [oct[0], oct[1], oct[2]];
            if !subnets_to_sweep.contains(&sn) {
                subnets_to_sweep.push(sn);
            }
        }
    }
    if subnets_to_sweep.is_empty() {
        if let Ok(local_ip) = local_ip_str.parse::<std::net::Ipv4Addr>() {
            let oct = local_ip.octets();
            if oct[0] != 127
                && oct[0] != 0
                && !(oct[0] == 169 && oct[1] == 254)
                && !(oct[0] == 10 && oct[1] == 66 && oct[2] == 0)
            {
                subnets_to_sweep.push([oct[0], oct[1], oct[2]]);
            }
        }
    }

    // 1. Broadcast signed beacons from the main mesh socket so the reply port
    //    is always the real mesh port (55225) — not an ephemeral port.
    {
        let pq_commit = nc.identity.pq_commitment();
        let beacon_pkt = build_beacon_packet(
            &nc.identity.public_key_bytes(),
            |d| nc.identity.sign(d).to_bytes(),
            None,
            None,
            false,
            Some(&pq_commit),
            Some(mesh_port),
        );
        let mut targets: Vec<SocketAddr> = Vec::new();
        for s in &subnets_to_sweep {
            if let Ok(t) = format!("{}.{}.{}.255:2270", s[0], s[1], s[2]).parse::<SocketAddr>() {
                targets.push(t);
            }
            if let Ok(t) =
                format!("{}.{}.{}.255:{}", s[0], s[1], s[2], mesh_port).parse::<SocketAddr>()
            {
                targets.push(t);
            }
        }
        // Also send to the global broadcast addresses
        if let Ok(t) = "255.255.255.255:2270".parse::<SocketAddr>() {
            targets.push(t);
        }
        if let Ok(t) = format!("255.255.255.255:{}", mesh_port).parse::<SocketAddr>() {
            targets.push(t);
        }
        for t in targets {
            let _ = nc.socket.send_to(&beacon_pkt, t).await;
        }
    }

    // 2. Active subnet probes: Send handshake probe to hosts in all detected subnets
    for s in &subnets_to_sweep {
        tracing::info!(
            subnet = %format!("{}.{}.{}.0/24", s[0], s[1], s[2]),
            "Starting autonomous LAN discovery sweep..."
        );
        for host in 1..=254 {
            let target_ip = std::net::Ipv4Addr::new(s[0], s[1], s[2], host);
            if local_ips.contains(&target_ip) {
                continue;
            }
            let target_sa = SocketAddr::new(std::net::IpAddr::V4(target_ip), mesh_port);
            // Skip actively connected peers so we don't disrupt their sessions or trigger re-handshake storms
            if addrs
                .iter()
                .any(|p| *p.value() == target_sa || p.value().ip() == target_sa.ip())
            {
                continue;
            }
            initiate_handshake(nc, &nc.socket, target_sa, pending_hs).await;

            if host % 32 == 0 {
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        }
    }
    tracing::info!("Autonomous LAN discovery sweep complete");
}

#[cfg(all(test, feature = "reality-front"))]
mod tests {
    use super::*;
    use vantablack::ghost::net::discovery::{CAP_REALITY_FRONT, CAP_REALITY_FRONT_KNOCK};

    /// A capability bit is a promise the packet path can keep, so a knock-only
    /// front must advertise the mode: a dialer admits only by SNI label and would
    /// otherwise spend a dial to find out it cannot be reached.
    #[test]
    fn a_knock_only_front_advertises_that_it_cannot_be_dialed() {
        assert_eq!(front_caps(false, false), 0, "no listener, no promise");
        assert_eq!(
            front_caps(false, true),
            0,
            "the mode is meaningless without the listener"
        );
        assert_eq!(front_caps(true, false), CAP_REALITY_FRONT);
        assert_eq!(
            front_caps(true, true),
            CAP_REALITY_FRONT | CAP_REALITY_FRONT_KNOCK,
            "a knock-only front is still a front, just not a dialable one"
        );
    }
}
