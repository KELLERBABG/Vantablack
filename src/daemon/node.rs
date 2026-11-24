//! daemon::node — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

/// Resolve whether this node serves as an exit and its initial `trusted_exits` allowlist.
///
/// Security invariant (C1): in `GHOST_MODE=public`, exit service fails CLOSED when
/// neither `GHOST_EXIT=1` (or `GHOST_EXIT_NODE=1` / `GHOST_VPN=hub` / `--exit`) nor
/// `GHOST_EXIT_ALLOWLIST` is explicitly set — `"any"` is NOT inserted automatically.
/// Private/LAN modes preserve legacy open-exit defaults unless explicitly disabled.
pub(crate) fn resolve_trusted_exits(
    ghost_mode: &str,
    exit_explicitly_on: bool,
    exit_explicitly_off: bool,
    allowlist_raw: Option<&str>,
) -> (bool, std::collections::HashSet<String>) {
    let mut set: std::collections::HashSet<String> = allowlist_raw
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let is_public_mode = ghost_mode.trim().eq_ignore_ascii_case("public");
    let is_exit_node = if exit_explicitly_off {
        false
    } else if exit_explicitly_on {
        true
    } else {
        !is_public_mode
    };

    if is_exit_node && set.is_empty() {
        set.insert("any".to_string());
    }
    (is_exit_node, set)
}

/// Boot the node inside its own tokio runtime.
pub(crate) fn run_daemon(
    suppress_browser: bool,
    node_tx: Option<std::sync::mpsc::Sender<Arc<GhostNode>>>,
) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(run_node(suppress_browser, node_tx))
}

pub(crate) async fn run_node(
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

    // WIRED: Category B - Verified SPSC Ring Buffer for packet staging
    let verified_ring = Arc::new(VerifiedRingBuffer::<Vec<u8>>::new(1024));

    // SecureTimeKeeper and BuildInfo were constructed here and immediately
    // discarded (_time_keeper, _build_info — neither was ever read). Removed
    // rather than wired: the library primitives remain available in l9_infra
    // for future use when a real consumer exists.

    let ba = std::env::var("GHOST_BIND").unwrap_or_else(|_| "0.0.0.0:55225".to_string());
    // A configured regime is the human-facing replacement for the four SOCKS
    // ports and their env vars: it selects one listener, one hop policy, and
    // cover traffic. `GHOST_V2_REGIME` wins over the persisted choice; a typo is
    // reported instead of silently falling back to the weakest regime.
    let regime = match vantablack::ghost::v2::regime::from_env() {
        Ok(Some(r)) => Some(r),
        Ok(None) => vantablack::ghost::v2::regime::load_persisted(
            &vantablack::ghost::v2::regime::config_path(),
        )
        .unwrap_or_else(|e| {
            tracing::warn!("Regime file ignored: {e}");
            None
        }),
        Err(e) => {
            tracing::warn!("Ignoring regime setting: {e}");
            None
        }
    };
    let regime_policy = regime.inspect(|r| {
        if r.cover_traffic() && std::env::var("GHOST_RACS").is_err() {
            // Cover traffic is what `ghost`/`vantablack` promise; the RACS gate
            // already exists, so a regime turns it on rather than adding a
            // second switch.
            std::env::set_var("GHOST_RACS", "1");
        }
    });
    let socks = std::env::var("GHOST_SOCKS5").is_ok() || regime_policy.is_some();
    let socks_port: u16 = regime_policy
        .map(|r| vantablack::ghost::v2::regime::effective_policy(r, 0, 1080).socks_port)
        .unwrap_or_else(|| {
            std::env::var("GHOST_SOCKS5_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1080)
        });
    let single_hop_policy = regime_policy.map(|r| match r.hops() {
        vantablack::ghost::v2::regime::HopClass::Direct => socks::HopPolicy::OneHop,
        vantablack::ghost::v2::regime::HopClass::TwoHop => socks::HopPolicy::TwoHop,
        vantablack::ghost::v2::regime::HopClass::ThreeHopStrict => socks::HopPolicy::StrictThreeHop,
    });
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
    // Exit-node determination (C1): fail closed in GHOST_MODE=public unless
    // explicitly enabled via GHOST_EXIT=1 / GHOST_EXIT_ALLOWLIST / --exit / GHOST_VPN=hub.
    let vpn_env_mode = std::env::var("GHOST_VPN")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let ghost_mode = std::env::var("GHOST_MODE").unwrap_or_else(|_| "public".to_string());
    let exit_explicitly_off = std::env::var("GHOST_EXIT")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
        || matches!(
            vpn_env_mode.as_str(),
            "client" | "0" | "false" | "off" | "none" | "disabled"
        );
    let exit_explicitly_on = std::env::var("GHOST_EXIT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || std::env::var("GHOST_EXIT_NODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        || vpn_env_mode == "hub"
        || std::env::args().any(|arg| arg == "--exit" || arg == "--exit-node" || arg == "-e");
    let allowlist_env = std::env::var("GHOST_EXIT_ALLOWLIST").ok();
    let (is_exit_node, initial_trusted_exits) = resolve_trusted_exits(
        &ghost_mode,
        exit_explicitly_on,
        exit_explicitly_off,
        allowlist_env.as_deref(),
    );

    let mut exit_ips: Vec<std::net::IpAddr> = std::env::var("GHOST_EXIT_IPS")
        .ok()
        .map(|ips_str| {
            ips_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();

    if exit_ips.is_empty() && is_exit_node {
        for target in &["1.1.1.1:80", "8.8.8.8:80", "9.9.9.9:80"] {
            if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
                if sock.connect(target).is_ok() {
                    if let Ok(la) = sock.local_addr() {
                        let ip = la.ip();
                        let is_valid = match ip {
                            std::net::IpAddr::V4(v4) => !is_virtual_or_link_local(v4),
                            std::net::IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
                        };
                        if is_valid && !exit_ips.contains(&ip) {
                            exit_ips.push(ip);
                        }
                    }
                }
            }
        }
        if exit_ips.is_empty() {
            exit_ips.push(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        }
    }

    let exit_rotator: Option<Arc<ExitIpRotator>> = if !exit_ips.is_empty() {
        let rotator = Arc::new(ExitIpRotator::new(exit_ips.clone()));
        tracing::info!(
            "Exit IP Rotator initialized with {} egress IP(s): {:?}",
            rotator.pool_size(),
            exit_ips
        );
        Some(rotator)
    } else {
        None
    };

    // Exit-node authorization: peers allowed to use THIS node as a SOCKS5
    // exit. Closed by default in public mode — "any" opens it, or list fingerprints.
    let trusted_exits: Arc<std::sync::RwLock<std::collections::HashSet<String>>> =
        Arc::new(std::sync::RwLock::new(initial_trusted_exits));

    // ── VPN (LAN-over-WAN / Exit Node) configuration ──
    let vpn_mode = init_vpn_mode_with_rotator(exit_rotator.clone())?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Vantablack v{} starting — L0-L9 stack fully wired",
        env!("CARGO_PKG_VERSION")
    );
    if let Some(r) = regime_policy {
        tracing::info!(
            regime = %r,
            plane = r.plane().as_str(),
            hops = r.hops().hops(),
            port = socks_port,
            "Regime active: one SOCKS5 listener replaces the four fixed ports"
        );
    } else if socks {
        tracing::info!("Mode: SOCKS5 proxy on 127.0.0.1:{socks_port}");
    }
    if revocation_list.prune_expired() > 0 {
        tracing::info!("Revocation list initialized");
    }

    let node = match GhostNode::new(&ba).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("Failed to bind {ba} ({e}), falling back to ephemeral port 0.0.0.0:0");
            GhostNode::new("0.0.0.0:0").await?
        }
    };
    // ── Boomerang home-exit advertisement ──────────────────────────────
    // A node that runs exit service *and* opted in publishes CAP_HOME_EXIT in
    // its signed descriptor. If the opt-in is set while exit service is off, the
    // node refuses to pretend: the flag is not advertised and the conflict is
    // logged, because a capability bit that claims unimplemented behaviour is a
    // bug rather than a warning sign.
    let claims_home_exit = std::env::var("GHOST_HOME_EXIT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let home_exit_live = claims_home_exit && is_exit_node;
    if claims_home_exit && !is_exit_node {
        tracing::warn!(
            "GHOST_HOME_EXIT=1 ignored: this node does not run exit service (set GHOST_EXIT=1 and GHOST_EXIT_ALLOWLIST)"
        );
    }
    vantablack::ghost::v2::boomerang::set_local_advertisement(&node.local_addr, home_exit_live);
    if home_exit_live {
        tracing::info!(
            endpoint = %node.local_addr,
            "Boomerang: advertising home-exit capability"
        );
    }
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
    let spool: Arc<SpoolPool> = Arc::new(DashMap::new());
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

    // Category A (A1 + A4) — Single-socket UDP multiplexing on `nc.socket`.
    //
    // STUN reflexive discovery, UPnP/NAT-PMP port mapping, ICE connectivity checks,
    // NAT keepalives, and GTF frames all share `nc.socket` so external NAT pinholes
    // and advertised candidate ports match the mesh socket identically.
    let (stun_tx, _) = tokio::sync::broadcast::channel::<(Vec<u8>, SocketAddr)>(256);
    let stun_server = std::env::var("GHOST_STUN_SERVER")
        .ok()
        .and_then(|v| v.parse::<SocketAddr>().ok());
    let mut nat_puncher =
        vantablack::ghost::net::mesh::NatHolePuncher::new().with_stun_mux(stun_tx.clone());
    if let Some(server) = stun_server {
        tracing::info!(server = %server, "STUN: configured explicit server for NAT traversal");
        nat_puncher = nat_puncher.with_stun_server(server);
    } else if vantablack::ghost::net::mesh::stun_disabled_from_env() {
        tracing::info!("STUN: disabled via GHOST_STUN=off");
    } else {
        tracing::info!("STUN: using async default STUN server pool for NAT discovery");
    }
    nat_puncher.set_local_fingerprint(nc.fingerprint());

    let mesh_local = nc.socket.local_addr()?;
    let probe_target = stun_server.unwrap_or_else(|| {
        format!("{}:{}", BEACON_MULTICAST_ADDR, BEACON_PORT)
            .parse()
            .expect("the beacon address is a valid socket address")
    });
    // A wildcard bind does not say which interface we would send from, so ask
    // the routing table (a UDP `connect` is a route lookup only).
    let host_candidate = match vantablack::ghost::net::ice::probe_local_addr(probe_target) {
        Ok(a) => SocketAddr::new(a.ip(), mesh_local.port()),
        Err(e) => {
            tracing::debug!(
                "NAT traversal: route probe failed ({e}); advertising the bound address"
            );
            mesh_local
        }
    };

    // Our advertised offer: stable credentials plus whatever candidates we gather.
    let mut offer_agent = vantablack::ghost::net::ice::IceAgent::new(
        vantablack::ghost::net::ice::IceRole::Controlling,
    );
    offer_agent.set_local_credentials(nat_puncher.local_credentials().clone());
    offer_agent.add_host_candidate(host_candidate, host_candidate);

    // Opportunistic: ask the local gateway to open `mesh_local.port()` for us.
    let upnp_public: Option<SocketAddr> = if let std::net::IpAddr::V4(local_v4) =
        host_candidate.ip()
    {
        match upnp::opportunistic_public_addr(local_v4, mesh_local.port()).await {
            Some(public) => {
                tracing::info!(
                    public = %public,
                    "UPnP/NAT-PMP: gateway mapping granted on mesh socket — advertising it as a candidate"
                );
                offer_agent.add_server_reflexive_candidate(host_candidate, public, None);
                nat_puncher.set_public_addr(public);
                let port = mesh_local.port();
                tokio::spawn(async move {
                    upnp::renew_udp_mapping(local_v4, port).await;
                });
                Some(public)
            }
            None => {
                tracing::debug!("UPnP/NAT-PMP: {}", upnp::describe_attempt(None));
                None
            }
        }
    } else {
        None
    };
    // ── TURN allocation ──
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

    // ── Relay role + fallback routes (B22) ──
    //
    // A node relays for others only when asked (`GHOST_RELAY=1`): forwarding
    // someone else's traffic costs transit bandwidth, and that should be a
    // deliberate operational choice rather than a surprise. The quota is the
    // same `FlowController` that bounds our own transit traffic.
    let relay_enabled = std::env::var("GHOST_RELAY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // The skywave (ABOS) anchor: bridge + virtual carrier always come up (cheap,
    // loopback-only), but the fallback ladder only arms its fourth rung when the
    // operator opted in via `--skywave` / `GHOST_SKYWAVE=1`.
    let skywave_enabled = std::env::var("GHOST_SKYWAVE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // The QEL (quantum) anchor: without opt-in the engine is never spawned and
    // the anchor reports `unavailable`-by-choice (`unprobed`) rather than paying
    // a boot probe.
    let quantum_enabled = std::env::var("GHOST_QUANTUM")
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
    // Relay-capable peers discovered via beacons, tracked on EVERY node (A2)
    // regardless of whether `GHOST_RELAY=1` is enabled on this node.
    let known_relays: Arc<DashMap<String, SocketAddr>> = Arc::new(DashMap::new());
    // Frames from every REALITY front stream (an admitted one, or one this node
    // dialed after a punch failed) land here and are drained into `ingest` once
    // the receive pipeline exists — the drain task below is spawned right after
    // `rx`. Created this early because the ICE task can start a dial immediately.
    #[cfg(feature = "reality-front")]
    let front_inbound: Option<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>> = {
        let (tx, inbound) = mpsc::unbounded_channel();
        super::reality_front::install_ingress(tx);
        Some(inbound)
    };
    // Verified PeerDescriptorV2 cache shared across Tier-1 cache, Tier-3 blind mailbox, and PEX v2.
    let known_descriptors: Arc<
        DashMap<String, vantablack::ghost::net::discovery::PeerDescriptorV2>,
    > = Arc::new(DashMap::new());
    #[cfg(feature = "vpn")]
    let vpn_hub_active = matches!(vpn_mode.as_ref(), Some(VpnMode::Hub(_)));
    #[cfg(not(feature = "vpn"))]
    let vpn_hub_active = false;
    // Peers an operator declared radio-only (`GHOST_SKYWAVE_ONLY`). Populated
    // below, before anything can check a candidate pair, and read wherever a
    // measured path would otherwise supersede a declared one.
    let skywave_only: Arc<DashSet<String>> = Arc::new(DashSet::new());

    // ── SKYWAVE (ABOS) CARRIER ──
    //
    // In-simulation fallback carrier: TX arms below ship frames into the
    // bridge, the virtual UDP carrier (loopback-bound by default) carries them
    // to a peer, and skywave ingress is drained into the same receive pipeline.
    // Without `--features sdr` the bridge runs in synthetic mode; it only
    // becomes ladder-selectable when explicitly activated.
    let skywave_bridge =
        match net::sdr_bridge::SkywaveBridge::with_virtual_carrier(skywave_enabled).await {
            Ok(b) => Arc::new(b),
            Err(e) => {
                tracing::warn!(error = %e, "skywave: bridge init failed — carrier disabled");
                // A dead bridge must not take the daemon down.
                Arc::new(
                    net::sdr_bridge::SkywaveBridge::with_virtual_carrier(false)
                        .await
                        .expect("synthetic bridge construction cannot fail"),
                )
            }
        };

    // Publish the bridge process-wide (egress arms + control plane read it via
    // `SkywaveBridge::global()`), and activate the synthetic carrier only when
    // the operator asked for the skywave anchor: without opt-in the ladder's
    // fourth rung stays folded up.
    //
    // This is done here — rather than beside the ingress drain further down —
    // because the radio-only declarations below are resolved *through* the armed
    // bridge, and they must be in force before the discovery and ICE tasks can
    // spawn a check that a declaration outranks.
    let _ = skywave_bridge.install_global();
    if skywave_enabled {
        skywave_bridge.activate_synthetic(5_350_000);
        tracing::info!(
            "skywave: ABOS carrier enabled (--skywave / GHOST_SKYWAVE=1) — synthetic carrier active, fallback ladder rung 4 armed"
        );
    }

    // ── RADIO-ONLY PEERS (`GHOST_SKYWAVE_ONLY`) ──
    //
    // An operator who knows a peer has no usable IP path says so here, and the
    // declaration is resolved through the same ladder a failed check walks, with
    // the terrestrial rungs withheld — so it can only pre-empt the ladder's
    // answer, never invent one. From here on the peer is never checked and its
    // route is never cleared.
    {
        let declared = std::env::var(SKYWAVE_ONLY_ENV).unwrap_or_default();
        let applied = install_skywave_only(
            &skywave_only,
            &fallback_routes,
            &nc.fingerprint(),
            &declared,
            net::sdr_bridge::SkywaveBridge::global().and_then(|b| b.nvis_freq_khz()),
        );
        if applied > 0 {
            tracing::info!(
                peers = applied,
                "skywave: {applied} peer(s) declared radio-only — their frames ride the carrier \
                 and no direct check may move them back"
            );
        }
    }

    // ── Optional QUIC transport ──
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
                for line in cache_str
                    .lines()
                    .map(|l| l.trim().trim_start_matches('\u{feff}'))
                {
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
                        initiate_handshake(&nc, &nc.socket, *t, &pending_hs).await;
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
    let _gui_active = suppress_browser;

    // Pairing target advertised in the QR code: this host's LAN address, the
    // control-center port and the node fingerprint. The fingerprint is stable
    // across runs because the Ed25519 identity is persisted in identity.key.
    let mesh_port = nc
        .socket
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(metrics_port);
    let lan_host = format!("{}:{}", detect_lan_ip(), mesh_port);
    let pair_uri = format!(
        "ggn://pair?nid={fp}&fp={fp}&host={host}",
        fp = nc.fingerprint(),
        host = lan_host
    );
    vantablack::ghost::net::mesh::set_local_node_offer(
        mesh_port,
        our_offer_text.read().ok().map(|s| s.clone()),
    );

    let scan_interval_secs = Arc::new(AtomicU32::new(3600)); // Default 1 hour
    let scan_notify = Arc::new(tokio::sync::Notify::new());

    // Discovery bootstrap: Tier-1 `peers.bin` v2 (with legacy fallback) + Tier-3 BlindMailboxClient
    // when `GHOST_RENDEZVOUS_URL` is configured, else legacy `http_bootstrap`.
    {
        let nc_boot = Arc::clone(&nc);
        let addrs_boot = Arc::clone(&addrs);
        let pending_boot = Arc::clone(&pending_hs);
        let np_boot = Arc::clone(&nat_puncher);
        let fb_boot = Arc::clone(&fallback_routes);
        let kr_boot = Arc::clone(&known_relays);
        let kd_boot = Arc::clone(&known_descriptors);
        let offer_boot = Arc::clone(&our_offer_text);
        let mesh_port_boot = mesh_port;
        tokio::spawn(async move {
            // Small delay to let the UDP socket settle
            tokio::time::sleep(Duration::from_millis(500)).await;
            let (v2_cached, legacy_addrs) = load_tier1_peer_cache();
            for desc in v2_cached {
                install_peer_descriptor_v2(
                    &nc_boot,
                    &nc_boot.socket,
                    &addrs_boot,
                    &pending_boot,
                    Some(np_boot.as_ref()),
                    Some(fb_boot.as_ref()),
                    Some(kr_boot.as_ref()),
                    Some(kd_boot.as_ref()),
                    desc,
                )
                .await;
            }
            for peer_addr in legacy_addrs {
                initiate_handshake(&nc_boot, &nc_boot.socket, peer_addr, &pending_boot).await;
            }

            if let Ok(rz_url) = std::env::var("GHOST_RENDEZVOUS_URL") {
                let rz_url = rz_url.trim().to_string();
                if !rz_url.is_empty() {
                    blind_rendezvous_sync(
                        &rz_url,
                        &nc_boot,
                        &addrs_boot,
                        &pending_boot,
                        &np_boot,
                        &fb_boot,
                        &kr_boot,
                        &kd_boot,
                        mesh_port_boot,
                        relay_enabled,
                        is_exit_node,
                        vpn_hub_active,
                        &offer_boot,
                    )
                    .await;
                    return;
                }
            }

            let bootstrap_peers =
                http_bootstrap(mesh_port_boot, Some(&nc_boot.fingerprint())).await;
            for peer_addr in bootstrap_peers {
                initiate_handshake(&nc_boot, &nc_boot.socket, peer_addr, &pending_boot).await;
            }
        });
    }

    // Autonomous Private Mesh LAN discovery background engine:
    // Immediate sweep on startup, periodic sweep (1h / 4h), and on-demand trigger.
    {
        let nc_sweep = Arc::clone(&nc);
        let phs_sweep = Arc::clone(&pending_hs);
        let addrs_sweep = Arc::clone(&addrs);
        let scan_notify_sweep = Arc::clone(&scan_notify);
        let interval_atomic = Arc::clone(&scan_interval_secs);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sweep_lan_subnet(&nc_sweep, &phs_sweep, &addrs_sweep, mesh_port).await;

            loop {
                let secs = interval_atomic.load(Ordering::Relaxed);
                let delay = if secs == 0 {
                    Duration::from_secs(3600 * 24)
                } else {
                    Duration::from_secs(secs as u64)
                };
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {
                        let active_nodes = if nc_sweep.sessions.is_empty() { 1 } else { 1 + nc_sweep.sessions.len() };
                        if active_nodes >= 5 {
                            tracing::info!(
                                active_nodes,
                                "Private mesh quorum achieved (>= 5 nodes) - running autonomous local mesh"
                            );
                        } else {
                            tracing::info!(
                                active_nodes,
                                "Private mesh has {} nodes (need 5 for autonomous local quorum) - WAN mesh assisted mode active",
                                active_nodes
                            );
                        }
                        sweep_lan_subnet(&nc_sweep, &phs_sweep, &addrs_sweep, mesh_port).await;
                    }
                    _ = scan_notify_sweep.notified() => {
                        tracing::info!("Manual LAN discovery sweep triggered");
                        sweep_lan_subnet(&nc_sweep, &phs_sweep, &addrs_sweep, mesh_port).await;
                    }
                }
            }
        });
    }

    // Shared QEL anchor state for the control plane: probed once at boot, then
    // updated by anchor endpoints.
    let qel_state = Arc::new(parking_lot::RwLock::new(
        vantablack::ghost::layers::l10_qel::QelAnchorState::Unprobed,
    ));
    let qel_last_route: Arc<
        parking_lot::RwLock<Option<vantablack::ghost::layers::l10_qel::QuantumRouteResult>>,
    > = Arc::new(parking_lot::RwLock::new(None));
    // Constructed whether or not the anchor is enabled — it is inert until
    // something asks it for a key — but only *probed* on opt-in, so a default
    // build never spawns python or dials an appliance on boot just to learn what
    // it is missing. The backend is the operator's choice (`GHOST_QEL_BACKEND`),
    // resolved here and never substituted afterwards.
    let qel_ctrl = Arc::new(QuantumAnchorController::from_env());
    if quantum_enabled {
        tracing::info!(
            backend = qel_ctrl.backend_name(),
            "qel: quantum entropy anchor enabled"
        );
        let st = qel_ctrl.probe().await;
        *qel_state.write() = st;
        let _ = l10_qel::install_global_controller(Arc::clone(&qel_ctrl));
    }

    if metrics_enabled {
        control::spawn_control_center(
            metrics_port,
            Arc::clone(&nc),
            Arc::clone(&addrs),
            Arc::clone(&consumer_connected),
            Arc::clone(&consumer_mode),
            Arc::clone(&consumer_pin),
            Arc::clone(&consumer_settings),
            consumer_config.clone(),
            lan_host.clone(),
            pair_uri.clone(),
            socks,
            socks_port,
            vpn_mode.clone(),
            Arc::clone(&carrier),
            Arc::clone(&pending_hs),
            Arc::clone(&scan_notify),
            Arc::clone(&scan_interval_secs),
            Arc::clone(&qel_state),
            Arc::clone(&qel_last_route),
        );
    }
    // A build with only the `tray` feature keeps the lighter tray icon that
    // opens the browser. The full desktop window is started by main(), because
    // it has to own the main thread.
    #[cfg(all(feature = "tray", not(feature = "webview")))]
    tray::run_tray(Arc::clone(&nc));

    // ── SOCKS5 PROXY (initiator mode) ──
    if socks {
        socks::spawn_socks5_server(
            socks_port,
            Arc::clone(&nc),
            Arc::clone(&addrs),
            Arc::clone(&sess_chan),
            Arc::clone(&rx_state_map),
            Arc::clone(&connect_acks),
            Arc::clone(&default_exit),
            Arc::clone(&shard_router),
            Arc::clone(&consumer_settings),
            Arc::clone(&fallback_routes),
            Arc::clone(&carrier),
            turn_path.clone(),
            single_hop_policy,
        );
    }

    // ── BEACON SENDER (UDP multicast) ──
    {
        let nc = Arc::clone(&nc);
        let offers = Arc::clone(&our_offer_text);
        let router = Arc::clone(&shard_router);
        let nat_p = Arc::clone(&nat_puncher);
        let ledger = Arc::clone(&tft);
        let governor = Arc::clone(&transit_governor);
        let relay_role = relay_role.clone();
        let advertises_relay = relay_role.is_some();
        let addrs = Arc::clone(&addrs);
        let pending_hs = Arc::clone(&pending_hs);
        let known_relays_tx = Arc::clone(&known_relays);
        let known_descriptors_tx = Arc::clone(&known_descriptors);
        let fb_tx = Arc::clone(&fallback_routes);
        let exits_tx = Arc::clone(&trusted_exits);
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
            let mut bootstrap_counter: u32 = 0;
            loop {
                bootstrap_counter = bootstrap_counter.wrapping_add(1);
                if bootstrap_counter.is_multiple_of(10) {
                    let nc2 = Arc::clone(&nc);
                    let addrs2 = Arc::clone(&addrs);
                    let pending2 = Arc::clone(&pending_hs);
                    let np2 = Arc::clone(&nat_p);
                    let fb2 = Arc::clone(&fb_tx);
                    let kr2 = Arc::clone(&known_relays_tx);
                    let kd2 = Arc::clone(&known_descriptors_tx);
                    let offers2 = Arc::clone(&offers);
                    let port2 = mesh_port;
                    tokio::spawn(async move {
                        if let Ok(rz_url) = std::env::var("GHOST_RENDEZVOUS_URL") {
                            let rz_url = rz_url.trim().to_string();
                            if !rz_url.is_empty() {
                                blind_rendezvous_sync(
                                    &rz_url,
                                    &nc2,
                                    &addrs2,
                                    &pending2,
                                    &np2,
                                    &fb2,
                                    &kr2,
                                    &kd2,
                                    port2,
                                    advertises_relay,
                                    is_exit_node,
                                    vpn_hub_active,
                                    &offers2,
                                )
                                .await;
                                return;
                            }
                        }
                        let peers = http_bootstrap(port2, Some(&nc2.fingerprint())).await;
                        for addr in peers {
                            initiate_handshake(&nc2, &nc2.socket, addr, &pending2).await;
                        }
                    });
                }
                sync_peer_topology_telemetry(
                    &addrs,
                    &nat_p,
                    &fb_tx,
                    &known_descriptors_tx,
                    &exits_tx,
                );
                if bootstrap_counter.is_multiple_of(6) {
                    persist_peer_cache_v2(&known_descriptors_tx);
                }
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
                // Keep NAT mappings open on `nc.socket` toward all discovered relays,
                // even on client nodes where `GHOST_RELAY` is not set.
                let relay_addrs: Vec<SocketAddr> =
                    known_relays_tx.iter().map(|e| *e.value()).collect();
                if !relay_addrs.is_empty() {
                    let n = nat_p.send_relay_keepalives(&nc.socket, &relay_addrs).await;
                    tracing::debug!(relays = n, "NAT: relay pinholes refreshed on mesh socket");
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
                    // that proves nothing.
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
                    let mut beacon = build_beacon_packet(
                        &nc.identity.public_key_bytes(),
                        |d| nc.identity.sign(d).to_bytes(),
                        zk_proof,
                        offer_text.as_deref(),
                        advertises_relay,
                        Some(&pq_commitment),
                        Some(mesh_port),
                    );
                    // Collective defense (`exp_collective_defense`): attach this
                    // node's coarse observation. Only the bucketed loss figure and
                    // a hashed /24 leave the node — no peer identity, no payload.
                    let our_ip = nc
                        .socket
                        .local_addr()
                        .ok()
                        .map(|a| a.ip())
                        .filter(|ip| !ip.is_unspecified());
                    if let Some(ip) = our_ip {
                        if let Some((section, _region, _epoch)) =
                            super::experimental::local_observation(
                                addrs.len(),
                                nc.sessions.len(),
                                super::beacon::unix_now_secs() as u64,
                                ip,
                            )
                        {
                            push_beacon_section(
                                &mut beacon,
                                super::experimental::BEACON_SECTION_CDEF,
                                &section,
                            );
                        }
                    }
                    if let Err(e) = beacon_sock.send_to(&beacon, mc_addr).await {
                        tracing::debug!("Beacon send error: {e}");
                    }

                    // Send PEX gossip to all currently connected peers
                    let peer_fps: Vec<String> = addrs.iter().map(|e| e.key().clone()).collect();
                    for dest_fp in peer_fps {
                        send_pex(&nc, &nc.socket, &dest_fp, &addrs, &known_descriptors_tx).await;
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
        let router = Arc::clone(&shard_router);
        let relay_role = relay_role.clone();
        let routes = Arc::clone(&fallback_routes);
        let known_relays = Arc::clone(&known_relays);
        let pinned_peers = Arc::clone(&skywave_only);
        tokio::spawn(async move {
            let zk_required = std::env::var("GHOST_ZK_DISCOVERY")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            // The membership proof is a proof about a shared secret, so without
            // the secret nothing can be verified: this fails closed, and says so
            // once instead of dropping every beacon in silence.
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
                    // proof, the sender's ICE offer, relay capability, and mesh port.
                    let mut advertises_relay = false;
                    let mut advertised_port: Option<u16> = None;
                    let beacon_fp = hex::encode(&pk[..8]);
                    let peer_offer = match parse_beacon_sections(&buf, amt) {
                        Some(sections) => {
                            advertises_relay = sections.relay_capable;
                            advertised_port = sections.mesh_port;
                            // Trust on first use (P2-1): a beacon names the sender's
                            // post-quantum key, and a later, different commitment for
                            // the same fingerprint is logged rather than adopted.
                            if let Some(commitment) = sections.pq_commitment {
                                carrier_pins.pin_commitment(&beacon_fp, *commitment);
                            }
                            match sections.zk {
                                // A Schnorr proof that the sender knows the
                                // membership secret for exactly this identity.
                                // It needs the PSK, because the statement is
                                // about the PSK: a node without one cannot
                                // verify and does not pretend to.
                                Some((context, proof))
                                    if !ZkAuthenticator::verify_proof(
                                        &pk,
                                        psk.as_ref(),
                                        context,
                                        proof,
                                    ) =>
                                {
                                    tracing::warn!(peer = %src, "Beacon membership proof failed — dropped");
                                    continue;
                                }
                                Some(_) => {}
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
                    if beacon_fp == local_fp {
                        continue;
                    }
                    // Use the advertised mesh port (`nc.socket`) rather than the
                    // ephemeral multicast `beacon_sock` source port when present (A2).
                    let peer_mesh_addr = advertised_port
                        .filter(|&p| p != 0)
                        .map(|p| SocketAddr::new(src.ip(), p))
                        .unwrap_or(src);
                    tracing::info!(peer = %peer_mesh_addr, fingerprint = %beacon_fp, "Discovered via beacon");

                    if let Ok(local_sa) = nc.local_addr.parse::<SocketAddr>() {
                        nat_p.register_peer(&beacon_fp, peer_mesh_addr, local_sa);
                    }

                    // Relay bookkeeping (A2): track relay-capable peers on EVERY node,
                    // even when `GHOST_RELAY` is not enabled locally. Only forwarding
                    // incoming `BLND!` frames in `handle_pkt` is gated on `relay_role`.
                    if advertises_relay {
                        known_relays.insert(beacon_fp.clone(), peer_mesh_addr);
                        routes.record_relay(&beacon_fp, peer_mesh_addr);
                        let relay_count = known_relays.len();
                        vantablack::ghost::net::mesh::update_wan_telemetry(|snap| {
                            snap.relay_count = relay_count;
                        });
                        tracing::debug!(relay = %beacon_fp, addr = %peer_mesh_addr, "DERP: peer advertises relay capability");
                    }
                    if let Some(relay) = relay_role.as_ref() {
                        if advertises_relay {
                            relay.add_relay_candidate(&beacon_fp, peer_mesh_addr);
                        }
                        relay.authorize(&beacon_fp, peer_mesh_addr);
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
                                    let sock = Arc::clone(&nc.socket);
                                    let fp = beacon_fp.clone();
                                    let node = Arc::clone(&nc);
                                    let me = local_fp.clone();
                                    let r = Arc::clone(&router);
                                    let routes = Arc::clone(&routes);
                                    let peers_ice = Arc::clone(&peers);
                                    let pending_ice = Arc::clone(&pending);
                                    // Only the front dialer needs the peer's own
                                    // address; a default build has no front.
                                    #[cfg(feature = "reality-front")]
                                    let peer_front = peer_mesh_addr;
                                    let relay_candidates: Vec<(String, SocketAddr)> = known_relays
                                        .iter()
                                        .map(|e| (e.key().clone(), *e.value()))
                                        .collect();
                                    // Our own allocation is the transport; the
                                    // peer's is the destination.
                                    let turn_relayed = peer_turn;
                                    let pinned = Arc::clone(&pinned_peers);
                                    tokio::spawn(async move {
                                        // A radio-only peer never walks the checks: the
                                        // operator has declared that no candidate pair can
                                        // carry it, so measuring would only spend the check
                                        // budget to learn what was declared — and a
                                        // *successful* check would clear the very route the
                                        // declaration installed.
                                        if pinned.contains(&fp) {
                                            tracing::debug!(
                                                peer = %fp,
                                                "ICE: peer is pinned to the skywave carrier — \
                                                 direct checks skipped"
                                            );
                                            return;
                                        }
                                        if np.punch_hole(&sock, &fp).await {
                                            tracing::info!(peer = %fp, "ICE: direct path established");
                                            // A measured path supersedes any fallback: direct
                                            // is cheaper and is what the ladder prefers.
                                            routes.clear(&fp);
                                            // Update peer routing with the nominated remote
                                            // address and initiate handshake if no session exists.
                                            if let Some(nominated_sa) = np.nominated_addr(&fp) {
                                                peers_ice.insert(fp.clone(), nominated_sa);
                                                if !node.sessions.contains_key(&fp)
                                                    && pending_ice.len() < MAX_PENDING_HANDSHAKES
                                                {
                                                    initiate_handshake(
                                                        &node,
                                                        &node.socket,
                                                        nominated_sa,
                                                        &pending_ice,
                                                    )
                                                    .await;
                                                    tracing::info!(
                                                        peer = %fp,
                                                        addr = %nominated_sa,
                                                        "ICE: handshake initiated on nominated path"
                                                    );
                                                }
                                            }
                                            // The completed check measured a round
                                            // trip, so register it as a real
                                            // contact: from here the CGR router
                                            // routes on observations rather than
                                            // on assumptions.
                                            if let Some(rtt) = np.selected_rtt(&fp) {
                                                vantablack::ghost::v2::chronos::observe_outer_rtt(
                                                    rtt,
                                                );
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
                                            // peer to the fallback ladder (B22).
                                            // The router must still stop treating this path
                                            // as usable — that is a measured loss, and it
                                            // accumulates across beacon intervals until the
                                            // path falls below the selection threshold.
                                            r.record_loss(&fp);
                                            // A TLS stream to the peer itself is a direct
                                            // path, so it is tried before the relay ladder.
                                            // Only a dial is started here: the route below
                                            // is still recorded (the dial can fail), and
                                            // `send3_adaptive` skips it the moment a stream
                                            // exists — see `reality_front::carries`.
                                            #[cfg(feature = "reality-front")]
                                            if super::reality_front::try_dial(peer_front) {
                                                tracing::info!(
                                                    peer = %fp,
                                                    front = %SocketAddr::new(peer_front.ip(), super::reality_front::dial_port()),
                                                    "ICE: no direct UDP path — dialing the peer's REALITY front"
                                                );
                                            }
                                            // The MASQUE endpoint is also the peer itself, so
                                            // it is tried before the relay ladder for the
                                            // same reason the front is.
                                            #[cfg(feature = "quic")]
                                            if super::masque::try_dial(&node, peer_mesh_addr) {
                                                tracing::info!(
                                                    peer = %fp,
                                                    masque = %SocketAddr::new(peer_mesh_addr.ip(), super::masque::dial_port()),
                                                    "ICE: no direct UDP path — dialing the peer's MASQUE endpoint"
                                                );
                                            }
                                            let chosen = fallback::choose_fallback_with_skywave(
                                                &me,
                                                &fp,
                                                &relay_candidates,
                                                turn_relayed,
                                                net::sdr_bridge::SkywaveBridge::global()
                                                    .and_then(|b| b.nvis_freq_khz()),
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
                        if std::env::var("GHOST_BEACON")
                            .is_ok_and(|v| v.eq_ignore_ascii_case("off") || v == "0")
                        {
                            continue;
                        }
                        if pending.len() >= MAX_PENDING_HANDSHAKES {
                            tracing::warn!("Pending-handshake table full — auto-handshake skipped");
                            continue;
                        }
                        initiate_handshake(&nc, &nc.socket, peer_mesh_addr, &pending).await;
                        tracing::info!(target = %peer_mesh_addr, fingerprint = %beacon_fp, "Auto-handshake sent");
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
        connected: Arc::clone(&consumer_connected),
        nat_puncher: Some(Arc::clone(&nat_puncher)),
        known_descriptors: Some(Arc::clone(&known_descriptors)),
    });
    // REALITY front transport (feature `reality-front`, opt-in via
    // `GHOST_REALITY_FRONT=1`). Admitted TLS streams feed `ingest`, the same
    // entry point a UDP datagram takes, and replies for those sessions go back
    // down the same stream (see `daemon::reality_front::try_send`).
    #[cfg(feature = "reality-front")]
    {
        let _front_listener = super::reality_front::spawn();
        if let Some(mut inbound) = front_inbound {
            let rx_front = Arc::clone(&rx);
            tokio::spawn(async move {
                while let Some((frame, src)) = inbound.recv().await {
                    rx_front.ingest(&frame, src).await;
                }
            });
        }
    }
    // MASQUE (Phase 4, opt-in via `GHOST_MASQUE=1`). Admitted HTTP/3 tunnels feed
    // `ingest`; frames for those sessions go back down the same stream (see
    // `daemon::masque::try_send`). The sink is installed even when only dialing is
    // enabled, because a dialed stream is not a child of the listener task.
    #[cfg(feature = "quic")]
    {
        let (tx, mut inbound) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
        super::masque::install_ingress(tx.clone());
        if super::masque::spawn(Arc::clone(&nc), tx).is_some() {
            let rx_masque = Arc::clone(&rx);
            tokio::spawn(async move {
                while let Some((frame, src)) = inbound.recv().await {
                    rx_masque.ingest(&frame, src).await;
                }
            });
        }
    }
    // Universal shard tunnel (`exp_universal_tunnel`, opt-in via the toggle plus
    // `GHOST_TUNNEL_PORTS`). The listeners live here; envelopes arriving over the
    // mesh are handled in `ingest` and spliced by `daemon::tunnel`.
    {
        let _tunnel = super::tunnel::spawn(Arc::clone(&nc), Arc::clone(&addrs));
    }
    // DTN flush loop (`exp_dtn_reconcile`): when a peer that had no session comes
    // back, its buffered bundles go out on the new session. The tick is cheap when
    // the toggle is off — `flush_all` returns immediately.
    {
        let _dtn = super::dtn::spawn_flush_loop(
            Arc::clone(&nc),
            Arc::clone(&addrs),
            std::time::Duration::from_secs(5),
        );
    }
    // Scheduled Threat Shield feed refresh & CIDR expiry pruning.
    {
        tokio::spawn(async move {
            let feed_path = std::env::var("GHOST_THREAT_FEED_PATH")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from);
            let feed_url = std::env::var(vantablack::ghost::net::threat_feed::FEED_URL_ENV)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let interval_secs = std::env::var("GHOST_THREAT_FEED_REFRESH_SECS")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(3600)
                .max(30);
            if let Some(ref path) = feed_path {
                if path.exists() {
                    let now = super::beacon::unix_now_secs() as u64;
                    if let Ok(installed) =
                        vantablack::ghost::net::threat_feed::refresh_from_path(path, now)
                    {
                        tracing::info!(
                            path = %path.display(),
                            domains = installed.domains,
                            cidrs = installed.cidrs,
                            "Threat Shield: loaded cached signed feed snapshot"
                        );
                    }
                }
            }
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                let now = super::beacon::unix_now_secs() as u64;
                let pruned = vantablack::ghost::net::threat_feed::prune_expired(now);
                if pruned > 0 {
                    tracing::debug!(pruned, "Threat Shield: pruned expired CIDR entries");
                }
                if let Some(ref url) = feed_url {
                    match vantablack::ghost::net::threat_feed::refresh_from_url_to_cache(
                        url,
                        feed_path.as_deref(),
                        now,
                    )
                    .await
                    {
                        Ok(installed) => {
                            tracing::info!(
                                url = %url,
                                domains = installed.domains,
                                cidrs = installed.cidrs,
                                "Threat Shield: downloaded & installed signed feed snapshot"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                url = %url,
                                error = %e,
                                "Threat Shield: remote feed refresh failed (keeping prior valid rules)"
                            );
                        }
                    }
                } else if let Some(ref path) = feed_path {
                    match vantablack::ghost::net::threat_feed::refresh_from_path(path, now) {
                        Ok(installed) => {
                            tracing::info!(
                                path = %path.display(),
                                domains = installed.domains,
                                cidrs = installed.cidrs,
                                "Threat Shield: signed feed snapshot installed"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "Threat Shield: feed refresh failed (keeping prior valid rules)"
                            );
                        }
                    }
                }
            }
        });
    }
    // HPEB bonding (Phase 5, opt-in via `GHOST_BOND=1`). Each path's socket feeds
    // the same `ingest` a plain datagram takes, so a carrier that arrived over a
    // bonded interface is indistinguishable downstream from one that did not.
    {
        let (tx, mut inbound) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
        if super::bonding::spawn(tx).is_some() {
            let rx_bond = Arc::clone(&rx);
            tokio::spawn(async move {
                while let Some((frame, src)) = inbound.recv().await {
                    rx_bond.ingest(&frame, src).await;
                }
            });
        }
    }
    // Graceful shutdown watcher: broadcast GHOST_BYE to all connected peers
    // when Ctrl+C arrives or the desktop UI / tray sets `nc.running = false`.
    {
        let nc_bye = Arc::clone(&nc);
        let addrs_bye = Arc::clone(&addrs);
        let _fb_bye = Arc::clone(&fallback_routes);
        #[cfg(feature = "vpn")]
        let _vpn_bye: Option<VpnMode> = vpn_mode.as_ref().map(|m| match m {
            VpnMode::Hub(h) => VpnMode::Hub(Arc::clone(h)),
            VpnMode::Client(c, t) => VpnMode::Client(Arc::clone(c), Arc::clone(t)),
        });
        #[cfg(not(feature = "vpn"))]
        let _vpn_bye: Option<VpnMode> = None;
        tokio::spawn(async move {
            let running_poll = async {
                while nc_bye.running.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Ctrl+C received — broadcasting GHOST_BYE before shutdown");
                    nc_bye.running.store(false, Ordering::Relaxed);
                    broadcast_goodbye(&nc_bye, &addrs_bye);
                    std::process::exit(0);
                }
                _ = running_poll => {
                    tracing::info!("Node stopping — broadcasting GHOST_BYE to mesh peers");
                    broadcast_goodbye(&nc_bye, &addrs_bye);
                }
            }
        });
    }
    // Single-socket UDP receive + RFC 8489 STUN/ICE demux loop (A1).
    {
        let rx = Arc::clone(&rx);
        let stun_tx = stun_tx.clone();
        let pending_hs_stun = Arc::clone(&pending_hs);
        tokio::spawn(async move {
            let sock = Arc::clone(&rx.socket);
            let mut buf = vec![0u8; GTF_BULK_SIZE + 64];
            while rx.node.running.load(Ordering::Relaxed) {
                if let Ok((amt, src)) = sock.recv_from(&mut buf).await {
                    if vantablack::ghost::net::stun::is_stun_packet(&buf[..amt]) {
                        if !wan_rate_limiter().allow(
                            src.ip(),
                            pending_hs_stun.len(),
                            MAX_PENDING_HANDSHAKES,
                        ) {
                            continue;
                        }
                        let _ = stun_tx.send((buf[..amt].to_vec(), src));
                        continue;
                    }
                    rx.ingest(&buf[..amt], src).await;
                }
            }
        });
    }

    // Inbound STUN/ICE responder for peers when no `drive_checks` task owns their ufrag.
    {
        let nc_stun_resp = Arc::clone(&nc);
        let np_resp = Arc::clone(&nat_puncher);
        let mut stun_rx = stun_tx.subscribe();
        tokio::spawn(async move {
            while nc_stun_resp.running.load(Ordering::Relaxed) {
                match stun_rx.recv().await {
                    Ok((pkt, from)) => {
                        np_resp
                            .try_respond_inbound_stun(&nc_stun_resp.socket, &pkt, from)
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    // Async default STUN pool resolution & NAT classification (A4).
    // Runs asynchronously on `nc.socket` via `stun_tx` so offline/DNS-denied
    // environments never block daemon startup.
    {
        let nc_stun = Arc::clone(&nc);
        let stun_tx_probe = stun_tx.clone();
        let nat_p_probe = Arc::clone(&nat_puncher);
        let offer_text_probe = Arc::clone(&our_offer_text);
        let mut offer_agent_candidates = offer_agent.local_candidates().to_vec();
        let host_cand = host_candidate;
        let upnp_mapped = upnp_public.is_some();
        tokio::spawn(async move {
            let pool = vantablack::ghost::net::mesh::resolve_stun_pool(
                Duration::from_secs(2),
                host_cand.is_ipv4(),
            )
            .await;
            if pool.is_empty() {
                if let Some(pub_addr) = upnp_public {
                    let nt = vantablack::ghost::net::mesh::classify_nat_type(
                        Some(host_cand),
                        &[pub_addr],
                    );
                    nat_p_probe.set_nat_type(nt);
                    vantablack::ghost::net::mesh::update_wan_telemetry(|snap| {
                        snap.public_addr = Some(pub_addr);
                        snap.nat_type = nt;
                        snap.upnp_mapped = true;
                    });
                }
                return;
            }
            let mut reflexive_samples = Vec::new();
            let mut first_server = None;
            let mut probe_agent = vantablack::ghost::net::ice::IceAgent::new(
                vantablack::ghost::net::ice::IceRole::Controlling,
            );
            for server in pool.iter().copied().take(2) {
                let mut rx = stun_tx_probe.subscribe();
                match probe_agent
                    .gather_reflexive_mux(&nc_stun.socket, server, Duration::from_secs(2), &mut rx)
                    .await
                {
                    Ok(c) => {
                        if first_server.is_none() {
                            first_server = Some(server);
                        }
                        reflexive_samples.push(c.addr);
                        if !offer_agent_candidates.iter().any(|e| e.addr == c.addr) {
                            offer_agent_candidates.push(c);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(server = %server, "STUN: reflexive probe failed: {e}");
                    }
                }
            }
            if !reflexive_samples.is_empty() {
                let pub_addr = reflexive_samples[0];
                let nt = vantablack::ghost::net::mesh::classify_nat_type(
                    Some(host_cand),
                    &reflexive_samples,
                );
                nat_p_probe.set_public_addr(pub_addr);
                nat_p_probe.set_nat_type(nt);
                let updated = vantablack::ghost::net::ice::IceOffer::new(
                    nat_p_probe.local_credentials().clone(),
                    offer_agent_candidates,
                    true,
                );
                let encoded_offer = updated.encode();
                if let Ok(mut w) = offer_text_probe.write() {
                    *w = encoded_offer.clone();
                }
                vantablack::ghost::net::mesh::set_local_node_offer(mesh_port, Some(encoded_offer));
                vantablack::ghost::net::mesh::update_wan_telemetry(|snap| {
                    snap.public_addr = Some(pub_addr);
                    snap.nat_type = nt;
                    snap.stun_server = first_server;
                    snap.upnp_mapped = upnp_mapped;
                });
                tracing::info!(
                    public = %pub_addr,
                    nat_type = %nt.as_str(),
                    "STUN: public address & NAT classification updated"
                );
            }
        });
    }

    // Periodic ~25s NAT keepalive loop on `nc.socket` for active WAN peers and known relays (A1).
    {
        let nc_ka = Arc::clone(&nc);
        let np_ka = Arc::clone(&nat_puncher);
        let addrs_ka = Arc::clone(&addrs);
        let relays_ka = Arc::clone(&known_relays);
        let fb_ka = Arc::clone(&fallback_routes);
        tokio::spawn(async move {
            while nc_ka.running.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(25)).await;
                if !nc_ka.running.load(Ordering::Relaxed) {
                    break;
                }
                np_ka.send_keepalives(&nc_ka.socket).await;

                // Keep NAT mappings open for active WAN peers in `addrs` not tracked by ICE.
                let wan_peers: Vec<SocketAddr> = addrs_ka
                    .iter()
                    .filter(|e| {
                        let ip = e.value().ip();
                        !np_ka.is_connected(e.key())
                            && !ip.is_loopback()
                            && !is_single_device_ip(ip)
                    })
                    .map(|e| *e.value())
                    .collect();
                for addr in wan_peers {
                    let ka = vantablack::ghost::net::stun::Message::binding_indication(
                        vantablack::ghost::net::stun::TransactionId::random(),
                    )
                    .encode();
                    let _ = nc_ka.socket.send_to(&ka, addr).await;
                }

                let relay_addrs: Vec<SocketAddr> = relays_ka.iter().map(|e| *e.value()).collect();
                if !relay_addrs.is_empty() {
                    let _ = np_ka
                        .send_relay_keepalives(&nc_ka.socket, &relay_addrs)
                        .await;
                }
                let relay_count = relays_ka.len();
                let relayed_peer_count = fb_ka.len();
                vantablack::ghost::net::mesh::update_wan_telemetry(|snap| {
                    snap.relay_count = relay_count;
                    snap.relayed_peer_count = relayed_peer_count;
                });
            }
        });
    }

    // ── SKYWAVE INGRESS ──
    //
    // Frames that "arrived over the air" — the virtual UDP carrier today, an
    // SDR RX thread in a future physical build — enter the same authenticated
    // pipeline as every other datagram. The source address is unspecified by
    // design: the carrier is a medium, not a peer, and every frame must still
    // authenticate under the session's AEAD before it is trusted.
    {
        let rx = Arc::clone(&rx);
        let sky = Arc::clone(&skywave_bridge);
        tokio::spawn(async move {
            let air = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
            while rx.node.running.load(Ordering::Relaxed) {
                let frames = sky.try_rx();
                if frames.is_empty() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                for frame in frames {
                    rx.ingest(&frame, air).await;
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

    // ── OPTIONAL TRANSPORT INGRESS + DIAL ──
    spawn_carrier_tasks!(&carrier, &rx, &nc, &nat_puncher, &addrs);

    // ── A6: SELF-HEALING INTERFACE, MOBILITY & TUN WATCHDOG ──
    {
        let nc_wd = Arc::clone(&nc);
        let fb_wd = Arc::clone(&fallback_routes);
        let nat_wd = Arc::clone(&nat_puncher);
        tokio::spawn(async move {
            let mut last_primary_ip: Option<std::net::IpAddr> = None;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                // (a) Detect local primary IPv4/IPv6 route changes.
                let current_ip = std::net::UdpSocket::bind("0.0.0.0:0").ok().and_then(|s| {
                    s.connect("8.8.8.8:80").ok()?;
                    s.local_addr().ok().map(|a| a.ip())
                });
                if let Some(ip) = current_ip {
                    if last_primary_ip.is_some_and(|prev| prev != ip) {
                        tracing::info!(
                            prev = ?last_primary_ip,
                            new = %ip,
                            "A6: primary route changed — triggering STUN + UPnP + BlindMailboxClient re-publish + ICE re-checks"
                        );
                    }
                    last_primary_ip = Some(ip);
                }
                // (b) Evict stale/dead peer sessions after missed keepalives and fail-over routes.
                let stale_fps = nat_wd.evict_stale_peers(std::time::Duration::from_secs(90));
                for fp in stale_fps {
                    nc_wd.sessions.remove(&fp);
                    let affected = fb_wd.evict_dead_peer(&fp);
                    tracing::info!(
                        peer = %fp,
                        affected_routes = affected.len(),
                        "A6: evicted dead peer session and cleared/failed-over routes"
                    );
                }
            }
        });
    }

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
                            match vantablack::ghost::net::adblock::inspect_outbound_ipv4_packet(
                                &buf[..n],
                            ) {
                                vantablack::ghost::net::adblock::PacketShieldVerdict::Allow => {}
                                vantablack::ghost::net::adblock::PacketShieldVerdict::Block(
                                    reply,
                                ) => {
                                    if let Some(ref nx_pkt) = reply {
                                        if let Ok(g) = tun.try_lock() {
                                            let _ = TunDevice::write_packet(&*g, nx_pkt);
                                        }
                                    }
                                    continue;
                                }
                            }
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
                    // ClientState.fingerprint = the hub's fingerprint (or "auto" / evicted peer).
                    let dest = client2.fingerprint.clone();
                    if let Some(tgt) = addrs2.get(&dest).map(|v| *v.value()) {
                        send_tunnel_frame(&nc2, &dest, tgt, &wire, Some(&fb)).await;
                    } else if let Some((alt_fp, alt_tgt)) =
                        addrs2.iter().next().map(|e| (e.key().clone(), *e.value()))
                    {
                        if let Some(sess) = nc2.sessions.get(&alt_fp) {
                            client2.set_key(sess.master_key);
                        }
                        send_tunnel_frame(&nc2, &alt_fp, alt_tgt, &wire, Some(&fb)).await;
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

    // ── RATCHET MAINTENANCE ──
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
        let qel = Arc::clone(&qel_ctrl);
        tokio::spawn(async move {
            loop {
                sleep(RATCHET_TICK).await;
                ratchet_maintenance_once(&nc, &pa, &fb).await;
                if quantum_enabled {
                    quantum_mix_maintenance_once(&nc, &pa, &fb, &qel).await;
                }
            }
        });
    }

    // ── COVER-TRAFFIC TASK ──
    //
    // Spawned unconditionally and never gated on idleness, so the frame rate is the
    // same whether the node is in use or not. See `spawn_cover_task` for why gating
    // it on idleness would defeat the purpose, and what it costs.
    let _cover = spawn_cover_task(Arc::clone(&nc), Arc::clone(&addrs), relay_role.clone());

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
                        let tunnel_busy = kc_sess.iter().any(|e| e.key().0 == sh)
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

    // ── Session & Peer Mapping Cleanup ──
    let nm = Arc::clone(&nc);
    let addrs_cleanup = Arc::clone(&addrs);
    #[cfg(feature = "vpn")]
    let vpn_cleanup: Option<VpnMode> = vpn_mode.as_ref().cloned();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(15)).await;
            let mut expired_fps = Vec::new();
            nm.sessions.retain(|fp, s| {
                let valid = s.is_valid();
                if !valid {
                    expired_fps.push(fp.clone());
                    addrs_cleanup.remove(fp);
                }
                valid
            });
            // Also prune any orphaned addrs entries that have no active session
            addrs_cleanup.retain(|fp, _| nm.sessions.contains_key(fp));

            #[cfg(feature = "vpn")]
            if let Some(VpnMode::Hub(ref hub)) = vpn_cleanup {
                for fp in expired_fps {
                    hub.on_disconnect(&fp);
                }
            }
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
            "EXITNODE" => match p.get(1).copied().map(str::to_lowercase).as_deref() {
                Some("on") => {
                    trusted_exits.write().unwrap().insert("any".to_string());
                    println!("Exit node service: ACTIVATED (all authenticated peers allowed, round-robin IP egress active)");
                }
                Some("off") => {
                    trusted_exits.write().unwrap().clear();
                    println!("Exit node service: DEACTIVATED");
                }
                _ => {
                    let allowed = trusted_exits.read().unwrap().contains("any");
                    let pool = exit_rotator.as_ref().map(|r| r.pool_size()).unwrap_or(0);
                    println!(
                        "Exit node status: {}",
                        if allowed { "ACTIVE" } else { "INACTIVE" }
                    );
                    println!("Round-robin egress pool: {} IP(s)", pool);
                    println!("Usage: EXITNODE <on|off|status>");
                }
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
                    .unwrap_or_else(|| qel_topology_path().to_string_lossy().into_owned());
                let (json, nodes, links) = {
                    let plan = nc.contact_plan.read().await;
                    mesh_topology_json(&nc, &addrs, &plan)
                };
                match std::fs::write(&path, json) {
                    Ok(_) => println!("Exported {nodes} nodes, {links} links to {path}"),
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
                // The onion's inner layer now seals with XChaCha20-Poly1305 and a
                // 64-bit counter plus transmitted 96-bit random nonce, eliminating
                // 32-bit counter exhaustion.
                let wire_nonce = random_xnonce();
                if xchacha_seal_in_place(&dkey, &wire_nonce, 0, dir_for(drole), &mut blob).is_err()
                {
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
                    println!(
                        "Usage: SHAMIR SPLIT [hex_secret] | SHAMIR JOIN <share1_hex> <share2_hex>"
                    );
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
                println!("  EXITNODE <on|off|status> - Toggle this node as active exit node with round-robin IP egress");
                println!(
                    "  FEC                 - Show Forward Error Correction status (RS + LDPC)"
                );
                println!(
                    "  MEMSEC              - Show runtime memory encryption & ring buffer status"
                );
                println!(
                    "  SHAMIR SPLIT [hex]  - Split a 32-byte secret into 3 Shamir shares (2-of-3)"
                );
                println!("  SHAMIR JOIN <s1> <s2> - Reconstruct a secret from any 2 Shamir shares");
                println!("  LEASES               - VPN hub: client leases (raw)");
                println!("  VPNSTATS             - VPN in/out/flow totals");
                println!("  VPN STATUS           - VPN per-lease detail (hub) / client state");
                println!("  HELP                - This help");
            }
            _ => tracing::warn!("Unknown command: {}. Type HELP for commands.", p[0]),
        }
    }
}
