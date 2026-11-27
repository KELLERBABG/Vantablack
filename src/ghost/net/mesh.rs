//! Mesh Topology and Peer Discovery Engine.
//!
//! Manages peer discovery via bootstrap seeds, STUN hole-punching,
//! contact plan maintenance, multi-hop relay coordination, and background gossip.

use std::net::SocketAddr;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::ghost::layers::l2_aead::xchacha_seal_in_place_with_aad;
use crate::ghost::layers::l4_rs;
use crate::ghost::net::cc;
use crate::ghost::net::routing::{ContactPlan, PoissonReputationMatrix, RouteOptions, Timestamp};
use crate::ghost::net::{frame_shard, ice, send_gtf_v2, stun, GtfV2Header};
use crate::ghost::session::Session;

pub const EMBEDDED_DEFAULT_CONFIG: &[(&str, u16, &str)] = &[
    ("51.15.xx.xx", 2270, "deadbeef12345678"),
    ("45.33.xx.xx", 2270, "cafebabe87654321"),
    ("139.162.xx.xx", 2270, "baadf00dabcdef01"),
];

#[derive(Debug, Clone)]
pub struct NatBinding {
    pub public_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub last_verified: Instant,
    pub punch_successes: u32,
    pub lifetime_secs: u64,
}

#[derive(Debug, Clone)]
pub struct NatPeerState {
    pub fingerprint: String,
    pub public_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub connected: bool,
    pub last_keepalive: Instant,
}

const STUN_TIMEOUT: Duration = Duration::from_secs(3);

const ICE_CHECK_BUDGET: Duration = Duration::from_secs(10);

pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NatType {
    Direct,
    Cone,
    Restricted,
    Symmetric,
    #[default]
    Unknown,
}

impl NatType {
    pub fn as_str(self) -> &'static str {
        match self {
            NatType::Direct => "Direct",
            NatType::Cone => "Cone",
            NatType::Restricted => "Restricted",
            NatType::Symmetric => "Symmetric",
            NatType::Unknown => "Unknown",
        }
    }
}

pub fn classify_nat_type(
    local_addr: Option<SocketAddr>,
    reflexive_samples: &[SocketAddr],
) -> NatType {
    if reflexive_samples.is_empty() {
        return NatType::Unknown;
    }
    let first = reflexive_samples[0];
    if let Some(local) = local_addr {
        if !local.ip().is_unspecified() && local.ip() == first.ip() && local.port() == first.port()
        {
            return NatType::Direct;
        }
    }
    if reflexive_samples.len() >= 2 {
        let same_mapping = reflexive_samples
            .iter()
            .all(|s| s.ip() == first.ip() && s.port() == first.port());
        if same_mapping {
            return NatType::Cone;
        }
        return NatType::Symmetric;
    }
    NatType::Restricted
}

pub fn stun_disabled_from_env() -> bool {
    let stun_off = std::env::var("GHOST_STUN")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "off" | "0" | "false" | "disabled"
            )
        })
        .unwrap_or(false);
    let server_off = std::env::var("GHOST_STUN_SERVER")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "off" | "0" | "false" | "disabled"
            )
        })
        .unwrap_or(false);
    stun_off || server_off
}

pub async fn resolve_stun_pool(timeout_per_host: Duration, ipv4_only: bool) -> Vec<SocketAddr> {
    if stun_disabled_from_env() {
        return Vec::new();
    }
    let entries: Vec<String> = match std::env::var("GHOST_STUN_SERVER") {
        Ok(val) if !val.trim().is_empty() => val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => DEFAULT_STUN_SERVERS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    };

    let mut resolved = Vec::new();
    for entry in entries {
        if let Ok(sa) = entry.parse::<SocketAddr>() {
            if (!ipv4_only || sa.is_ipv4()) && !resolved.contains(&sa) {
                resolved.push(sa);
            }
            continue;
        }
        if let Ok(Ok(addrs)) =
            tokio::time::timeout(timeout_per_host, tokio::net::lookup_host(&entry)).await
        {
            for sa in addrs {
                if (!ipv4_only || sa.is_ipv4()) && !resolved.contains(&sa) {
                    resolved.push(sa);
                    break; // One address per STUN hostname keeps probing fast
                }
            }
        }
    }
    resolved
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WanTelemetrySnapshot {
    pub public_addr: Option<SocketAddr>,
    pub nat_type: NatType,
    pub stun_server: Option<SocketAddr>,
    pub relay_count: usize,
    pub relayed_peer_count: usize,
    pub upnp_mapped: bool,
    pub updated_unix_secs: u64,
}

static WAN_TELEMETRY: std::sync::OnceLock<std::sync::RwLock<WanTelemetrySnapshot>> =
    std::sync::OnceLock::new();

fn wan_telemetry_cell() -> &'static std::sync::RwLock<WanTelemetrySnapshot> {
    WAN_TELEMETRY.get_or_init(|| std::sync::RwLock::new(WanTelemetrySnapshot::default()))
}

pub fn wan_telemetry_snapshot() -> WanTelemetrySnapshot {
    wan_telemetry_cell()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub fn update_wan_telemetry<F: FnOnce(&mut WanTelemetrySnapshot)>(f: F) {
    let mut guard = wan_telemetry_cell()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    f(&mut guard);
    guard.updated_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PeerTopologyTelemetry {
    pub rtt_ms: Option<f64>,
    pub transport: Option<String>,
    pub via_relay_fp: Option<String>,
    pub is_exit: bool,
}

static PEER_TELEMETRY: std::sync::OnceLock<
    std::sync::RwLock<std::collections::HashMap<String, PeerTopologyTelemetry>>,
> = std::sync::OnceLock::new();

fn peer_telemetry_cell(
) -> &'static std::sync::RwLock<std::collections::HashMap<String, PeerTopologyTelemetry>> {
    PEER_TELEMETRY.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

pub fn update_peer_telemetry<F: FnOnce(&mut PeerTopologyTelemetry)>(fp: &str, f: F) {
    let mut guard = peer_telemetry_cell()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    let entry = guard.entry(fp.to_string()).or_default();
    f(entry);
}

pub fn remove_peer_telemetry(fp: &str) {
    let mut guard = peer_telemetry_cell()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    guard.remove(fp);
}

pub fn peer_telemetry_snapshot() -> std::collections::HashMap<String, PeerTopologyTelemetry> {
    peer_telemetry_cell()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

static LOCAL_NODE_OFFER: std::sync::OnceLock<std::sync::RwLock<(u16, Option<String>)>> =
    std::sync::OnceLock::new();

fn local_node_offer_cell() -> &'static std::sync::RwLock<(u16, Option<String>)> {
    LOCAL_NODE_OFFER.get_or_init(|| std::sync::RwLock::new((0, None)))
}

pub fn set_local_node_offer(mesh_port: u16, ice_offer: Option<String>) {
    let mut guard = local_node_offer_cell()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    *guard = (mesh_port, ice_offer);
}

pub fn local_node_offer() -> (u16, Option<String>) {
    local_node_offer_cell()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

struct ActiveUfragGuard {
    set: Arc<DashSet<String>>,
    ufrag: String,
}

impl Drop for ActiveUfragGuard {
    fn drop(&mut self) {
        self.set.remove(&self.ufrag);
    }
}

pub struct NatHolePuncher {
    peers: Arc<DashMap<String, NatPeerState>>,
    stun_server: Option<SocketAddr>,
    public_addr: std::sync::Mutex<Option<SocketAddr>>,
    nat_type: std::sync::Mutex<NatType>,
    offers: Arc<DashMap<String, ice::IceOffer>>,
    local_credentials: ice::IceCredentials,
    local_fingerprint: Option<String>,
    selected_rtts: Arc<DashMap<String, Duration>>,
    nominated_addrs: Arc<DashMap<String, SocketAddr>>,
    stun_mux: Option<broadcast::Sender<(Vec<u8>, SocketAddr)>>,
    active_ufrags: Arc<DashSet<String>>,
}

impl Default for NatHolePuncher {
    fn default() -> Self {
        Self {
            peers: Arc::new(DashMap::new()),
            stun_server: None,
            public_addr: std::sync::Mutex::new(None),
            nat_type: std::sync::Mutex::new(NatType::Unknown),
            offers: Arc::new(DashMap::new()),
            local_credentials: ice::IceCredentials::generate(),
            local_fingerprint: None,
            selected_rtts: Arc::new(DashMap::new()),
            nominated_addrs: Arc::new(DashMap::new()),
            stun_mux: None,
            active_ufrags: Arc::new(DashSet::new()),
        }
    }
}

impl NatHolePuncher {
    pub fn evict_stale_peers(&self, max_idle: Duration) -> Vec<String> {
        let stale: Vec<String> = self
            .peers
            .iter()
            .filter(|p| p.value().last_keepalive.elapsed() > max_idle)
            .map(|p| p.key().clone())
            .collect();
        for fp in &stale {
            self.peers.remove(fp);
        }
        stale
    }
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_stun_server(mut self, stun_addr: SocketAddr) -> Self {
        self.stun_server = Some(stun_addr);
        self
    }

    pub fn set_stun_server(&mut self, stun_addr: SocketAddr) {
        self.stun_server = Some(stun_addr);
    }

    pub fn with_stun_mux(mut self, tx: broadcast::Sender<(Vec<u8>, SocketAddr)>) -> Self {
        self.stun_mux = Some(tx);
        self
    }

    pub fn stun_server(&self) -> Option<SocketAddr> {
        self.stun_server
    }

    pub fn public_addr(&self) -> Option<SocketAddr> {
        *self.public_addr.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_public_addr(&self, addr: SocketAddr) {
        *self.public_addr.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr);
    }

    pub fn nat_type(&self) -> NatType {
        *self.nat_type.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_nat_type(&self, nat_type: NatType) {
        *self.nat_type.lock().unwrap_or_else(|e| e.into_inner()) = nat_type;
    }

    pub fn nominated_addr(&self, fp: &str) -> Option<SocketAddr> {
        self.nominated_addrs.get(fp).map(|a| *a.value())
    }

    pub fn selected_rtt(&self, fp: &str) -> Option<Duration> {
        self.selected_rtts.get(fp).map(|r| *r.value())
    }

    pub fn set_ice_offer(&self, fp: &str, offer: ice::IceOffer) {
        self.offers.insert(fp.to_string(), offer);
    }

    pub fn local_credentials(&self) -> &ice::IceCredentials {
        &self.local_credentials
    }

    pub fn set_local_fingerprint(&mut self, fp: impl Into<String>) {
        self.local_fingerprint = Some(fp.into());
    }

    pub fn is_connected(&self, fp: &str) -> bool {
        self.peers.get(fp).map(|p| p.connected).unwrap_or(false)
    }

    pub fn ice_offer(&self, fp: &str) -> Option<ice::IceOffer> {
        self.offers.get(fp).map(|o| o.clone())
    }

    pub async fn discover_public_addr_from(
        &self,
        sock: &UdpSocket,
        server: SocketAddr,
    ) -> Option<SocketAddr> {
        let mut agent = ice::IceAgent::new(ice::IceRole::Controlling);
        let res = match self.stun_mux.as_ref() {
            Some(tx) => {
                let mut rx = tx.subscribe();
                agent
                    .gather_reflexive_mux(sock, server, STUN_TIMEOUT, &mut rx)
                    .await
            }
            None => agent.gather_reflexive(sock, server, STUN_TIMEOUT).await,
        };
        match res {
            Ok(c) => {
                self.set_public_addr(c.addr);
                info!(public = %c.addr, "STUN: public address discovered");
                Some(c.addr)
            }
            Err(e) => {
                warn!(server = %server, "STUN: public address discovery failed: {e}");
                None
            }
        }
    }

    pub async fn discover_public_addr(&self, sock: &UdpSocket) -> Option<SocketAddr> {
        let server = self.stun_server?;
        self.discover_public_addr_from(sock, server).await
    }

    pub fn register_peer(&self, fp: &str, public_addr: SocketAddr, local_addr: SocketAddr) {
        self.peers.insert(
            fp.to_string(),
            NatPeerState {
                fingerprint: fp.to_string(),
                public_addr,
                local_addr,
                connected: false,
                last_keepalive: Instant::now(),
            },
        );
        debug!("NAT peer registered: {} at {}", fp, public_addr);
    }

    pub async fn punch_hole(&self, sock: &UdpSocket, fp: &str) -> bool {
        let Some(state) = self.peers.get(fp).map(|s| s.clone()) else {
            warn!("ICE: cannot check unknown peer {fp}");
            return false;
        };
        if state.connected {
            return true;
        }
        let Some(offer) = self.offers.get(fp).map(|o| o.clone()) else {
            warn!(
                peer = %fp,
                "ICE: no offer (credentials + candidates) for peer — checks must be authenticated"
            );
            return false;
        };

        let mut mux_rx = self.stun_mux.as_ref().map(|tx| tx.subscribe());
        self.active_ufrags.insert(offer.credentials.ufrag.clone());
        let _active_guard = ActiveUfragGuard {
            set: Arc::clone(&self.active_ufrags),
            ufrag: offer.credentials.ufrag.clone(),
        };

        let controlling = match self.local_fingerprint.as_deref() {
            Some(me) => me > fp,
            None => !offer.controlling,
        };
        let role = if controlling {
            ice::IceRole::Controlling
        } else {
            ice::IceRole::Controlled
        };
        let mut agent = ice::IceAgent::new(role);
        agent.set_local_credentials(self.local_credentials.clone());
        agent.set_remote_credentials(offer.credentials.clone());

        let route = offer
            .candidates
            .first()
            .map(|c| c.base)
            .unwrap_or(state.public_addr);
        match agent.gather_host(sock, route) {
            Ok(c) => {
                debug!(local = %c.addr, "ICE: local host candidate");
            }
            Err(e) => {
                warn!(peer = %fp, "ICE: host candidate gathering failed: {e}");
                return false;
            }
        }
        if let Some(server) = self.stun_server {
            let res = match mux_rx.as_mut() {
                Some(rx) => {
                    agent
                        .gather_reflexive_mux(sock, server, STUN_TIMEOUT, rx)
                        .await
                }
                None => agent.gather_reflexive(sock, server, STUN_TIMEOUT).await,
            };
            match res {
                Ok(c) => self.set_public_addr(c.addr),
                Err(e) => debug!(peer = %fp, "ICE: reflexive gathering failed: {e}"),
            }
        }
        for c in offer.candidates {
            agent.add_remote_candidate(c);
        }
        agent.form_pairs();
        if agent.pairs().is_empty() {
            warn!(peer = %fp, "ICE: no candidate pairs (component mismatch?)");
            return false;
        }

        let established = self.drive_checks(sock, &mut agent, mux_rx.as_mut()).await;
        if established {
            let nominated_remote = agent.selected_pair().map(|p| p.remote.addr);
            if let Some(remote_addr) = nominated_remote {
                self.nominated_addrs.insert(fp.to_string(), remote_addr);
            }
            if let Some(mut s) = self.peers.get_mut(fp) {
                if let Some(remote_addr) = nominated_remote {
                    s.public_addr = remote_addr;
                }
                s.connected = true;
                s.last_keepalive = Instant::now();
            }
            let measured_rtt_ms = agent.selected_pair_rtt().map(|rtt| {
                debug!(peer = %fp, rtt_ms = rtt.as_millis(), "ICE: measured path RTT");
                self.selected_rtts.insert(fp.to_string(), rtt);
                rtt.as_secs_f64() * 1000.0
            });
            let is_lan_nom = nominated_remote
                .map(|a| super::fallback::is_lan_addr(&a))
                .unwrap_or(false);
            update_peer_telemetry(fp, |t| {
                if measured_rtt_ms.is_some() {
                    t.rtt_ms = measured_rtt_ms;
                }
                t.transport = Some(if is_lan_nom {
                    "direct_lan".to_string()
                } else {
                    "direct_wan_ice".to_string()
                });
                t.via_relay_fp = None;
            });
            info!(peer = %fp, nominated = ?nominated_remote, "ICE: path established");
        } else {
            warn!(
                peer = %fp,
                "ICE: every candidate pair failed — a relay (TURN/DERP) is required"
            );
        }
        established
    }

    pub async fn try_respond_inbound_stun(&self, sock: &UdpSocket, raw: &[u8], from: SocketAddr) {
        let Ok(msg) = stun::Message::parse(raw) else {
            return;
        };
        if msg.typ.method() != stun::Method::BINDING || msg.typ.class() != stun::Class::Request {
            return;
        }
        if let Some(stun::Attribute::Username(u)) = msg.get(0x0006) {
            let Ok(u_str) = std::str::from_utf8(u) else {
                return;
            };
            let Some((local_u, remote_u)) = u_str.split_once(':') else {
                return;
            };
            if local_u != self.local_credentials.ufrag || self.active_ufrags.contains(remote_u) {
                return;
            }
        }
        if stun::verify_integrity(raw, self.local_credentials.password.as_bytes()).is_err() {
            return;
        }
        let mut resp = stun::Message::binding_success(msg.txid, from);
        if let Some(stun::Attribute::Username(u)) = msg.get(0x0006) {
            resp.push(stun::Attribute::Username(u.clone()));
        }
        if let Ok(bytes) = resp.encode_with_integrity(self.local_credentials.password.as_bytes()) {
            let _ = sock.send_to(&bytes, from).await;
        }
    }

    async fn drive_checks(
        &self,
        sock: &UdpSocket,
        agent: &mut ice::IceAgent,
        mut mux_rx: Option<&mut broadcast::Receiver<(Vec<u8>, SocketAddr)>>,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + ICE_CHECK_BUDGET;
        let mut buf = vec![0u8; 1500];
        let mut last_rto_tick = tokio::time::Instant::now();

        loop {
            if agent.selected_pair().is_some() {
                return true;
            }
            match agent.next_check() {
                Some(idx) => {
                    let nominate = agent.role() == ice::IceRole::Controlling;
                    let dest = agent.pairs()[idx].remote.addr;
                    match agent.build_check(idx, nominate) {
                        Ok(check) => {
                            if let Err(e) = sock.send_to(&check, dest).await {
                                debug!(dest = %dest, "ICE: check send failed: {e}");
                                agent.fail_pair(idx);
                                continue;
                            }
                        }
                        Err(e) => {
                            warn!("ICE: cannot build check: {e}");
                            agent.fail_pair(idx);
                            continue;
                        }
                    }
                    last_rto_tick = tokio::time::Instant::now();
                }
                None if agent.is_exhausted() => return false,
                None if agent.pairs().is_empty() => return false,
                None => {} // all pairs already in flight: just wait
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return agent.selected_pair().is_some();
            }
            let wait = remaining.min(ice::DEFAULT_RTO);
            let received: Option<(Vec<u8>, SocketAddr)> = match mux_rx.as_deref_mut() {
                Some(rx) => match tokio::time::timeout(wait, rx.recv()).await {
                    Err(_) => None,
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                    Ok(Err(broadcast::error::RecvError::Closed)) => {
                        return agent.selected_pair().is_some();
                    }
                    Ok(Ok(pkt)) => Some(pkt),
                },
                None => match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
                    Err(_) => None,
                    Ok(Err(e)) => {
                        debug!("ICE: recv error: {e}");
                        None
                    }
                    Ok(Ok((n, from))) => Some((buf[..n].to_vec(), from)),
                },
            };

            if let Some((pkt, from)) = received {
                match agent.handle_check(&pkt, from) {
                    Ok(Some(outcome)) => {
                        if let Some(response) = outcome.response {
                            if let Err(e) = sock.send_to(&response, from).await {
                                debug!(peer = %from, "ICE: response send failed: {e}");
                            }
                        }
                    }
                    Ok(None) => {} // unrelated traffic
                    Err(e) => debug!(peer = %from, "ICE: check rejected: {e}"),
                }
            } else if last_rto_tick.elapsed() >= ice::DEFAULT_RTO {
                last_rto_tick = tokio::time::Instant::now();
                let in_progress: Vec<usize> = agent
                    .pairs()
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.state == ice::PairState::InProgress)
                    .map(|(i, _)| i)
                    .collect();
                let nominate = agent.role() == ice::IceRole::Controlling;
                for idx in in_progress {
                    if agent.retransmit(idx) {
                        let dest = agent.pairs()[idx].remote.addr;
                        if let Ok(check) = agent.build_check(idx, nominate) {
                            let _ = sock.send_to(&check, dest).await;
                        }
                    } else {
                        agent.fail_pair(idx);
                    }
                }
            }
        }
    }

    pub async fn send_keepalives(&self, sock: &UdpSocket) {
        for mut entry in self.peers.iter_mut() {
            if entry.connected && entry.last_keepalive.elapsed() > Duration::from_secs(25) {
                let keepalive =
                    stun::Message::binding_indication(stun::TransactionId::random()).encode();
                match sock.send_to(&keepalive, entry.public_addr).await {
                    Ok(_) => entry.last_keepalive = Instant::now(),
                    Err(e) => {
                        debug!(peer = %entry.fingerprint, "NAT keepalive failed: {e}");
                    }
                }
            }
        }
    }

    pub async fn send_relay_keepalives(&self, sock: &UdpSocket, relays: &[SocketAddr]) -> usize {
        let mut sent = 0usize;
        for addr in relays {
            let keepalive =
                stun::Message::binding_indication(stun::TransactionId::random()).encode();
            match sock.send_to(&keepalive, addr).await {
                Ok(_) => sent = sent.saturating_add(1),
                Err(e) => debug!(relay = %addr, "relay pinhole keepalive failed: {e}"),
            }
        }
        sent
    }

    pub fn local_cache(&self) -> Vec<(String, SocketAddr)> {
        self.peers
            .iter()
            .filter(|e| e.connected)
            .map(|e| (e.fingerprint.clone(), e.public_addr))
            .collect()
    }
}

pub const DEFAULT_PATH_FITNESS: f64 = 0.5;

#[derive(Debug, Clone)]
pub struct PathMetrics {
    pub srtt_us: f64,
    pub min_rtt_us: f64,
    pub loss_rate: f64,
    pub cwnd: u64,
    pub delivery_bps: f64,
    pub delivered_bytes: u64,
    pub loss_events: u64,
    pub last_updated: Instant,
    pub samples: u64,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            srtt_us: 50_000.0,
            min_rtt_us: 50_000.0,
            loss_rate: 0.0,
            cwnd: cc::INIT_CWND,
            delivery_bps: 0.0,
            delivered_bytes: 0,
            loss_events: 0,
            last_updated: Instant::now(),
            samples: 0,
        }
    }
}

impl PathMetrics {
    pub const STALE_AFTER: Duration = Duration::from_secs(30);

    pub fn observe_rtt(&mut self, sample_us: f64) {
        if !(sample_us.is_finite() && sample_us > 0.0) {
            return;
        }
        const ALPHA: f64 = 0.125; // RFC 6298 §2.3
        if self.samples == 0 {
            self.srtt_us = sample_us;
            self.min_rtt_us = sample_us;
        } else {
            self.srtt_us = self.srtt_us * (1.0 - ALPHA) + sample_us * ALPHA;
            self.min_rtt_us = self.min_rtt_us.min(sample_us);
        }
        self.samples = self.samples.saturating_add(1);
        self.last_updated = Instant::now();
    }

    pub fn observe_loss(&mut self) {
        const BETA: f64 = 0.1;
        self.loss_rate = self.loss_rate * (1.0 - BETA) + BETA;
        self.loss_events = self.loss_events.saturating_add(1);
        self.cwnd = (self.cwnd / 2).max(cc::DEFAULT_MSS);
        self.last_updated = Instant::now();
    }

    pub fn observe_delivery(&mut self, bytes: u64, elapsed: Duration) {
        const BETA: f64 = 0.1;
        const ALPHA: f64 = 0.25;
        self.delivered_bytes = self.delivered_bytes.saturating_add(bytes);
        self.loss_rate *= 1.0 - BETA;

        if self.cwnd > 0 {
            let inc = (cc::DEFAULT_MSS as f64 * bytes as f64 / self.cwnd as f64).max(1.0) as u64;
            self.cwnd = self.cwnd.saturating_add(inc).min(cc::DEFAULT_MAX_CWND);
        }

        let secs = elapsed.as_secs_f64();
        if secs > 0.0 {
            let instant = bytes as f64 / secs;
            self.delivery_bps = if self.delivery_bps <= 0.0 {
                instant
            } else {
                self.delivery_bps * (1.0 - ALPHA) + instant * ALPHA
            };
        }
        self.last_updated = Instant::now();
    }

    pub fn observe(&mut self, rtt_sample_us: f64, lost: bool) {
        if lost {
            self.observe_loss();
        }
        self.observe_rtt(rtt_sample_us);
    }

    pub fn measured(&self) -> bool {
        self.samples > 0 && self.last_updated.elapsed() < Self::STALE_AFTER
    }

    pub fn rate_bps(&self) -> f64 {
        if !self.measured() || self.loss_rate > 0.5 {
            return 0.0;
        }
        let srtt_s = (self.srtt_us.max(100.0)) / 1_000_000.0;
        let window_rate = self.cwnd as f64 / srtt_s;
        let observed = self.delivery_bps * 2.0;
        if observed > 0.0 {
            window_rate.min(observed)
        } else {
            window_rate
        }
    }

    pub fn fitness(&self) -> f64 {
        if self.loss_rate > 0.5 {
            return 0.0; // Unusable path
        }
        if !self.measured() {
            return DEFAULT_PATH_FITNESS * (1.0 - self.loss_rate);
        }
        let rtt_score = (100_000.0 / self.srtt_us.max(1.0)).min(2.0);
        let loss_score = (1.0 - self.loss_rate).powi(2);
        let tp_score = (self.rate_bps() / 1_000_000.0).min(10.0) / 10.0;
        rtt_score * 0.4 + loss_score * 0.3 + tp_score * 0.3
    }
}

#[derive(Debug, Clone)]
pub struct ShardRoute {
    pub peer_fingerprint: String,
    pub shard_index: u8,
    pub weight: f64,
    pub reliability: f64,
}

pub struct AdaptiveShardRouter {
    path_metrics: Arc<DashMap<String, PathMetrics>>,
    min_fitness: f64,
    data_shards: usize,
}

impl Default for AdaptiveShardRouter {
    fn default() -> Self {
        Self {
            path_metrics: Arc::new(DashMap::new()),
            min_fitness: 0.3,
            data_shards: 2, // RS(2,1): need 2 of 3
        }
    }
}

impl AdaptiveShardRouter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn record_success(&self, peer_fp: &str, rtt_us: f64) {
        let mut metrics = self.path_metrics.entry(peer_fp.to_string()).or_default();
        metrics.observe_rtt(rtt_us);

        debug!(
            "Path to {}: RTT={:.0}us, rate={:.0} B/s, fitness={:.2}",
            peer_fp,
            metrics.srtt_us,
            metrics.rate_bps(),
            metrics.fitness()
        );
    }

    pub fn record_loss(&self, peer_fp: &str) {
        let mut metrics = self.path_metrics.entry(peer_fp.to_string()).or_default();
        metrics.observe_loss();
        warn!(
            "Path loss to {}: loss_rate={:.2}",
            peer_fp, metrics.loss_rate
        );
    }

    pub fn record_delivery(&self, peer_fp: &str, bytes: u64, elapsed: Duration) {
        let mut metrics = self.path_metrics.entry(peer_fp.to_string()).or_default();
        metrics.observe_delivery(bytes, elapsed);
    }

    pub fn live_path_rates(&self) -> Vec<f64> {
        self.path_metrics
            .iter()
            .map(|e| e.value().rate_bps())
            .filter(|r| *r > 0.0)
            .collect()
    }

    pub fn path_rate_bps(&self, peer_fp: &str) -> f64 {
        self.path_metrics
            .get(peer_fp)
            .map(|m| m.rate_bps())
            .unwrap_or(0.0)
    }

    pub fn path_rtt_us(&self, peer_fp: &str) -> Option<f64> {
        self.path_metrics
            .get(peer_fp)
            .filter(|m| m.measured())
            .map(|m| m.srtt_us)
    }

    pub fn shard_target_count(&self) -> usize {
        self.data_shards.saturating_add(1)
    }

    pub fn path_fitness(&self, peer_fp: &str) -> f64 {
        self.path_metrics
            .get(peer_fp)
            .map(|m| m.fitness())
            .unwrap_or(DEFAULT_PATH_FITNESS)
    }

    pub fn select_shard_targets(
        &self,
        available: &[(String, SocketAddr)],
    ) -> Vec<(String, SocketAddr, f64)> {
        let mut scored: Vec<(String, SocketAddr, f64)> = available
            .iter()
            .map(|(fp, addr)| (fp.clone(), *addr, self.path_fitness(fp)))
            .filter(|(_, _, f)| *f >= self.min_fitness)
            .collect();

        scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }

    pub fn select_shard_targets_routed(
        &self,
        me: &str,
        available: &[(String, SocketAddr)],
        plan: &ContactPlan,
        now: Timestamp,
        want: usize,
    ) -> Vec<(String, SocketAddr, f64)> {
        let mut candidates: Vec<(String, SocketAddr, f64, f64, Vec<String>)> = available
            .iter()
            .filter(|(fp, _)| fp != me)
            .filter_map(|(fp, addr)| {
                let journey =
                    plan.find_earliest_arrival_with(me, fp, now, &RouteOptions::default())?;
                Some((
                    fp.clone(),
                    *addr,
                    self.path_fitness(fp),
                    journey.arrival_time,
                    journey.transit_nodes(),
                ))
            })
            .collect();
        candidates.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal));

        let mut used_transit = std::collections::HashSet::new();
        let mut routed = Vec::new();
        let mut deferred = Vec::new();
        for candidate in candidates {
            let overlaps = candidate.4.iter().any(|node| used_transit.contains(node));
            if overlaps {
                deferred.push(candidate);
            } else {
                used_transit.extend(candidate.4.iter().cloned());
                routed.push(candidate);
            }
        }

        deferred.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal));
        routed.extend(deferred);

        let mut out: Vec<(String, SocketAddr, f64)> = routed
            .into_iter()
            .map(|(fp, addr, fitness, _, _)| (fp, addr, fitness))
            .collect();
        let mut unrouted: Vec<(String, SocketAddr, f64)> = available
            .iter()
            .filter(|(fp, _)| fp != me && !out.iter().any(|(selected, _, _)| selected == fp))
            .map(|(fp, addr)| (fp.clone(), *addr, self.path_fitness(fp)))
            .collect();
        unrouted.sort_by(|a, b| {
            b.2.partial_cmp(&a.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        out.extend(unrouted);
        out.truncate(want.max(1));
        out
    }

    pub fn assign_shards(&self, targets: &[(String, SocketAddr, f64)]) -> Vec<ShardRoute> {
        let mut routes = Vec::new();
        if targets.is_empty() {
            return routes;
        }
        for shard_idx in 0..3u8 {
            if let Some((fp, _addr, fitness)) = targets.get(shard_idx as usize % targets.len()) {
                routes.push(ShardRoute {
                    peer_fingerprint: fp.clone(),
                    shard_index: shard_idx,
                    weight: *fitness,
                    reliability: *fitness,
                });
            }
        }
        routes
    }

    pub fn assign_shards_to_primary(
        &self,
        primary_fp: &str,
        shard_count: usize,
    ) -> Vec<ShardRoute> {
        let fitness = self.path_fitness(primary_fp);
        (0..shard_count.min(3))
            .map(|idx| ShardRoute {
                peer_fingerprint: primary_fp.to_string(),
                shard_index: idx as u8,
                weight: fitness,
                reliability: fitness,
            })
            .collect()
    }

    pub fn can_reconstruct(&self) -> bool {
        let good_paths = self
            .path_metrics
            .iter()
            .filter(|m| m.fitness() >= self.min_fitness)
            .count();
        good_paths >= self.data_shards
    }
}

#[derive(Debug, Clone)]
pub struct ReciprocityRecord {
    pub bytes_forwarded_for_them: u64,
    pub bytes_forwarded_for_us: u64,
    pub shards_relayed_for_us: u64,
    pub shards_dropped_for_them: u64,
    pub reciprocity_ratio: f64,
    pub last_activity: Instant,
}

impl Default for ReciprocityRecord {
    fn default() -> Self {
        Self {
            bytes_forwarded_for_them: 0,
            bytes_forwarded_for_us: 0,
            shards_relayed_for_us: 0,
            shards_dropped_for_them: 0,
            reciprocity_ratio: 1.0,
            last_activity: Instant::now(),
        }
    }
}

impl ReciprocityRecord {
    pub fn update_ratio(&mut self) {
        let sent = self.bytes_forwarded_for_them.max(1);
        let recv = self.bytes_forwarded_for_us;
        self.reciprocity_ratio = recv as f64 / sent as f64;
    }

    pub const LEECH_EVAL_THRESHOLD_BYTES: u64 = 10_000_000;

    pub fn is_leeching(&self) -> bool {
        self.bytes_forwarded_for_them > Self::LEECH_EVAL_THRESHOLD_BYTES
            && self.reciprocity_ratio < 0.1
    }

    pub fn rate_limit_factor(&self) -> f64 {
        if self.bytes_forwarded_for_them <= 100_000 || self.reciprocity_ratio >= 0.3 {
            1.0
        } else if self.reciprocity_ratio >= 0.1 {
            0.5
        } else {
            0.25
        }
    }
}

pub struct TitForTatEnforcer {
    reciprocity: Arc<DashMap<(String, String), ReciprocityRecord>>,
    reputation: Arc<PoissonReputationMatrix>,
    our_fingerprint: String,
    evicted: Arc<DashMap<String, bool>>,
    exempt_peers: Arc<DashMap<String, bool>>,
    min_forward_bytes: u64,
}

impl TitForTatEnforcer {
    pub fn new(our_fingerprint: String, reputation: Arc<PoissonReputationMatrix>) -> Self {
        Self {
            reciprocity: Arc::new(DashMap::new()),
            reputation,
            our_fingerprint,
            evicted: Arc::new(DashMap::new()),
            exempt_peers: Arc::new(DashMap::new()),
            min_forward_bytes: 1024, // 1 KB minimum before evaluation
        }
    }

    pub fn set_peer_exempt(&self, peer_fp: &str, exempt: bool) {
        if exempt {
            self.exempt_peers.insert(peer_fp.to_string(), true);
        } else {
            self.exempt_peers.remove(peer_fp);
        }
    }

    pub fn is_exempt(&self, peer_fp: &str) -> bool {
        self.exempt_peers.get(peer_fp).map(|v| *v).unwrap_or(false)
    }

    pub fn rate_limit_factor(&self, peer_fp: &str) -> f64 {
        if self.is_exempt(peer_fp) {
            return 1.0;
        }
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        self.reciprocity
            .get(&key)
            .map(|r| r.rate_limit_factor())
            .unwrap_or(1.0)
    }

    pub fn forwarded_for(&self, peer_fp: &str, bytes: u64) {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        let mut record = self.reciprocity.entry(key).or_default();
        record.bytes_forwarded_for_them = record.bytes_forwarded_for_them.saturating_add(bytes);
        record.update_ratio();
        record.last_activity = Instant::now();
    }

    pub fn forwarded_by(&self, peer_fp: &str, bytes: u64) {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        let mut record = self.reciprocity.entry(key).or_default();
        record.bytes_forwarded_for_us = record.bytes_forwarded_for_us.saturating_add(bytes);
        record.shards_relayed_for_us = record.shards_relayed_for_us.saturating_add(1);
        record.update_ratio();
        record.last_activity = Instant::now();
    }

    pub fn dropped_for(&self, peer_fp: &str) {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        let mut record = self.reciprocity.entry(key).or_default();
        record.shards_dropped_for_them = record.shards_dropped_for_them.saturating_add(1);
        record.update_ratio();
    }

    pub async fn should_evict(&self, peer_fp: &str) -> bool {
        if self.is_exempt(peer_fp) {
            return false;
        }
        if self.evicted.get(peer_fp).map(|v| *v).unwrap_or(false) {
            return true;
        }

        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        if let Some(record) = self.reciprocity.get(&key) {
            if record.bytes_forwarded_for_them < self.min_forward_bytes {
                return false; // Not enough data to judge yet
            }

            if record.is_leeching() {
                warn!(
                    "Peer {} is leeching (ratio={:.2}), recommending eviction",
                    peer_fp, record.reciprocity_ratio
                );

                self.reputation
                    .record_interaction(&self.our_fingerprint, peer_fp, false);
                return true;
            }

            if record.reciprocity_ratio > 0.8 {
                self.reputation
                    .record_interaction(&self.our_fingerprint, peer_fp, true);
            }
        }
        false
    }

    pub fn evict(&self, peer_fp: &str) {
        self.evicted.insert(peer_fp.to_string(), true);
        warn!("Evicted peer {} for leeching behavior", peer_fp);
    }

    pub fn ratio_with(&self, peer_fp: &str) -> f64 {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        self.reciprocity
            .get(&key)
            .map(|r| r.reciprocity_ratio)
            .unwrap_or(1.0)
    }

    pub fn is_evicted(&self, peer_fp: &str) -> bool {
        self.evicted.get(peer_fp).map(|v| *v).unwrap_or(false)
    }

    pub fn peer_stats(&self, peer_fp: &str) -> (u64, u64, f64, bool) {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        let (sent, recv, ratio) = self
            .reciprocity
            .get(&key)
            .map(|r| {
                (
                    r.bytes_forwarded_for_them,
                    r.bytes_forwarded_for_us,
                    r.reciprocity_ratio,
                )
            })
            .unwrap_or((0, 0, 1.0));
        let evicted = self.is_evicted(peer_fp);
        (sent, recv, ratio, evicted)
    }

    pub fn all_stats(&self) -> Vec<(String, u64, u64, f64, bool)> {
        self.reciprocity
            .iter()
            .map(|entry| {
                let peer_fp = entry.key().1.clone();
                let r = entry.value();
                let evicted = self.is_evicted(&peer_fp);
                (
                    peer_fp,
                    r.bytes_forwarded_for_them,
                    r.bytes_forwarded_for_us,
                    r.reciprocity_ratio,
                    evicted,
                )
            })
            .collect()
    }

    pub async fn audit_cycle(&self, sessions: &DashMap<String, Session>) -> Vec<String> {
        let mut to_evict = Vec::new();
        let peer_fps: Vec<String> = sessions.iter().map(|e| e.key().clone()).collect();

        for fp in &peer_fps {
            if self.should_evict(fp).await {
                to_evict.push(fp.clone());
            }
        }
        to_evict
    }
}

pub struct MeshNode {
    pub fingerprint: String,
    pub nat: NatHolePuncher,
    pub router: AdaptiveShardRouter,
    pub tft: Arc<TitForTatEnforcer>,
    peer_registry: Arc<DashMap<String, (SocketAddr, u32)>>,
    pub routing_enabled: AtomicBool,
}

impl MeshNode {
    pub async fn new(fingerprint: String, reputation: Arc<PoissonReputationMatrix>) -> Self {
        Self {
            tft: Arc::new(TitForTatEnforcer::new(fingerprint.clone(), reputation)),
            fingerprint,
            nat: NatHolePuncher::new(),
            router: AdaptiveShardRouter::new(),
            peer_registry: Arc::new(DashMap::new()),
            routing_enabled: AtomicBool::new(true),
        }
    }

    pub fn register_peer(&self, fp: &str, addr: SocketAddr, distance: u32) {
        self.peer_registry.insert(fp.to_string(), (addr, distance));
        self.nat.register_peer(fp, addr, addr);
        debug!("Mesh: registered peer {} at distance {}", fp, distance);
    }

    pub fn peers_within(&self, max_distance: u32) -> Vec<(String, SocketAddr)> {
        self.peer_registry
            .iter()
            .filter(|e| e.value().1 <= max_distance)
            .map(|e| (e.key().clone(), e.value().0))
            .collect()
    }

    pub async fn select_egress_targets(
        &self,
        _destination: &str,
    ) -> Vec<(String, SocketAddr, f64)> {
        let available = self.peers_within(2);
        let mut candidates = self.router.select_shard_targets(&available);

        candidates.retain(|(fp, _, _)| !self.tft.is_evicted(fp));

        for (fp, _, score) in candidates.iter_mut() {
            let ratio = self.tft.ratio_with(fp);
            if ratio > 0.8 {
                *score *= 1.2; // 20% boost for cooperative peers
            }
        }

        candidates
    }

    pub fn assign_shard_routes(&self, targets: &[(String, SocketAddr, f64)]) -> Vec<ShardRoute> {
        self.router.assign_shards(targets)
    }

    pub fn cache_tree(&self, max_entries: usize) -> Vec<(String, SocketAddr, u32)> {
        self.peer_registry
            .iter()
            .take(max_entries)
            .map(|e| (e.key().clone(), e.value().0, e.value().1))
            .collect()
    }
}

#[derive(Debug)]
pub struct ExitIpRotator {
    pub egress_ips: Vec<std::net::IpAddr>,
    pub current_idx: std::sync::atomic::AtomicUsize,
    pub rotation_interval: Option<std::time::Duration>,
    pub last_rotation: std::time::Instant,
}

impl ExitIpRotator {
    pub fn new(ips: Vec<std::net::IpAddr>) -> Self {
        Self {
            egress_ips: ips,
            current_idx: std::sync::atomic::AtomicUsize::new(0),
            rotation_interval: None,
            last_rotation: std::time::Instant::now(),
        }
    }

    pub fn get_next_socket_addr(&self, target_port: u16) -> std::net::SocketAddr {
        if self.egress_ips.is_empty() {
            return std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                target_port,
            );
        }
        let idx = self
            .current_idx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ip = self.egress_ips[idx % self.egress_ips.len()];
        std::net::SocketAddr::new(ip, target_port)
    }

    pub fn current_ip(&self) -> Option<std::net::IpAddr> {
        if self.egress_ips.is_empty() {
            None
        } else {
            Some(self.egress_ips[0])
        }
    }

    pub fn set_rotation_interval(&mut self, interval: std::time::Duration) {
        self.rotation_interval = Some(interval);
    }

    pub fn should_rotate(&self) -> bool {
        if let Some(interval) = self.rotation_interval {
            self.last_rotation.elapsed() >= interval
        } else {
            false
        }
    }

    pub fn rotate(&mut self) -> bool {
        if self.egress_ips.len() < 2 {
            return false;
        }
        self.current_idx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.last_rotation = std::time::Instant::now();
        true
    }

    pub fn add_ip(&mut self, ip: std::net::IpAddr) {
        self.egress_ips.push(ip);
    }

    pub fn remove_ip(&mut self, ip: &std::net::IpAddr) {
        self.egress_ips.retain(|e| e != ip);
    }

    pub fn pool_size(&self) -> usize {
        self.egress_ips.len()
    }
}

pub async fn dispatch_shards_multipath(
    sock: &tokio::net::UdpSocket,
    session_hash: [u8; 4],
    counter: u32,
    shards: &[Vec<u8>],
    auth_tag: &[u8; 16],
    relay_hop_fingerprint: &str,
    targets: &[(String, SocketAddr, f64)],
    mesh: &AdaptiveShardRouter,
    use_bulk: bool,
) -> Vec<tokio::io::Result<()>> {
    let routes = mesh.assign_shards(targets);
    let mut results = Vec::with_capacity(routes.len());

    for route in &routes {
        let shard_idx = route.shard_index as usize;
        if shard_idx >= shards.len() {
            continue;
        }
        let shard_payload = &shards[shard_idx];

        let relay_pkt = crate::ghost::net::relay::build_relay_packet(
            relay_hop_fingerprint,
            1, // one hop remaining — the intermediate forwards to final destination
            shard_payload,
        );

        let peer_addr = targets
            .iter()
            .find(|(fp, _, _)| *fp == route.peer_fingerprint)
            .map(|(_, addr, _)| *addr)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

        if peer_addr.port() == 0 {
            results.push(Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "No address for peer",
            )));
            continue;
        }

        let result = crate::ghost::net::send_gtf(
            sock,
            &peer_addr,
            session_hash,
            counter,
            route.shard_index,
            &relay_pkt,
            auth_tag,
            use_bulk,
        )
        .await;
        results.push(result);
    }

    results
}

pub async fn forward_to_exit_tunnel(
    sock: &UdpSocket,
    sessions: &DashMap<String, Session>,
    exit_rotator: &ExitIpRotator,
    peer_addrs: &DashMap<String, SocketAddr>,
    reconstructed_payload: &[u8],
    exit_node_fingerprint: &str,
) -> bool {
    let exit_addr = match peer_addrs.get(exit_node_fingerprint) {
        Some(e) => *e.value(),
        None => {
            warn!(
                "Exit node {} not found in peer registry",
                exit_node_fingerprint
            );
            return false;
        }
    };

    let session_entry = match sessions.get(exit_node_fingerprint) {
        Some(s) => s,
        None => {
            warn!(
                "No session established with exit node {}",
                exit_node_fingerprint
            );
            return false;
        }
    };

    let material = session_entry.seal_material();
    let sh = session_entry.session_hash;
    let use_bulk = session_entry.use_bulk;
    drop(session_entry);

    let mut framed = reconstructed_payload.to_vec();
    let needs_padding = if !framed.len().is_multiple_of(2) {
        1
    } else {
        0
    };
    if needs_padding > 0 {
        framed.push(0);
    }

    let tail = if use_bulk {
        [0u8; crate::ghost::net::JITTER_MAX]
    } else {
        crate::ghost::net::random_tail()
    };
    let aad: &[u8] = if use_bulk { &[] } else { &tail[..] };

    xchacha_seal_in_place_with_aad(
        &material.key,
        &material.nonce,
        material.epoch,
        material.direction,
        &mut framed,
        aad,
    )
    .expect("sealing an owned buffer cannot fail");

    let tag = if framed.len() >= 16 {
        let mut t = [0u8; 16];
        if let Some(slice) = framed.get(framed.len().saturating_sub(16)..) {
            if slice.len() == 16 {
                t.copy_from_slice(slice);
            }
        }
        t
    } else {
        [0u8; 16]
    };

    let shards = l4_rs::encode(&mut framed);

    let _egress_addr = exit_rotator.get_next_socket_addr(0);

    for (i, shard) in shards.iter().take(3).enumerate() {
        let shard_data = frame_shard(shard);
        let header = GtfV2Header {
            session_hash: sh,
            counter: material.counter,
            epoch: material.epoch,
            nonce: material.nonce,
            shard_index: i as u8,
            flags: 0,
            bulk: use_bulk,
            tail,
        };
        if let Err(e) = send_gtf_v2(sock, &exit_addr, &header, &shard_data, &tag).await {
            debug!("Exit tunnel send error to {}: {}", exit_node_fingerprint, e);
            return false;
        }
    }

    info!(
        "Forwarded {} bytes to exit tunnel via {} (egress rotation active)",
        reconstructed_payload.len(),
        exit_node_fingerprint
    );
    true
}

pub fn spawn_mesh_tasks(
    sock: Arc<UdpSocket>,
    sessions: Arc<DashMap<String, Session>>,
    mesh: Arc<MeshNode>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();

    let s1 = Arc::clone(&sock);
    let m1 = Arc::clone(&mesh);
    handles.push(tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(20)).await;
            m1.nat.send_keepalives(&s1).await;
        }
    }));

    let s2 = sessions;
    let m2 = Arc::clone(&mesh);
    handles.push(tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(120)).await; // Audit every 2 minutes
            let to_evict = m2.tft.audit_cycle(&s2).await;
            for fp in to_evict {
                m2.tft.evict(&fp);
                if let Some((_, _session)) = s2.remove(&fp) {
                    info!("Evicted {} — session torn down", fp);
                }
            }
        }
    }));

    let _m3 = Arc::clone(&mesh);
    handles.push(tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(300)).await; // Every 5 minutes
            debug!("Mesh: path metrics aging cycle");
        }
    }));

    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_peer_registration() {
        let puncher = NatHolePuncher::new();
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        puncher.register_peer("test_fp", addr, addr);
        if let Some(mut s) = puncher.peers.get_mut("test_fp") {
            s.connected = true;
        }
        let cache = puncher.local_cache();
        assert_eq!(cache.len(), 1, "Should have 1 connected peer");
    }

    #[test]
    fn test_path_metrics_fitness() {
        let mut metrics = PathMetrics::default();
        metrics.observe(10_000.0, false);
        metrics.observe(12_000.0, false);
        metrics.observe(11_000.0, false);
        let good_fitness = metrics.fitness();
        assert!(good_fitness > 0.5, "Good path should have high fitness");

        for _ in 0..10 {
            metrics.observe(200_000.0, true);
        }
        let bad_fitness = metrics.fitness();
        assert!(
            bad_fitness < good_fitness,
            "Bad path should have lower fitness"
        );
    }

    #[test]
    fn a_loss_is_not_an_rtt_sample() {
        let mut m = PathMetrics::default();
        m.observe_rtt(80_000.0);
        m.observe_rtt(80_000.0);
        let before_rtt = m.srtt_us;
        let before_fitness = m.fitness();
        let before_rate = m.rate_bps();
        for _ in 0..5 {
            m.observe_loss();
        }
        assert_eq!(
            m.srtt_us, before_rtt,
            "a loss must not move the RTT estimate"
        );
        assert_eq!(m.loss_events, 5);
        assert!(m.loss_rate > 0.3, "loss is still recorded as loss");
        assert!(m.cwnd < cc::INIT_CWND, "loss halves the window");
        assert!(m.cwnd >= cc::DEFAULT_MSS, "but never below one segment");
        assert!(
            m.fitness() < before_fitness,
            "loss must lower the score ({:.3}), not raise it ({:.3})",
            m.fitness(),
            before_fitness
        );
        assert!(
            m.rate_bps() < before_rate,
            "halving the window must lower the rate estimate ({:.0} → {:.0})",
            before_rate,
            m.rate_bps()
        );
    }

    #[test]
    fn measured_delivery_grows_the_window_and_the_rate() {
        let mut m = PathMetrics::default();
        m.observe_rtt(40_000.0);
        let start = m.rate_bps();
        assert!(start > 0.0, "a measured path has an estimate");
        let tick = Duration::from_millis(40);
        for _ in 0..10 {
            m.observe_delivery(m.cwnd, tick);
        }
        assert!(m.cwnd > cc::INIT_CWND, "delivery opens the window");
        assert!(
            m.rate_bps() > start,
            "rate {:.0} should exceed {:.0}",
            m.rate_bps(),
            start
        );
        assert_eq!(m.delivered_bytes, m.delivered_bytes.max(1));
        assert!(m.loss_rate < 0.01, "delivery decays the loss estimate");
    }

    #[test]
    fn a_path_losing_more_than_it_delivers_reports_no_rate() {
        let mut m = PathMetrics::default();
        m.observe_rtt(30_000.0);
        for _ in 0..20 {
            m.observe_loss();
        }
        assert!(m.loss_rate > 0.5);
        assert_eq!(m.rate_bps(), 0.0, "no estimate, not a zero estimate");
        assert_eq!(m.fitness(), 0.0, "and it must not be selected");
    }

    #[test]
    fn a_stale_measurement_stops_counting() {
        let mut m = PathMetrics::default();
        m.observe_rtt(10_000.0);
        assert!(m.measured());
        m.last_updated = Instant::now() - (PathMetrics::STALE_AFTER + Duration::from_secs(1));
        assert!(!m.measured());
        assert_eq!(m.rate_bps(), 0.0);
        assert_eq!(
            m.fitness(),
            DEFAULT_PATH_FITNESS,
            "no losses, so no penalty"
        );
    }

    #[test]
    fn the_router_reports_only_paths_it_can_rate() {
        let router = AdaptiveShardRouter::new();
        router.record_success("measured", 25_000.0);
        router.record_delivery("measured", 20_000, Duration::from_millis(25));
        router.record_loss("lossy");
        let rates = router.live_path_rates();
        assert_eq!(rates.len(), 1, "only the measured path has an estimate");
        assert!(rates[0] > 0.0);
        assert_eq!(router.path_rtt_us("measured"), Some(25_000.0));
        assert_eq!(router.path_rtt_us("lossy"), None);
        let lossy_fitness = router.path_fitness("lossy");
        assert!(
            lossy_fitness < DEFAULT_PATH_FITNESS && lossy_fitness > 0.0,
            "one loss with no RTT sample must cost something ({lossy_fitness}), \
             without discarding a path we have not finished measuring"
        );
    }

    #[test]
    fn routed_shard_selection_orders_by_arrival_and_keeps_paths_disjoint() {
        let router = AdaptiveShardRouter::new();
        let available = vec![
            ("direct_fast".to_string(), "10.0.0.1:1234".parse().unwrap()),
            ("direct_slow".to_string(), "10.0.0.2:1234".parse().unwrap()),
            ("via_relay_a".to_string(), "10.0.0.3:1234".parse().unwrap()),
            ("shadow".to_string(), "10.0.0.4:1234".parse().unwrap()),
        ];
        let now = 1_000.0;
        let mut plan = ContactPlan::default();
        plan.observe_link(
            "me",
            "direct_fast",
            Duration::from_millis(20),
            now,
            60.0,
            0.0,
        );
        plan.observe_link(
            "me",
            "direct_slow",
            Duration::from_millis(80),
            now,
            60.0,
            0.0,
        );
        plan.observe_link("me", "relay_a", Duration::from_millis(2), now, 60.0, 0.0);
        plan.observe_link(
            "relay_a",
            "via_relay_a",
            Duration::from_millis(4),
            now,
            60.0,
            0.0,
        );
        plan.observe_link(
            "relay_a",
            "shadow",
            Duration::from_millis(4),
            now,
            60.0,
            0.0,
        );

        let targets = router.select_shard_targets_routed("me", &available, &plan, now, 4);
        assert_eq!(targets.len(), 4);
        assert_eq!(targets[0].0, "via_relay_a");
        assert_eq!(targets[1].0, "direct_fast");
        assert_eq!(targets[2].0, "direct_slow");
        assert_eq!(targets[3].0, "shadow");

        let routes = router.assign_shards(&targets[..3]);
        assert_eq!(routes.len(), 3);
        let peers: std::collections::HashSet<&str> =
            routes.iter().map(|r| r.peer_fingerprint.as_str()).collect();
        assert_eq!(peers.len(), 3, "each shard must take its own path");
    }

    #[test]
    fn assign_shards_without_targets_is_empty() {
        let router = AdaptiveShardRouter::new();
        assert!(router.assign_shards(&[]).is_empty());
    }

    #[test]
    fn test_adaptive_shard_selection() {
        let router = AdaptiveShardRouter::new();
        let available = vec![
            ("peer_a".to_string(), "10.0.0.1:1234".parse().unwrap()),
            ("peer_b".to_string(), "10.0.0.2:1234".parse().unwrap()),
            ("peer_c".to_string(), "10.0.0.3:1234".parse().unwrap()),
        ];
        let targets = router.select_shard_targets(&available);
        assert!(
            targets.len() >= 2,
            "Should select at least 2 targets for RS(2,1)"
        );

        let routes = router.assign_shards(&targets);
        assert_eq!(routes.len(), 3, "Should assign all 3 shards");
        let indices: Vec<u8> = routes.iter().map(|r| r.shard_index).collect();
        assert!(indices.contains(&0));
        assert!(indices.contains(&1));
        assert!(indices.contains(&2));
    }

    #[test]
    fn test_reciprocity_detection() {
        let rep = Arc::new(PoissonReputationMatrix::new());
        let tft = TitForTatEnforcer::new("self".to_string(), rep);

        tft.forwarded_by("leecher", 100);
        tft.forwarded_by("leecher", 50);
        tft.forwarded_for("leecher", 10_000);

        assert!(tft.ratio_with("leecher") < 0.3, "Leech ratio should be low");

        tft.forwarded_by("fair", 10_000);
        tft.forwarded_for("fair", 10_000);
        assert!(
            tft.ratio_with("fair") > 0.5,
            "Fair ratio should be balanced"
        );
    }

    #[tokio::test]
    async fn test_asymmetric_cgnat_and_relay_only_not_evicted_at_10kb() {
        let rep = Arc::new(PoissonReputationMatrix::new());
        let tft = TitForTatEnforcer::new("self".to_string(), rep);

        tft.forwarded_for("mobile_cgnat", 50_000);
        assert!(
            !tft.should_evict("mobile_cgnat").await,
            "Asymmetric 5G/CGNAT client must not be evicted at 50 KB"
        );
        assert_eq!(tft.rate_limit_factor("mobile_cgnat"), 1.0);

        tft.forwarded_for("mobile_cgnat", 150_000);
        assert!(!tft.should_evict("mobile_cgnat").await);
        assert!(tft.rate_limit_factor("mobile_cgnat") < 1.0);

        tft.set_peer_exempt("relay_only_peer", true);
        tft.forwarded_for("relay_only_peer", 15_000_000);
        assert!(!tft.should_evict("relay_only_peer").await);
        assert_eq!(tft.rate_limit_factor("relay_only_peer"), 1.0);

        tft.forwarded_for("abusive_leecher", 11_000_000);
        assert!(tft.should_evict("abusive_leecher").await);
    }

    #[test]
    fn test_shard_route_assignment() {
        let mesh = AdaptiveShardRouter::new();
        let targets = vec![
            (
                "fast_peer".to_string(),
                "1.1.1.1:1234".parse().unwrap(),
                0.95,
            ),
            (
                "medium_peer".to_string(),
                "2.2.2.2:1234".parse().unwrap(),
                0.60,
            ),
            (
                "slow_peer".to_string(),
                "3.3.3.3:1234".parse().unwrap(),
                0.35,
            ),
        ];
        let routes = mesh.assign_shards(&targets);
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].peer_fingerprint, "fast_peer");
        assert_eq!(routes[0].shard_index, 0);
    }

    #[test]
    fn assign_shards_to_primary_never_scatters_to_other_peers() {
        let router = AdaptiveShardRouter::new();
        let routes = router.assign_shards_to_primary("primary_fp", 3);
        assert_eq!(routes.len(), 3);
        assert!(routes.iter().all(|r| r.peer_fingerprint == "primary_fp"));
        assert_eq!(
            routes.iter().map(|r| r.shard_index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn classify_nat_type_distinguishes_direct_cone_restricted_symmetric_and_unknown() {
        let local: SocketAddr = "192.168.1.10:55225".parse().unwrap();
        let pub_local: SocketAddr = "198.51.100.10:55225".parse().unwrap();
        let mapped_a: SocketAddr = "198.51.100.10:41000".parse().unwrap();
        let mapped_b: SocketAddr = "198.51.100.10:41001".parse().unwrap();

        assert_eq!(classify_nat_type(Some(local), &[]), NatType::Unknown);
        assert_eq!(
            classify_nat_type(Some(pub_local), &[pub_local]),
            NatType::Direct
        );
        assert_eq!(
            classify_nat_type(Some(local), &[mapped_a]),
            NatType::Restricted
        );
        assert_eq!(
            classify_nat_type(Some(local), &[mapped_a, mapped_a]),
            NatType::Cone
        );
        assert_eq!(
            classify_nat_type(Some(local), &[mapped_a, mapped_b]),
            NatType::Symmetric
        );
    }

    #[test]
    fn wan_telemetry_snapshot_updates_atomically() {
        let addr: SocketAddr = "203.0.113.20:55225".parse().unwrap();
        update_wan_telemetry(|snap| {
            snap.public_addr = Some(addr);
            snap.nat_type = NatType::Cone;
            snap.relay_count = 2;
        });
        let snap = wan_telemetry_snapshot();
        assert_eq!(snap.public_addr, Some(addr));
        assert_eq!(snap.nat_type, NatType::Cone);
        assert_eq!(snap.relay_count, 2);
    }
}
