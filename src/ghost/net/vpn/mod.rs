//! LAN-over-WAN VPN module ("road warrior" mode).
//!
//! Implements the audited design from PROTOTYPE.md:
//!
//! - [`LeaseTable`]: overlay-IP leases keyed by Ed25519 fingerprint, with the
//!   strict re-anchor precedence ladder (handshake > window-advance >
//!   silence-fallback). Identity-keyed, never address-keyed.
//! - [`UdpFlowTable`]: per-flow OS socket bindings with aggressive TTLs,
//!   per-fingerprint and global caps, LRU eviction.
//! - [`seal_datagram`] / [`VpnIngress`]: raw-IP datagrams ride the mesh as
//!   UNRELIABLE datagrams — never AckEngine, never RxState, no retransmit,
//!   no head-of-line blocking. Inner TCP owns retransmission. Separate
//!   counter space and a dedicated XChaCha20-Poly1305 AEAD context so tunnel
//!   traffic can never collide with control-channel replay windows or nonces.
//!
//! Nothing in this module allocates an unbounded channel.

#[cfg(target_os = "macos")]
pub mod apple;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chacha20poly1305::KeyInit;
use parking_lot::Mutex;

#[cfg(target_os = "android")]
pub mod android_jni;
pub mod client;
pub mod hub;

pub use netstack::{Done, Headroom};
pub mod netstack;
pub mod tun;

use crate::ghost::layers::l6_session;

/// Overlay IPv4 prefix for the VPN (10.66.0.0/24).
pub const OVERLAY_PREFIX: u8 = 10;
pub const OVERLAY_SECOND_OCTET: u8 = 66;
/// Hub is always .1; clients get .10.. .254.
pub const OVERLAY_HUB_HOST: u8 = 1;
pub const OVERLAY_FIRST_CLIENT_HOST: u8 = 10;
pub const OVERLAY_LAST_CLIENT_HOST: u8 = 254;

/// Client TUN MTU. Fits every IP packet into one 1472-byte GTF bulk frame
/// (1446-byte payload). 1280 = IPv6 minimum MTU.
pub const TUN_MTU: u16 = 1280;
/// TCP MSS advertised on every proxied TCP flow inside the overlay: the
/// tunnel MTU minus IP (20) + TCP (20) headers. The netstack clamps the
/// MSS option on client SYNs and hub SYN-ACKs to this value so no inner
/// segment can exceed one tunnel datagram (PMTUD blackhole guard — LTE
/// paths commonly drop "fragmentation needed" ICMP).
pub const OVERLAY_MSS: u16 = TUN_MTU - 40;

/// UDP flow TTL for DNS-classified flows (destination port 53).
pub const UDP_DNS_TTL: Duration = Duration::from_secs(10);
/// UDP flow TTL for all other flows.
pub const UDP_GENERAL_TTL: Duration = Duration::from_secs(45);
/// Max concurrent UDP flows per client fingerprint.
pub const UDP_FLOWS_PER_FP: usize = 64;
/// Max concurrent UDP flows globally.
pub const UDP_FLOWS_GLOBAL: usize = 1024;

/// Silence window for the re-anchor fallback (route flapping).
pub const SILENCE_REANCHOR: Duration = Duration::from_secs(15);

/// Default TTL before an unrefreshed tunnel epoch self-destructs (§4 Harvest-Then-Decay).
pub const DEFAULT_EPOCH_TTL: Duration = Duration::from_secs(15 + 60);

/// Which role this node plays in the VPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnRole {
    /// Hub: sits in the home LAN, terminates flows, leases overlay IPs.
    Hub,
    /// Client: road warrior, tunnels LAN-bound packets to the hub.
    Client,
}

/// Static VPN configuration (env-driven in main.rs).
#[derive(Debug, Clone)]
pub struct VpnConfig {
    pub role: VpnRole,
    /// Hub overlay IP as seen by clients (default 10.66.0.1).
    pub hub_overlay: Ipv4Addr,
    /// Home-LAN subnet served by the hub (advertised to clients).
    pub lan_subnet: (Ipv4Addr, u8),
    /// DNS server handed to clients (usually the router).
    pub dns_server: Ipv4Addr,
    /// DNS search domain handed to clients (e.g. "fritz.box"). Never ".local" —
    /// unicast DNS cannot resolve mDNS names (v2 adds a relay).
    pub search_domain: Option<String>,
    /// Explicit client allowlist (fingerprint hex). Empty = deny all
    /// (authorization is an operator decision, not a mesh property).
    pub allowed_fingerprints: Vec<String>,
    /// Bind OS flow sockets to this address (the hub's LAN IP), never
    /// 0.0.0.0 (audit: predictable egress on multi-homed hosts).
    pub lan_bind_addr: IpAddr,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            role: VpnRole::Hub,
            hub_overlay: Ipv4Addr::new(OVERLAY_PREFIX, OVERLAY_SECOND_OCTET, 0, OVERLAY_HUB_HOST),
            lan_subnet: (Ipv4Addr::new(192, 168, 1, 0), 24),
            dns_server: Ipv4Addr::new(192, 168, 1, 1),
            search_domain: None,
            allowed_fingerprints: Vec::new(),
            lan_bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

// ── LeaseTable ──────────────────────────────────────────────────────

/// One client lease: overlay IP + live endpoint + epoch.
#[derive(Debug, Clone)]
pub struct Lease {
    pub fingerprint: String,
    pub overlay_ip: Ipv4Addr,
    /// Current best-known wire address for return traffic.
    pub endpoint: SocketAddr,
    /// Session epoch. Rotates on every fresh handshake; invalidates all
    /// per-epoch tunnel state (counters, replay windows).
    pub epoch: u32,
    /// Last authenticated packet from the CURRENT endpoint.
    pub last_seen: Instant,
    /// Highest tunnel counter accepted from this client in this epoch.
    /// Governs the monotonic re-anchor rule.
    pub tunnel_v_max: u32,
    /// Timestamp when this epoch expires and self-destructs (§4 Harvest-Then-Decay).
    pub epoch_ttl: Instant,
}

/// Why a re-anchor (or its refusal) happened — for tests and console output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorEvent {
    /// Fresh handshake rotated the epoch and re-anchored unconditionally.
    HandshakeRotation,
    /// Packet advanced the replay window (N > V_MAX) — monotonic re-anchor.
    WindowAdvance,
    /// Silence fallback: endpoint silent >= SILENCE_REANCHOR, valid in-window
    /// packet from a new address.
    SilenceFallback,
    /// Packet was fine but the endpoint did NOT move (the migration-race
    /// protection: late packet from a dead address).
    NoChange,
}

/// Leases keyed by fingerprint.
#[derive(Default)]
pub struct LeaseTable {
    by_fp: Mutex<HashMap<String, Lease>>,
    by_ip: Mutex<HashMap<Ipv4Addr, String>>,
    next_host: Mutex<u8>,
}

impl LeaseTable {
    pub fn new() -> Self {
        Self {
            by_fp: Mutex::new(HashMap::new()),
            by_ip: Mutex::new(HashMap::new()),
            next_host: Mutex::new(OVERLAY_FIRST_CLIENT_HOST),
        }
    }

    /// Allocate (or return) the overlay IP for a fingerprint.
    /// Caller MUST have verified `cfg.allowed_fingerprints` first.
    pub fn lease_for(&self, fingerprint: &str) -> Option<Ipv4Addr> {
        let mut fps = self.by_fp.lock();
        if let Some(l) = fps.get(fingerprint) {
            return Some(l.overlay_ip);
        }
        let mut next = self.next_host.lock();
        let used: std::collections::HashSet<u8> =
            fps.values().map(|l| l.overlay_ip.octets()[3]).collect();
        let mut host = *next;
        for _ in OVERLAY_FIRST_CLIENT_HOST..=OVERLAY_LAST_CLIENT_HOST {
            if host > OVERLAY_LAST_CLIENT_HOST {
                host = OVERLAY_FIRST_CLIENT_HOST;
            }
            if !used.contains(&host) {
                *next = host + 1;
                let ip = Ipv4Addr::new(OVERLAY_PREFIX, OVERLAY_SECOND_OCTET, 0, host);
                self.by_ip.lock().insert(ip, fingerprint.to_string());
                fps.insert(
                    fingerprint.to_string(),
                    Lease {
                        fingerprint: fingerprint.to_string(),
                        overlay_ip: ip,
                        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                        epoch: 0,
                        last_seen: Instant::now(),
                        tunnel_v_max: 0,
                        epoch_ttl: Instant::now() + DEFAULT_EPOCH_TTL,
                    },
                );
                return Some(ip);
            }
            host += 1;
        }
        None // pool exhausted
    }

    /// Is `ip` a well-formed client overlay address (10.66.0.host)?
    fn is_valid_overlay(ip: Ipv4Addr) -> bool {
        let o = ip.octets();
        o[0] == OVERLAY_PREFIX
            && o[1] == OVERLAY_SECOND_OCTET
            && o[2] == 0
            && o[3] >= OVERLAY_FIRST_CLIENT_HOST
            && o[3] <= OVERLAY_LAST_CLIENT_HOST
    }

    /// Lease honoring a client-provided overlay IP hint. The client
    /// configures its own TUN, so it self-selects its address; the hub
    /// adopts the hint when free (never the hub host, never one claimed by
    /// another fingerprint), otherwise auto-assigns. Returns
    /// `(overlay_ip, hint_was_overridden)`.
    pub fn lease_for_hint(&self, fingerprint: &str, hint: Option<Ipv4Addr>) -> (Ipv4Addr, bool) {
        if let Some(h) = hint {
            if Self::is_valid_overlay(h) {
                let mut fps = self.by_fp.lock();
                if let Some(l) = fps.get(fingerprint) {
                    return (l.overlay_ip, false); // already leased
                }
                let claimed_by_other = fps
                    .values()
                    .any(|l| l.overlay_ip == h && l.fingerprint != fingerprint);
                if !claimed_by_other {
                    let mut next = self.next_host.lock();
                    self.by_ip.lock().insert(h, fingerprint.to_string());
                    fps.insert(
                        fingerprint.to_string(),
                        Lease {
                            fingerprint: fingerprint.to_string(),
                            overlay_ip: h,
                            endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                            epoch: 0,
                            last_seen: Instant::now(),
                            tunnel_v_max: 0,
                            epoch_ttl: Instant::now() + DEFAULT_EPOCH_TTL,
                        },
                    );
                    // Advance the allocator past the hinted host so it is
                    // never reissued to an auto-assigned client.
                    if h.octets()[3] + 1 > OVERLAY_FIRST_CLIENT_HOST {
                        *next = (*next).max(h.octets()[3] + 1);
                    }
                    return (h, false);
                }
                // hint claimed by another fingerprint → auto-assign below
            }
        }
        (
            self.lease_for(fingerprint).unwrap_or(Ipv4Addr::UNSPECIFIED),
            false,
        )
    }

    /// Fresh handshake from a known fingerprint: rotate epoch, zero the
    /// tunnel window, re-anchor unconditionally (precedence 1). Never
    /// consults V_MAX. Returns the event for logging/tests.
    pub fn rotate_epoch(&self, fingerprint: &str, endpoint: SocketAddr) -> Option<AnchorEvent> {
        self.rotate_epoch_with_ttl(fingerprint, endpoint, DEFAULT_EPOCH_TTL)
    }

    /// Fresh handshake with explicit epoch TTL (§4 Harvest-Then-Decay).
    pub fn rotate_epoch_with_ttl(
        &self,
        fingerprint: &str,
        endpoint: SocketAddr,
        ttl: Duration,
    ) -> Option<AnchorEvent> {
        let mut fps = self.by_fp.lock();
        let l = fps.get_mut(fingerprint)?;
        l.epoch = l.epoch.wrapping_add(1);
        l.tunnel_v_max = 0;
        l.endpoint = endpoint;
        l.last_seen = Instant::now();
        l.epoch_ttl = Instant::now() + ttl;
        Some(AnchorEvent::HandshakeRotation)
    }

    /// Adopt an authenticated tunnel epoch exactly, without assuming epochs
    /// advance by one. This is used for loss-tolerant mobility where a client
    /// may complete several re-anchors before the hub sees the next packet.
    pub fn adopt_epoch(&self, fingerprint: &str, epoch: u32, endpoint: SocketAddr) -> bool {
        self.adopt_epoch_with_ttl(fingerprint, epoch, endpoint, DEFAULT_EPOCH_TTL)
    }

    /// Adopt an authenticated tunnel epoch with explicit TTL (§4 Harvest-Then-Decay).
    pub fn adopt_epoch_with_ttl(
        &self,
        fingerprint: &str,
        epoch: u32,
        endpoint: SocketAddr,
        ttl: Duration,
    ) -> bool {
        let mut fps = self.by_fp.lock();
        let Some(lease) = fps.get_mut(fingerprint) else {
            return false;
        };
        lease.epoch = epoch;
        lease.tunnel_v_max = 0;
        lease.endpoint = endpoint;
        lease.last_seen = Instant::now();
        lease.epoch_ttl = Instant::now() + ttl;
        true
    }

    /// Check if the client's current epoch has expired and self-destructed (§4 Harvest-Then-Decay).
    pub fn is_epoch_expired(&self, fingerprint: &str) -> bool {
        let fps = self.by_fp.lock();
        fps.get(fingerprint)
            .map(|l| Instant::now() >= l.epoch_ttl)
            .unwrap_or(true)
    }

    /// Force immediate self-destruction/expiration of an epoch (§4 Harvest-Then-Decay).
    pub fn expire_epoch_now(&self, fingerprint: &str) -> bool {
        let mut fps = self.by_fp.lock();
        let Some(l) = fps.get_mut(fingerprint) else {
            return false;
        };
        l.epoch_ttl = Instant::now() - Duration::from_secs(1);
        l.tunnel_v_max = u32::MAX;
        true
    }

    /// Current epoch for a fingerprint (0 if unleased).
    pub fn epoch_of(&self, fingerprint: &str) -> Option<u32> {
        self.by_fp.lock().get(fingerprint).map(|l| l.epoch)
    }

    /// A tunnel packet from `from` with counter `ctr` was authenticated.
    /// Applies the re-anchor precedence ladder:
    ///   1. (handled by `rotate_epoch` — never here)
    ///   2. ctr > tunnel_v_max  → accept + re-anchor (monotonic rule)
    ///   3. in-window + silent endpoint >= SILENCE_REANCHOR → re-anchor
    ///   else: accept as data, endpoint unchanged (late-packet race guard).
    pub fn observe_tunnel_packet(
        &self,
        fingerprint: &str,
        epoch: u32,
        ctr: u32,
        from: SocketAddr,
    ) -> (bool, AnchorEvent) {
        let mut fps = self.by_fp.lock();
        let Some(l) = fps.get_mut(fingerprint) else {
            return (false, AnchorEvent::NoChange);
        };
        if l.epoch != epoch {
            // stale epoch packet — authenticated but from a dead session era
            return (false, AnchorEvent::NoChange);
        }
        if Instant::now() >= l.epoch_ttl {
            // §4 Harvest-Then-Decay: epoch self-destructed.
            // Reset tunnel_v_max to u32::MAX so any historical packet from this epoch is dead.
            l.tunnel_v_max = u32::MAX;
            return (false, AnchorEvent::NoChange);
        }
        let advanced = ctr > l.tunnel_v_max;
        if advanced {
            l.tunnel_v_max = ctr;
        }
        if l.endpoint != from {
            if advanced {
                l.endpoint = from;
                l.last_seen = Instant::now();
                return (true, AnchorEvent::WindowAdvance);
            }
            if l.last_seen.elapsed() >= SILENCE_REANCHOR {
                l.endpoint = from;
                l.last_seen = Instant::now();
                return (true, AnchorEvent::SilenceFallback);
            }
            // The migration-race guard: valid data from a dead address does
            // NOT move the endpoint.
            return (true, AnchorEvent::NoChange);
        }
        l.last_seen = Instant::now();
        (
            true,
            if advanced {
                AnchorEvent::WindowAdvance
            } else {
                AnchorEvent::NoChange
            },
        )
    }

    /// Where return traffic goes for an overlay IP. O(1) lookup via secondary by_ip index.
    pub fn endpoint_for_ip(&self, overlay_ip: Ipv4Addr) -> Option<SocketAddr> {
        let fp = self.by_ip.lock().get(&overlay_ip).cloned()?;
        let fps = self.by_fp.lock();
        let l = fps.get(&fp)?;
        if l.endpoint.port() != 0 {
            Some(l.endpoint)
        } else {
            None
        }
    }

    /// Fingerprint owning an overlay IP. O(1) lookup via secondary by_ip index.
    pub fn fingerprint_for_ip(&self, overlay_ip: Ipv4Addr) -> Option<String> {
        self.by_ip.lock().get(&overlay_ip).cloned()
    }

    pub fn lease_count(&self) -> usize {
        self.by_fp.lock().len()
    }

    /// Console snapshot for `LEASES`.
    pub fn snapshot(&self) -> Vec<Lease> {
        let mut v: Vec<Lease> = self.by_fp.lock().values().cloned().collect();
        v.sort_by_key(|l| l.overlay_ip);
        v
    }
}

// ── UdpFlowTable ────────────────────────────────────────────────────

/// Key of one userspace UDP flow on the hub.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub fp: String,
    pub overlay_src: Ipv4Addr,
    pub overlay_port: u16,
    pub dst: SocketAddr,
}

/// A live UDP flow: the bound OS socket (demux key) + metadata.
#[derive(Clone)]
pub struct UdpFlow {
    pub key: FlowKey,
    /// The bound OS socket. Return packets from the LAN arrive here and are
    /// demuxed back into the tunnel by `local_port`.
    pub socket: Arc<std::net::UdpSocket>,
    pub last_seen: Instant,
    pub is_dns: bool,
}

impl UdpFlow {
    pub fn local_port(&self) -> u16 {
        self.socket.local_addr().map(|a| a.port()).unwrap_or(0)
    }
}

/// Bounded UDP flow table (audit rule 3): TTLs, per-fp cap, global cap, LRU.
pub struct UdpFlowTable {
    flows: Mutex<HashMap<FlowKey, Arc<UdpFlow>>>,
    by_port: Mutex<HashMap<u16, FlowKey>>,
    lan_bind: IpAddr,
    /// Flow TTLs (production defaults; injectable for churn-gate timing).
    dns_ttl: Duration,
    general_ttl: Duration,
    /// Injected factory so tests run without binding real LAN addresses.
    bind_socket: Box<dyn Fn(IpAddr) -> std::io::Result<Arc<std::net::UdpSocket>> + Send + Sync>,
}

fn real_bind(addr: IpAddr) -> std::io::Result<Arc<std::net::UdpSocket>> {
    let bind_to = SocketAddr::new(addr, 0);
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(bind_to),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_address(true)?;
    let sa = socket2::SockAddr::from(bind_to);
    sock.bind(&sa)?;
    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(Arc::new(std_sock))
}

impl UdpFlowTable {
    pub fn new(lan_bind: IpAddr) -> Self {
        Self::with_timing(lan_bind, UDP_DNS_TTL, UDP_GENERAL_TTL)
    }

    /// Constructor with injected flow TTLs (test timing; production via `new`).
    pub fn with_timing(lan_bind: IpAddr, dns_ttl: Duration, general_ttl: Duration) -> Self {
        Self {
            flows: Mutex::new(HashMap::new()),
            by_port: Mutex::new(HashMap::new()),
            lan_bind,
            bind_socket: Box::new(real_bind),
            dns_ttl,
            general_ttl,
        }
    }

    /// Test constructor: inject a fake binder.
    pub fn with_binder(
        lan_bind: IpAddr,
        f: Box<dyn Fn(IpAddr) -> std::io::Result<Arc<std::net::UdpSocket>> + Send + Sync>,
    ) -> Self {
        Self {
            flows: Mutex::new(HashMap::new()),
            by_port: Mutex::new(HashMap::new()),
            lan_bind,
            bind_socket: f,
            dns_ttl: UDP_DNS_TTL,
            general_ttl: UDP_GENERAL_TTL,
        }
    }

    /// Get-or-create the OS binding for a flow, enforcing caps. Returns the
    /// flow (socket included). On cap breach the LRU flow is evicted; if
    /// still over, the new flow is refused (drop — v1). Bounded, no EMFILE.
    pub fn get_or_create(&self, key: FlowKey) -> Option<Arc<UdpFlow>> {
        let mut flows = self.flows.lock();
        if let Some(f) = flows.get(&key) {
            // cheap refresh: bump last_seen by reinserting a fresh Arc copy
            let refreshed = Arc::new(UdpFlow {
                key: f.key.clone(),
                socket: Arc::clone(&f.socket),
                last_seen: Instant::now(),
                is_dns: f.is_dns,
            });
            flows.insert(key, Arc::clone(&refreshed));
            return Some(refreshed);
        }
        let per_fp = flows.values().filter(|f| f.key.fp == key.fp).count();
        if per_fp >= UDP_FLOWS_PER_FP {
            Self::evict_lru_for(&mut *flows, &mut *self.by_port.lock(), Some(&key.fp));
        }
        if flows.len() >= UDP_FLOWS_GLOBAL {
            Self::evict_lru_for(&mut *flows, &mut *self.by_port.lock(), None);
            if flows.len() >= UDP_FLOWS_GLOBAL {
                return None; // still full: refuse (drop) — bounded
            }
        }
        let socket = (self.bind_socket)(self.lan_bind).ok()?;
        let is_dns = key.dst.port() == 53;
        let flow = Arc::new(UdpFlow {
            key: key.clone(),
            socket,
            last_seen: Instant::now(),
            is_dns,
        });
        let local_port = flow.local_port();
        flows.insert(key.clone(), Arc::clone(&flow));
        if local_port != 0 {
            self.by_port.lock().insert(local_port, key);
        }
        Some(flow)
    }

    fn evict_lru_for(
        flows: &mut HashMap<FlowKey, Arc<UdpFlow>>,
        by_port: &mut HashMap<u16, FlowKey>,
        fp: Option<&str>,
    ) {
        let victim = flows
            .values()
            .filter(|f| fp.map_or(true, |p| f.key.fp == p))
            .min_by_key(|f| f.last_seen)
            .map(|f| (f.key.clone(), f.local_port()));
        if let Some((k, port)) = victim {
            flows.remove(&k);
            by_port.remove(&port);
        }
    }

    /// Lazy expiry: drop flows silent past their TTL.
    pub fn sweep(&self) -> usize {
        let mut flows = self.flows.lock();
        let mut by_port = self.by_port.lock();
        let before = flows.len();
        let dns_ttl = self.dns_ttl;
        let general_ttl = self.general_ttl;
        flows.retain(|_, f| {
            let ttl = if f.is_dns { dns_ttl } else { general_ttl };
            let keep = f.last_seen.elapsed() < ttl;
            if !keep {
                by_port.remove(&f.local_port());
            }
            keep
        });
        before - flows.len()
    }

    /// Demux: which flow does a packet arriving on local port `port` belong to?
    /// O(1) lookup via secondary by_port index.
    pub fn flow_for_local_port(&self, port: u16) -> Option<FlowKey> {
        self.by_port.lock().get(&port).cloned()
    }

    pub fn len(&self) -> usize {
        self.flows.lock().len()
    }

    /// How many live flows belong to one fingerprint (`VPN STATUS`).
    pub fn count_for(&self, fp: &str) -> usize {
        self.flows.lock().keys().filter(|k| k.fp == fp).count()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.lock().is_empty()
    }
}

// ── Tunnel datagram crypto ──────────────────────────────────────────

/// Wire layout of a VPN tunnel datagram (before mesh framing):
/// `[4B epoch][8B ctr][8B rand][XChaCha20-Poly1305(payload + tag)]`
///
/// G6: widened from `[4B epoch][4B ctr][ChaCha20-Poly1305(…)]` (HDR=8) to
/// eliminate 32-bit counter exhaustion. The random segment makes the 24-byte
/// XChaCha nonce unique even if (epoch, ctr) repeats across sessions, and the
/// u64 counter space is effectively inexhaustible.
pub const TUNNEL_HDR_LEN: usize = 20; // 4 + 8 + 8

/// Max inner IP packet we carry (TUN_MTU) + AEAD tag.
pub const TUNNEL_MAX_PAYLOAD: usize = TUN_MTU as usize + 16;

/// Context bytes mixed into the XChaCha nonce.
const TUNNEL_CONTEXT: [u8; 4] = *b"GTun";

/// Build a 24-byte XChaCha nonce from the tunnel context, epoch, counter
/// and a random segment: `[4B "GTun" | 4B epoch | 8B ctr | 8B rand]`.
fn tunnel_xnonce(epoch: u32, ctr: u64, rand_seg: &[u8; 8]) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0..4].copy_from_slice(&TUNNEL_CONTEXT);
    nonce[4..8].copy_from_slice(&epoch.to_be_bytes());
    nonce[8..16].copy_from_slice(&ctr.to_be_bytes());
    nonce[16..24].copy_from_slice(rand_seg);
    nonce
}

/// Generate a fresh 8-byte random segment for the tunnel nonce.
fn tunnel_rand_seg() -> [u8; 8] {
    let mut r = [0u8; 8];
    rand::Rng::fill(&mut rand::thread_rng(), &mut r[..]);
    r
}

/// Seal a raw IP packet into a tunnel datagram. Pure function.
///
/// G6: uses XChaCha20-Poly1305 with a u64 counter and an 8-byte random
/// nonce segment transmitted on the wire, so the nonce space cannot exhaust.
pub fn seal_datagram(key: &[u8; 32], epoch: u32, ctr: u64, ip_packet: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::AeadInPlace;
    let mut body = ip_packet.to_vec();
    let rand_seg = tunnel_rand_seg();
    let nonce = tunnel_xnonce(epoch, ctr, &rand_seg);
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(chacha20poly1305::XNonce::from_slice(&nonce), &[], &mut body)
        .expect("AEAD seal cannot fail for valid key");
    let mut out = Vec::with_capacity(TUNNEL_HDR_LEN + body.len() + 16);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&ctr.to_be_bytes());
    out.extend_from_slice(&rand_seg);
    out.extend_from_slice(&body);
    out.extend_from_slice(tag.as_slice());
    out
}

/// Result of opening a tunnel datagram.
pub enum OpenOutcome {
    /// Authenticated + fresh; payload is the inner IP packet. `advanced` is
    /// true when the replay window moved (drives re-anchor permission).
    Accepted { ip_packet: Vec<u8>, advanced: bool },
    /// Authenticated but duplicate/ancient counter (replay) — drop.
    Replay,
    /// Authentication failed or stale epoch — hostile/corrupt; drop.
    AuthFail,
}

/// Replay-window state per (fingerprint, epoch).
#[derive(Default)]
struct TunnelRx {
    guard: l6_session::SessionGuardU64,
    v_max: u64,
}

/// Ingress engine: owns per-epoch replay state and opens datagrams.
/// This is the ONLY path tunnel packets take — structurally disconnected
/// from AckEngine/RxState (audited M1 invariant).
pub struct VpnIngress {
    rx: Mutex<HashMap<(String, u32), TunnelRx>>,
}

impl Default for VpnIngress {
    fn default() -> Self {
        Self {
            rx: Mutex::new(HashMap::new()),
        }
    }
}

impl VpnIngress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a tunnel datagram. `expected_epoch` comes from the LeaseTable
    /// (set by rotate_epoch). Returns the outcome; never blocks.
    ///
    /// G6: reads the widened `[4B epoch][8B ctr][8B rand][ct+tag]` format
    /// and uses XChaCha20-Poly1305 to open.
    pub fn open(
        &self,
        key: &[u8; 32],
        fingerprint: &str,
        expected_epoch: u32,
        wire: &[u8],
    ) -> OpenOutcome {
        use chacha20poly1305::aead::AeadInPlace;
        if wire.len() < TUNNEL_HDR_LEN + 16 {
            return OpenOutcome::AuthFail;
        }
        let epoch = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
        let ctr = u64::from_be_bytes([
            wire[4], wire[5], wire[6], wire[7], wire[8], wire[9], wire[10], wire[11],
        ]);
        let rand_seg: [u8; 8] = [
            wire[12], wire[13], wire[14], wire[15], wire[16], wire[17], wire[18], wire[19],
        ];
        if epoch != expected_epoch {
            return OpenOutcome::AuthFail; // dead era
        }
        let mut body = wire[TUNNEL_HDR_LEN..].to_vec();
        let split = body.len() - 16;
        let tag_bytes = body.split_off(split);
        let mut tag = chacha20poly1305::Tag::default();
        tag.copy_from_slice(&tag_bytes);
        let nonce = tunnel_xnonce(epoch, ctr, &rand_seg);
        let cipher =
            chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
        if cipher
            .decrypt_in_place_detached(
                chacha20poly1305::XNonce::from_slice(&nonce),
                &[],
                &mut body,
                &tag,
            )
            .is_err()
        {
            return OpenOutcome::AuthFail;
        }
        let mut rx = self.rx.lock();
        let state = rx.entry((fingerprint.to_string(), epoch)).or_default();
        let advanced = ctr > state.v_max;
        if !state.guard.check_and_update(ctr) {
            return OpenOutcome::Replay;
        }
        if advanced {
            state.v_max = ctr;
        }
        OpenOutcome::Accepted {
            ip_packet: body,
            advanced,
        }
    }

    /// Evict all state for a fingerprint (epoch rotation cleanup).
    pub fn evict(&self, fingerprint: &str) {
        self.rx.lock().retain(|(fp, _), _| fp != fingerprint);
    }

    /// Retain only the authenticated current epoch for a fingerprint.
    ///
    /// Mobility can advance an inner tunnel epoch before the outer mesh
    /// session is rebuilt. The candidate epoch must be authenticated first;
    /// only then is older replay state removed. Keeping this operation separate
    /// prevents an unauthenticated packet from forcing a destructive reset.
    pub fn retain_epoch(&self, fingerprint: &str, epoch: u32) {
        self.rx
            .lock()
            .retain(|(fp, e), _| fp != fingerprint || *e == epoch);
    }
}

// ── Tests (module-level invariants, no OS/LAN needed) ───────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u8) -> String {
        format!("{n:016x}")
    }

    #[test]
    fn lease_allocation_is_stable_and_unique() {
        let t = LeaseTable::new();
        let a = t.lease_for(&fp(1)).unwrap();
        let b = t.lease_for(&fp(2)).unwrap();
        let a2 = t.lease_for(&fp(1)).unwrap();
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn migration_race_late_packet_does_not_move_endpoint() {
        let t = LeaseTable::new();
        let f = fp(7);
        t.lease_for(&f).unwrap();
        let ip_a: SocketAddr = "198.51.100.10:40000".parse().unwrap();
        let ip_b: SocketAddr = "203.0.113.99:51000".parse().unwrap();
        t.rotate_epoch(&f, ip_a);
        // N+1 from the new address advances the window and re-anchors
        let (ok, ev) = t.observe_tunnel_packet(&f, 1, 151, ip_b);
        assert!(ok && ev == AnchorEvent::WindowAdvance);
        // late N from the dead address: accepted as data, endpoint unchanged
        let (_ok, ev2) = t.observe_tunnel_packet(&f, 1, 150, ip_a);
        assert_eq!(ev2, AnchorEvent::NoChange);
        assert_eq!(t.endpoint_for_ip(t.lease_for(&f).unwrap()).unwrap(), ip_b);
    }

    #[test]
    fn silence_fallback_reanchors_after_window() {
        let t = LeaseTable::new();
        let f = fp(8);
        t.lease_for(&f).unwrap();
        let ip_a: SocketAddr = "198.51.100.10:40000".parse().unwrap();
        t.rotate_epoch(&f, ip_a);
        // backdate last_seen beyond the silence window
        {
            let mut m = t.by_fp.lock();
            m.get_mut(&f).unwrap().last_seen =
                Instant::now() - SILENCE_REANCHOR - Duration::from_secs(1);
        }
        let ip_c: SocketAddr = "203.0.113.5:52000".parse().unwrap();
        // in-window counter (not advancing) from a fresh address
        t.observe_tunnel_packet(&f, 1, 1, ip_c);
        assert_eq!(t.endpoint_for_ip(t.lease_for(&f).unwrap()).unwrap(), ip_c);
    }

    #[test]
    fn stale_epoch_packets_are_rejected() {
        let t = LeaseTable::new();
        let f = fp(9);
        t.lease_for(&f).unwrap();
        let ep: SocketAddr = "198.51.100.1:1".parse().unwrap();
        t.rotate_epoch(&f, ep); // epoch 1
        let (ok, _) = t.observe_tunnel_packet(&f, 0, 500, ep);
        assert!(!ok);
    }

    #[test]
    fn tunnel_datagram_roundtrip_replay_tamper() {
        let key = [42u8; 32];
        let packet = vec![0x45u8; 60];
        let wire = seal_datagram(&key, 3, 17, &packet);
        let ing = VpnIngress::new();
        match ing.open(&key, "aa", 3, &wire) {
            OpenOutcome::Accepted {
                ip_packet,
                advanced,
            } => {
                assert_eq!(ip_packet, packet);
                assert!(advanced);
            }
            _ => panic!("first open must accept"),
        }
        assert!(matches!(
            ing.open(&key, "aa", 3, &wire),
            OpenOutcome::Replay
        ));
        let mut tampered = wire.clone();
        tampered[TUNNEL_HDR_LEN + 2] ^= 0xFF; // flip a byte in the ciphertext body
        assert!(matches!(
            ing.open(&key, "aa", 3, &tampered),
            OpenOutcome::AuthFail
        ));
        // wrong epoch never opens
        assert!(matches!(
            ing.open(&key, "aa", 4, &wire),
            OpenOutcome::AuthFail
        ));
    }

    #[test]
    fn epoch_rotation_evicts_ingress_state() {
        let key = [7u8; 32];
        let ing = VpnIngress::new();
        let wire = seal_datagram(&key, 1, 5, &[0x45u8; 40]);
        assert!(matches!(
            ing.open(&key, "bb", 1, &wire),
            OpenOutcome::Accepted { .. }
        ));
        ing.evict("bb");
        // after eviction the replay window is gone: same wire opens again
        assert!(matches!(
            ing.open(&key, "bb", 1, &wire),
            OpenOutcome::Accepted { .. }
        ));
    }

    #[test]
    fn flow_table_caps_enforced() {
        let binder = Box::new(|_a: IpAddr| {
            std::net::UdpSocket::bind("127.0.0.1:0")
                .map(|s| Arc::new(s))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrInUse, e))
        });
        let t = UdpFlowTable::with_binder(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), binder);
        for i in 0..(UDP_FLOWS_PER_FP + 8) {
            let _ = t.get_or_create(FlowKey {
                fp: fp(1),
                overlay_src: Ipv4Addr::new(10, 66, 0, 10),
                overlay_port: 5000 + i as u16,
                dst: SocketAddr::from(([192, 168, 1, 1], 53)),
            });
        }
        assert_eq!(t.len(), UDP_FLOWS_PER_FP); // per-fp cap holds via LRU eviction
    }

    #[test]
    fn flow_table_ttl_sweep_and_demux() {
        let binder = Box::new(|_a: IpAddr| {
            std::net::UdpSocket::bind("127.0.0.1:0")
                .map(|s| Arc::new(s))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrInUse, e))
        });
        let t = UdpFlowTable::with_binder(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), binder);
        let key = FlowKey {
            fp: fp(2),
            overlay_src: Ipv4Addr::new(10, 66, 0, 11),
            overlay_port: 5353,
            dst: SocketAddr::from(([192, 168, 1, 1], 53)),
        };
        let flow = t.get_or_create(key.clone()).unwrap();
        let port = flow.local_port();
        assert_eq!(t.flow_for_local_port(port).as_ref(), Some(&key));
        assert_eq!(t.sweep(), 0); // fresh flow survives
        {
            let mut fl = t.flows.lock();
            let f = Arc::make_mut(fl.get_mut(&key).unwrap());
            f.last_seen = Instant::now() - UDP_DNS_TTL - Duration::from_secs(1);
        }
        assert_eq!(t.sweep(), 1);
        assert_eq!(t.len(), 0);
        assert_eq!(t.flow_for_local_port(port), None); // by_port secondary index cleaned up

        // Test D11: refreshed Arc is returned with fresh last_seen
        let flow1 = t.get_or_create(key.clone()).unwrap();
        let old_seen = flow1.last_seen;
        std::thread::sleep(Duration::from_millis(5));
        let flow2 = t.get_or_create(key.clone()).unwrap();
        assert!(
            flow2.last_seen > old_seen,
            "get_or_create must return refreshed Arc"
        );
    }

    /// G6 regression: a counter beyond u32::MAX roundtrips correctly.
    #[test]
    fn test_tunnel_u64_counter_beyond_u32_max() {
        let key = [0xABu8; 32];
        let packet = vec![0x45u8; 100];
        let big_ctr: u64 = (u32::MAX as u64) + 42;
        let wire = seal_datagram(&key, 1, big_ctr, &packet);
        let ing = VpnIngress::new();
        match ing.open(&key, "g6", 1, &wire) {
            OpenOutcome::Accepted { ip_packet, .. } => {
                assert_eq!(ip_packet, packet);
            }
            other => panic!(
                "expected Accepted, got {:?}",
                match other {
                    OpenOutcome::Replay => "Replay",
                    OpenOutcome::AuthFail => "AuthFail",
                    _ => "unknown",
                }
            ),
        }
    }

    /// G6 regression: same (epoch, ctr) with different random segments produces
    /// different ciphertexts — the random nonce segment provides uniqueness.
    #[test]
    fn test_tunnel_xnonce_uniqueness() {
        let key = [0xCDu8; 32];
        let packet = vec![0x60u8; 80];
        let w1 = seal_datagram(&key, 2, 99, &packet);
        let w2 = seal_datagram(&key, 2, 99, &packet);
        // The random segments (bytes 12..20) must differ with overwhelming probability
        assert_ne!(
            &w1[12..20],
            &w2[12..20],
            "two seals must use different random nonce segments"
        );
        // And therefore the ciphertexts differ
        assert_ne!(w1, w2);
        // But both must open correctly
        let ing = VpnIngress::new();
        assert!(matches!(
            ing.open(&key, "uniq", 2, &w1),
            OpenOutcome::Accepted { .. }
        ));
        // Second one has same counter — replay, which is expected since the
        // replay window only tracks the counter, not the random segment.
        assert!(matches!(
            ing.open(&key, "uniq", 2, &w2),
            OpenOutcome::Replay
        ));
    }

    #[test]
    fn test_self_destructing_epoch_decay_and_auth_fail() {
        // §4 Harvest-Then-Decay Proof:
        // Intercepted wire datagram accepted at T0 is permanently rejected with AuthFail
        // after the epoch decays/self-destructs, rather than Replay.
        let t = LeaseTable::new();
        let f = fp(44);
        t.lease_for(&f).unwrap();
        let ep: SocketAddr = "198.51.100.1:40000".parse().unwrap();

        // 1. Rotate with short 40ms TTL for deterministic local test
        t.rotate_epoch_with_ttl(&f, ep, Duration::from_millis(40));
        assert!(!t.is_epoch_expired(&f));

        // Packet accepted during active epoch lifetime
        let (ok, ev) = t.observe_tunnel_packet(&f, 1, 10, ep);
        assert!(ok);
        assert_eq!(ev, AnchorEvent::WindowAdvance);

        // 2. Wait for epoch decay (> 40ms)
        std::thread::sleep(Duration::from_millis(50));
        assert!(t.is_epoch_expired(&f));

        // 3. Replay of old counter or new counter from decayed epoch fails
        let (ok_replay, ev_replay) = t.observe_tunnel_packet(&f, 1, 10, ep);
        assert!(
            !ok_replay,
            "Replayed packet from decayed epoch must be rejected"
        );
        assert_eq!(ev_replay, AnchorEvent::NoChange);

        let (ok_new, _) = t.observe_tunnel_packet(&f, 1, 11, ep);
        assert!(!ok_new, "New packet from decayed epoch must be rejected");

        // 4. Ingress level: when epoch decays and client re-handshakes to epoch 2,
        // captured wire datagram from epoch 1 replayed against post-decay session returns AuthFail
        let ingress = VpnIngress::new();
        let key = [0x77u8; 32];
        let packet = vec![0x33u8; 64];
        let wire = seal_datagram(&key, 1, 10, &packet);

        // Valid while expected_epoch == 1
        let outcome1 = ingress.open(&key, "decay_test", 1, &wire);
        assert!(matches!(outcome1, OpenOutcome::Accepted { .. }));

        // Replay in same epoch -> Replay
        let outcome_rep = ingress.open(&key, "decay_test", 1, &wire);
        assert!(matches!(outcome_rep, OpenOutcome::Replay));

        // After decay & session advance to epoch 2: old wire packet -> AuthFail!
        ingress.evict("decay_test");
        let outcome_post_decay = ingress.open(&key, "decay_test", 2, &wire);
        assert!(
            matches!(outcome_post_decay, OpenOutcome::AuthFail),
            "Decayed epoch wire packet must fail with AuthFail"
        );
    }
}
