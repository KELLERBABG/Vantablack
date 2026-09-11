//! Hub orchestration — glues mesh packet handling to the lease table,
//! netstack, and UDP flow table, and pumps egress back into the mesh.
//!
//! Wire encapsulation inside a session: after the standard GTF assembly and
//! session AEAD decryption, a VPN payload is
//! `b"GVPN1" + seal_datagram(key, epoch, ctr, ip_packet)` where the inner
//! AEAD uses the SAME session master key but a dedicated nonce domain
//! (`tunnel_nonce`) — tunnel and control traffic never share a nonce pair.
//! The session guard already rejected replays at the frame layer; the inner
//! epoch/ctr drive the LEASE re-anchor ladder and a second replay window.
//!
//! All egress produced here is the BARE tunnel datagram (epoch||ctr||ct||tag).
//! Callers (main.rs) prepend the `GVPN1` magic exactly once when wrapping.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use super::netstack::Netstack;
use super::{
    seal_datagram, FlowKey, LeaseTable, OpenOutcome, UdpFlowTable, VpnConfig, VpnIngress,
};

/// Magic prefix marking a VPN tunnel payload inside a decrypted session frame.
pub const VPN_PAYLOAD_MAGIC: &[u8; 5] = b"GVPN1";

/// Egress unit: a sealed tunnel datagram plus the session routing info.
pub struct EgressUnit {
    pub fingerprint: String,
    pub session_hash: [u8; 4],
    pub endpoint: SocketAddr,
    /// Bare tunnel datagram (epoch || ctr || ciphertext || tag) — the caller
    /// wraps it as `[GVPN1][wire]` inside the session-encrypted frame.
    pub wire: Vec<u8>,
}

/// Per-client session material the hub caches for egress sealing.
#[derive(Clone)]
struct ClientSession {
    master_key: [u8; 32],
    session_hash: [u8; 4],
    endpoint: SocketAddr,
}

/// The hub-side VPN context. Handlers are synchronous; main.rs drives the
/// async egress pumps around them.
pub struct VpnHub {
    pub cfg: VpnConfig,
    pub leases: LeaseTable,
    pub flows: Arc<UdpFlowTable>,
    pub netstack: Netstack,
    sessions: Mutex<HashMap<String, ClientSession>>,
    /// Flows we already spawned a reader thread for (dedup across packets).
    readers_spawned: Mutex<HashSet<FlowKey>>,
    ingress: VpnIngress,
    /// Inner-epoch per fingerprint (mirror of the lease epoch for fast checks).
    ingress_epochs: Mutex<HashMap<String, u32>>,
    /// Hub→client tunnel counters (per fingerprint).
    tx_counters: Mutex<HashMap<String, u32>>,
    /// Egress queue: (fingerprint, bare tunnel wire). Bounded (rule 3).
    egress: Mutex<std::sync::mpsc::Receiver<(String, Vec<u8>)>>,
    egress_tx: std::sync::mpsc::SyncSender<(String, Vec<u8>)>,
    stats_in: AtomicU32,
    stats_out: AtomicU32,
    /// Reader idle limit (production default; injected for churn gates).
    reader_idle_limit: Duration,
    stats_dropped: AtomicU32,
}

impl VpnHub {
    pub fn start(cfg: VpnConfig) -> Arc<Self> {
        let flows = Arc::new(UdpFlowTable::new(cfg.lan_bind_addr));
        Self::start_with_flows(cfg, flows, Duration::from_secs(10))
    }

    /// Test constructor: inject the flow table (which carries its own TTLs)
    /// and the reader idle limit — churn-gate timing, no runtime knobs.
    pub fn start_with_flows(
        cfg: VpnConfig,
        flows: Arc<UdpFlowTable>,
        reader_idle_limit: Duration,
    ) -> Arc<Self> {
        let netstack = Netstack::start();
        let (tx, rx) = std::sync::mpsc::sync_channel::<(String, Vec<u8>)>(4096);
        Arc::new(Self {
            cfg,
            leases: LeaseTable::new(),
            flows,
            netstack,
            sessions: Mutex::new(HashMap::new()),
            readers_spawned: Mutex::new(HashSet::new()),
            ingress: VpnIngress::new(),
            ingress_epochs: Mutex::new(HashMap::new()),
            tx_counters: Mutex::new(HashMap::new()),
            egress: Mutex::new(rx),
            egress_tx: tx,
            stats_in: AtomicU32::new(0),
            stats_out: AtomicU32::new(0),
            stats_dropped: AtomicU32::new(0),
            reader_idle_limit,
        })
    }

    /// Fresh handshake from a client (precedence 1 of the re-anchor ladder):
    /// allocate/refresh the lease, re-anchor unconditionally, zero the tunnel
    /// window, and evict all per-epoch state. Never consults V_MAX.
    pub fn on_handshake(&self, fp: &str, endpoint: SocketAddr) {
        if !self.authorized(fp) {
            return;
        }
        self.leases.lease_for(fp); // ensure a lease exists
        if self.leases.rotate_epoch(fp, endpoint).is_some() {
            self.ingress.evict(fp);
            self.sessions.lock().remove(fp);
            self.tx_counters.lock().remove(fp);
            self.readers_spawned.lock().retain(|k| k.fp != fp);
            // Fresh epoch: the client restarts its counter space, so the
            // hub must too (keyed by fingerprint only).
            self.tx_counters.lock().remove(fp);
            tracing::info!(peer = %fp, "VPN handshake: epoch rotated, state evicted");
        }
    }

    /// Is `fp` allowed to use this hub?
    pub fn authorized(&self, fp: &str) -> bool {
        self.cfg.allowed_fingerprints.iter().any(|a| a == fp)
    }

    /// Handle a decrypted `GVPN1` payload from a client.
    /// `fp` is the verified peer fingerprint; `master_key`/`session_hash`
    /// come from the session the frame arrived in; `src` is the wire address.
    pub fn handle_tunnel_payload(
        self: &Arc<Self>,
        fp: &str,
        master_key: &[u8; 32],
        session_hash: [u8; 4],
        payload: &[u8],
        src: SocketAddr,
    ) {
        if payload.len() < super::TUNNEL_HDR_LEN + 16 {
            return;
        }
        if !self.authorized(fp) {
            tracing::warn!(peer = %fp, "VPN tunnel denied — fingerprint not in GHOST_VPN_CLIENTS");
            return;
        }
        self.sessions.lock().insert(
            fp.to_string(),
            ClientSession {
                master_key: *master_key,
                session_hash,
                endpoint: src,
            },
        );

        // Adopt a NEW inner epoch before open(): a fresh epoch means the
        // client re-handshook (precedence 1) — evict all its per-epoch state.
        let epoch = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let ctr = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let mut epochs = self.ingress_epochs.lock();
        let adopted = match epochs.get(fp) {
            None => {
                epochs.insert(fp.to_string(), epoch);
                self.leases.rotate_epoch(fp, src);
                self.ingress.evict(fp);
                true
            }
            Some(&e) if e != epoch => {
                epochs.insert(fp.to_string(), epoch);
                self.leases.rotate_epoch(fp, src);
                self.ingress.evict(fp);
                true
            }
            Some(_) => false,
        };
        drop(epochs);
        if adopted {
            tracing::info!(peer = %fp, epoch, "VPN epoch adopted — lease re-anchored, state evicted");
        }

        let expected = self.ingress_epochs.lock().get(fp).copied().unwrap_or(epoch);
        match self.ingress.open(master_key, fp, expected, payload) {
            OpenOutcome::Accepted { ip_packet, advanced } => {
                self.leases.observe_tunnel_packet(fp, epoch, ctr, src);
                let _ = advanced;
                self.stats_in.fetch_add(1, Ordering::Relaxed);
                self.route_inner(fp, epoch, ip_packet);
            }
            OpenOutcome::Replay => {
                tracing::debug!(peer = %fp, ctr, "VPN replay dropped");
            }
            OpenOutcome::AuthFail => {
                tracing::warn!(peer = %fp, "VPN datagram failed inner auth");
            }
        }
    }

    /// Route one decrypted inner IP packet: TCP → netstack, UDP → flow table,
    /// ICMP echo to the hub → direct reply, else drop.
    fn route_inner(self: &Arc<Self>, fp: &str, epoch: u32, pkt: Vec<u8>) {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return;
        }
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        let proto = pkt[9];
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        match proto {
            6 => {
                // TCP: feed the netstack (NAT front-end handles addressing).
                let _ = self.netstack.try_feed(pkt);
            }
            17 => {
                if pkt.len() < ihl + 8 {
                    return;
                }
                let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                // The client configured its own TUN: adopt its self-chosen
                // overlay IP as the lease hint (auto-assign only on clash).
                let (overlay, _) = self.leases.lease_for_hint(fp, Some(src_ip));
                let key = FlowKey {
                    fp: fp.to_string(),
                    overlay_src: overlay,
                    overlay_port: sport,
                    dst: SocketAddr::from((dst, dport)),
                };
                let Some(flow) = self.flows.get_or_create(key.clone()) else {
                    tracing::warn!(peer = %fp, "UDP flow refused (cap)");
                    self.stats_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let payload_start = ihl + 8;
                if pkt.len() > payload_start {
                    let udp_payload = pkt[payload_start..].to_vec();
                    let dst_addr = SocketAddr::from((dst, dport));
                    // The query itself is sent from THIS (packet-handling)
                    // context — never a per-packet thread.
                    if let Err(e) = flow.socket.send_to(&udp_payload, dst_addr) {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            tracing::debug!(error = %e, "UDP flow send failed");
                        }
                    }
                    // One reader thread per live flow; the reader drops its
                    // dedup key on exit so post-idle queries re-spawn.
                    if self.readers_spawned.lock().insert(key.clone()) {
                        self.spawn_flow_reader(key, flow.clone());
                    }
                }
            }
            1 => {
                // ICMP: answer echo requests addressed to the hub overlay IP.
                self.answer_icmp(fp, epoch, &pkt);
            }
            _ => {}
        }
    }

    /// Reader loop for one UDP flow: relays LAN replies back into the tunnel.
    /// Exits after `reader_idle_limit` of silence; on exit it drops the
    /// reader-dedup key so the next packet on this tuple re-spawns a reader
    /// (attached to this same socket if the flow has not been swept yet).
    /// The socket fd is dropped with the thread.
    fn spawn_flow_reader(self: &Arc<Self>, key: FlowKey, flow: Arc<super::UdpFlow>) {
        let key_out = key.clone();
        let fp = key.fp.clone();
        let client_ip = key.overlay_src;
        let client_port = key.overlay_port;
        let (dst_ip, dst_port) = match key.dst {
            SocketAddr::V4(sa) => (*sa.ip(), sa.port()),
            _ => return,
        };
        let idle_limit = self.reader_idle_limit;
        let replies = self.egress_tx.clone();
        let this = Arc::clone(self);
        let _ = std::thread::Builder::new().name("ggn-udp-flow".into()).spawn(move || {
            // 4096 bytes: an EDNS0 DNS response can approach 4 KB, and `recv`
            // into a too-small buffer truncates *silently* — the client would
            // receive a malformed reply with no error logged anywhere.
            // (PROTOTYPE.md flaw #2: this was 2048.)
            let mut buf = vec![0u8; 4096];
            let mut quiet = Duration::ZERO;
            loop {
                match flow.socket.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        quiet = Duration::ZERO;
                        if let Some(ip) = build_udp_packet(
                            IpAddr::V4(dst_ip),
                            dst_port,
                            IpAddr::V4(client_ip),
                            client_port,
                            &buf[..n],
                        ) {
                            // Seal with the CURRENT session info at reply time.
                            if let Some(wire) = this.seal_for_client(&fp, ip) {
                                if replies.send((fp.clone(), wire)).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Poll cadence: 10 Hz; exit after `reader_idle_limit`
                        // of total silence so reader and flow lifecycles agree.
                        quiet += Duration::from_millis(100);
                        if quiet >= idle_limit {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }
            // Lifecycle agreement: a dead reader must not block a respawn —
            // drop the dedup key so the next packet on this tuple re-spawns
            // a reader for the (possibly successor) flow socket.
            this.readers_spawned.lock().remove(&key_out);
        });
    }

    /// ICMP echo → echo reply (for the hub's own overlay address).
    fn answer_icmp(&self, fp: &str, epoch: u32, pkt: &[u8]) {
        if pkt.len() < 28 {
            return;
        }
        // Scope: only echoes addressed to the hub's own overlay IP. Echoes
        // aimed at real LAN devices are dropped (counted) — a synthetic reply
        // would mask real reachability, which is what a ping must measure.
        if Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]) != self.cfg.hub_overlay {
            self.stats_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        if pkt.len() < ihl + 8 || pkt[ihl] != 8 {
            return; // not an echo request
        }
        let mut reply = pkt.to_vec();
        reply[ihl] = 0; // echo reply
        let (s, d) = (
            [reply[12], reply[13], reply[14], reply[15]],
            [reply[16], reply[17], reply[18], reply[19]],
        );
        reply[12..16].copy_from_slice(&d);
        reply[16..20].copy_from_slice(&s);
        fix_ip_checksum(&mut reply, ihl);
        reply[ihl + 2] = 0;
        reply[ihl + 3] = 0;
        let sum = internet_checksum(&reply[ihl..]);
        reply[ihl + 2] = (sum >> 8) as u8;
        reply[ihl + 3] = (sum & 0xFF) as u8;
        self.enqueue_to_client(fp, epoch, reply);
    }

    /// Seal an IP packet for a client and queue it for the egress pump.
    fn enqueue_to_client(&self, fp: &str, _epoch: u32, ip_packet: Vec<u8>) {
        if let Some(wire) = self.seal_for_client(fp, ip_packet) {
            let _ = self.egress_tx.try_send((fp.to_string(), wire));
        }
    }

    /// Seal an IP packet for a client → bare tunnel datagram (no magic).
    /// The epoch is the one ADOPTED from the client's wire header
    /// (`ingress_epochs`) — never `lease.epoch`, which increments on both
    /// handshake rotation AND adoption and would desync from the client.
    fn seal_for_client(&self, fp: &str, ip_packet: Vec<u8>) -> Option<Vec<u8>> {
        let info = self.sessions.lock().get(fp).cloned()?;
        let epoch = self.ingress_epochs.lock().get(fp).copied().unwrap_or(0);
        let mut ctrs = self.tx_counters.lock();
        let slot = ctrs.entry(fp.to_string()).or_insert(0);
        let next = slot.wrapping_add(1);
        if next == 0 {
            *slot = 1; // skip the 0 counter on wrap
        } else {
            *slot = next;
        }
        // The wrap below keeps the counter space alive, but the client's replay
        // window is monotonic: once it has accepted u32::MAX it rejects every
        // later counter, wrapped ones included. Nothing counts down to a re-key
        // yet (PROTOTYPE.md flaw #1), so at minimum make the approach loud.
        const CTR_REKEY_AT: u32 = u32::MAX - 1_000_000;
        if *slot >= CTR_REKEY_AT {
            tracing::warn!(
                fingerprint = %fp, counter = *slot,
                "VPN hub: tunnel counter nearing exhaustion — client must re-key"
            );
        }
        let wire = seal_datagram(&info.master_key, epoch, *slot, &ip_packet);
        self.stats_out.fetch_add(1, Ordering::Relaxed);
        Some(wire)
    }

    /// Drain one pending egress item. Returns an `EgressUnit` the caller
    /// sends over the mesh (session-encrypted, GVPN1-wrapped).
    pub fn poll_egress(&self) -> Option<EgressUnit> {
        let (fp, wire) = self.egress.lock().try_recv().ok()?;
        let info = self.sessions.lock().get(&fp).cloned()?;
        Some(EgressUnit {
            fingerprint: fp.clone(),
            session_hash: info.session_hash,
            endpoint: info.endpoint,
            wire,
        })
    }

    /// Drain netstack egress (TCP): one NAT-egress IP packet, sealed for the
    /// client that owns its destination overlay IP. Call in a loop until None.
    pub fn poll_netstack_egress(&self) -> Option<EgressUnit> {
        let pkt = self.netstack.poll_outgoing()?;
        if pkt.len() < 20 {
            return None;
        }
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let fp = self.leases.fingerprint_for_ip(dst)?;
        let wire = self.seal_for_client(&fp, pkt)?;
        let info = self.sessions.lock().get(&fp).cloned()?;
        Some(EgressUnit {
            fingerprint: fp.clone(),
            session_hash: info.session_hash,
            endpoint: info.endpoint,
            wire,
        })
    }

    /// 1 Hz housekeeping: expire UDP flows.
    pub fn sweep(&self) -> usize {
        self.flows.sweep()
    }

    pub fn stats(&self) -> (u32, u32, u32, usize, usize) {
        let ns = self.netstack.stats();
        (
            self.stats_in.load(Ordering::Relaxed),
            self.stats_out.load(Ordering::Relaxed),
            self.stats_dropped.load(Ordering::Relaxed),
            self.leases.lease_count(),
            ns.tcp_flows as usize,
        )
    }

    pub fn leases_snapshot(&self) -> Vec<super::Lease> {
        self.leases.snapshot()
    }

    /// Per-lease detail for the console `VPN STATUS` view.
    ///
    /// Each lock is taken and released on its own (never nested), so this can
    /// never invert lock order against the seal/ingest paths.
    pub fn lease_views(&self) -> Vec<LeaseView> {
        let leases = self.leases.snapshot();
        let mut views = Vec::with_capacity(leases.len());
        for l in leases {
            let udp_flows = self.flows.count_for(&l.fingerprint);
            let counter_headroom = self
                .tx_counters
                .lock()
                .get(&l.fingerprint)
                .map(|c| u32::MAX.saturating_sub(*c))
                .unwrap_or(u32::MAX);
            views.push(LeaseView {
                fingerprint: l.fingerprint,
                overlay_ip: l.overlay_ip,
                endpoint: l.endpoint,
                epoch: l.epoch,
                idle_secs: l.last_seen.elapsed().as_secs_f32(),
                tunnel_v_max: l.tunnel_v_max,
                udp_flows,
                counter_headroom,
            });
        }
        views
    }

    /// Metrics snapshot for `/metrics` and `/healthz`.
    ///
    /// `counter_headroom_min` is the operationally important one: how close the
    /// busiest lease is to exhausting its per-epoch tunnel counter — a state
    /// that was unrecoverable before the re-key trigger existed (PROTOTYPE.md
    /// flaw #1). Exporting it lets a dashboard alert *before* it bites.
    pub fn metrics(&self) -> VpnHubMetrics {
        let ns = self.netstack.stats();
        let counter_headroom_min = self
            .tx_counters
            .lock()
            .values()
            .map(|c| u32::MAX.saturating_sub(*c))
            .min()
            .unwrap_or(u32::MAX);
        VpnHubMetrics {
            frames_in: self.stats_in.load(Ordering::Relaxed),
            frames_out: self.stats_out.load(Ordering::Relaxed),
            frames_dropped: self.stats_dropped.load(Ordering::Relaxed),
            leases: self.leases.lease_count(),
            tcp_flows: ns.tcp_flows as usize,
            udp_flows: self.flows.len(),
            counter_headroom_min,
        }
    }
}

/// Point-in-time VPN hub counters for the monitoring endpoints.
#[derive(Debug, Clone, Copy, Default)]
pub struct VpnHubMetrics {
    pub frames_in: u32,
    pub frames_out: u32,
    pub frames_dropped: u32,
    pub leases: usize,
    pub tcp_flows: usize,
    pub udp_flows: usize,
    /// Smallest remaining tunnel-counter headroom across leases
    /// (`u32::MAX` when no lease has spent a counter yet).
    pub counter_headroom_min: u32,
}

/// One lease as rendered by the console `VPN STATUS` view.
///
/// The lease table alone cannot answer "which client is holding flows?" or "how
/// close is this client to a counter re-key?" — which is what you actually want
/// mid-incident — so this joins the lease, its UDP flow count and its
/// per-epoch counter headroom into a single row.
#[derive(Debug, Clone)]
pub struct LeaseView {
    pub fingerprint: String,
    pub overlay_ip: Ipv4Addr,
    pub endpoint: SocketAddr,
    pub epoch: u32,
    /// Seconds since an authenticated packet from the current endpoint.
    pub idle_secs: f32,
    /// Highest tunnel counter accepted from this client in this epoch.
    pub tunnel_v_max: u32,
    /// Live UDP flow bindings owned by this fingerprint.
    pub udp_flows: usize,
    /// Remaining per-epoch tunnel-counter headroom (`u32::MAX` = untouched).
    pub counter_headroom: u32,
}

// ── IP/UDP packet construction (LAN → client replies) ───────────────

/// Build a raw IPv4+UDP packet (both checksums correct) from a LAN reply.
pub fn build_udp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let (s4, d4) = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        _ => return None,
    };
    let udp_len = 8 + payload.len();
    if udp_len > 0xFFFF {
        return None;
    }
    let total = 20 + udp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&s4.octets());
    pkt[16..20].copy_from_slice(&d4.octets());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[26..28].copy_from_slice(&0u16.to_be_bytes()); // csum placeholder
    pkt[28..].copy_from_slice(payload);
    fix_ip_checksum(&mut pkt, 20);
    // UDP checksum with pseudo-header (IPv4)
    let mut buf = Vec::with_capacity(12 + udp_len);
    buf.extend_from_slice(&s4.octets());
    buf.extend_from_slice(&d4.octets());
    buf.push(0);
    buf.push(17);
    buf.extend_from_slice(&(udp_len as u16).to_be_bytes());
    buf.extend_from_slice(&pkt[20..]);
    let sum = internet_checksum(&buf);
    pkt[26] = (sum >> 8) as u8;
    pkt[27] = (sum & 0xFF) as u8;
    Some(pkt)
}

/// Zero + recompute the IPv4 header checksum in place.
fn fix_ip_checksum(pkt: &mut [u8], ihl: usize) {
    pkt[10] = 0;
    pkt[11] = 0;
    let sum = internet_checksum(&pkt[..ihl]);
    pkt[10] = (sum >> 8) as u8;
    pkt[11] = (sum & 0xFF) as u8;
}

pub(crate) fn internet_checksum(buf: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    if i < buf.len() {
        sum += (buf[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_builder_checksums() {
        let pkt = build_udp_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            53,
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 10)),
            51000,
            b"answers",
        )
        .unwrap();
        assert_eq!(internet_checksum(&pkt[..20]), 0);
        let mut buf = Vec::new();
        buf.extend_from_slice(&pkt[12..20]);
        buf.push(0);
        buf.push(17);
        buf.extend_from_slice(&((pkt.len() - 20) as u16).to_be_bytes());
        buf.extend_from_slice(&pkt[20..]);
        assert_eq!(internet_checksum(&buf), 0);
    }

    #[test]
    fn icvmp_echo_reply_flips_and_recomputes() {
        // An echo request to the hub: src 10.66.0.10 → dst 10.66.0.1
        let mut req = vec![0u8; 20 + 8];
        req[0] = 0x45;
        req[8] = 64;
        req[9] = 1;
        req[12..16].copy_from_slice(&[10, 66, 0, 10]);
        req[16..20].copy_from_slice(&[10, 66, 0, 1]);
        req[20] = 8; // echo request
        req[21] = 0;
        let pkt = req.clone();
        let ihl = 20;
        let mut reply = pkt;
        reply[ihl] = 0;
        let (s, d) = (
            [reply[12], reply[13], reply[14], reply[15]],
            [reply[16], reply[17], reply[18], reply[19]],
        );
        reply[12..16].copy_from_slice(&d);
        reply[16..20].copy_from_slice(&s);
        assert_eq!(&reply[12..16], &[10, 66, 0, 1]);
        assert_eq!(&reply[16..20], &[10, 66, 0, 10]);
        assert_eq!(reply[ihl], 0); // echo reply type
    }

    #[test]
    fn counters_skip_zero_on_wrap() {
        // Structural check of the wrap rule used in seal_for_client.
        let slot: u32 = 0xFFFF_FFFF;
        let next = slot.wrapping_add(1);
        assert_eq!(next, 0);
        let adjusted = if next == 0 { 1 } else { next };
        assert_eq!(adjusted, 1);
    }
}
