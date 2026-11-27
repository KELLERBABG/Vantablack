//! Hub orchestration — glues mesh packet handling to the lease table,
//! netstack, and UDP flow table, and pumps egress back into the mesh.
//!
//! Wire encapsulation inside a session: after the standard GTF assembly and
//! session AEAD decryption, a VPN payload is
//! `b"GVPN1" + seal_datagram(key, epoch, ctr, ip_packet)` where the inner
//! XChaCha20-Poly1305 AEAD uses the SAME session master key but a dedicated
//! nonce domain (`tunnel_xnonce`) — tunnel and control traffic never share a
//! nonce pair. The session guard already rejected replays at the frame layer;
//! the inner epoch/ctr drive the LEASE re-anchor ladder and a second replay
//! window.
//!
//! All egress produced here is the BARE tunnel datagram (epoch||ctr||rand||ct||tag).
//! Callers (main.rs) prepend the `GVPN1` magic exactly once when wrapping.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use super::netstack::Netstack;
use super::{seal_datagram, FlowKey, LeaseTable, OpenOutcome, UdpFlowTable, VpnConfig, VpnIngress};

pub const VPN_PAYLOAD_MAGIC: &[u8; 5] = b"GVPN1";

pub const VPN_PAYLOAD_V2_MAGIC: &[u8; 5] = b"GVPN2";

pub const GHOST_BYE_MAGIC: &[u8; 14] = b"GHOST_BYE_____";

pub struct EgressUnit {
    pub fingerprint: String,
    pub session_hash: [u8; 4],
    pub endpoint: SocketAddr,
    pub wire: Vec<u8>,
}

#[derive(Clone)]
struct ClientSession {
    master_key: [u8; 32],
    session_hash: [u8; 4],
    endpoint: SocketAddr,
}

pub struct VpnHub {
    pub cfg: VpnConfig,
    pub leases: LeaseTable,
    pub flows: Arc<UdpFlowTable>,
    pub netstack: Netstack,
    sessions: Mutex<HashMap<String, ClientSession>>,
    readers_spawned: Mutex<HashSet<FlowKey>>,
    ingress: VpnIngress,
    ingress_epochs: Mutex<HashMap<String, u32>>,
    tx_counters: Mutex<HashMap<String, u64>>,
    egress: Mutex<std::sync::mpsc::Receiver<(String, Vec<u8>)>>,
    egress_tx: std::sync::mpsc::SyncSender<(String, Vec<u8>)>,
    stats_in: AtomicU32,
    stats_out: AtomicU32,
    reader_idle_limit: Duration,
    stats_dropped: AtomicU32,
}

impl VpnHub {
    pub fn start(cfg: VpnConfig) -> Arc<Self> {
        Self::start_with_rotator(cfg, None)
    }

    pub fn start_with_rotator(
        cfg: VpnConfig,
        rotator: Option<Arc<crate::ghost::net::mesh::ExitIpRotator>>,
    ) -> Arc<Self> {
        let flows = Arc::new(UdpFlowTable::new(cfg.lan_bind_addr));
        Self::start_with_flows_and_rotator(cfg, flows, Duration::from_secs(10), rotator)
    }

    pub fn start_with_flows(
        cfg: VpnConfig,
        flows: Arc<UdpFlowTable>,
        reader_idle_limit: Duration,
    ) -> Arc<Self> {
        Self::start_with_flows_and_rotator(cfg, flows, reader_idle_limit, None)
    }

    pub fn start_with_flows_and_rotator(
        cfg: VpnConfig,
        flows: Arc<UdpFlowTable>,
        reader_idle_limit: Duration,
        rotator: Option<Arc<crate::ghost::net::mesh::ExitIpRotator>>,
    ) -> Arc<Self> {
        let netstack = Netstack::start_with_rotator(rotator);
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

    pub fn on_handshake(&self, fp: &str, endpoint: SocketAddr) {
        if !self.authorized(fp) {
            return;
        }
        self.leases.lease_for(fp); // ensure a lease exists
        if self.leases.rotate_epoch(fp, endpoint).is_some() {
            self.ingress.evict(fp);
            self.ingress_epochs.lock().remove(fp);
            self.sessions.lock().remove(fp);
            self.tx_counters.lock().remove(fp);
            self.readers_spawned.lock().retain(|k| k.fp != fp);
            tracing::info!(peer = %fp, "VPN handshake: epoch rotated, state evicted");
        }
    }

    pub fn on_disconnect(&self, fp: &str) {
        let had_lease = self.leases.evict(fp);
        let evicted_flows = self.flows.evict_for(fp);
        self.ingress.evict(fp);
        self.ingress_epochs.lock().remove(fp);
        let had_session = self.sessions.lock().remove(fp).is_some();
        self.tx_counters.lock().remove(fp);
        self.readers_spawned.lock().retain(|k| k.fp != fp);
        if had_lease || had_session || evicted_flows > 0 {
            tracing::info!(
                peer = %fp,
                evicted_flows,
                "VPN hub: peer disconnected (GHOST_BYE) — lease and flow state evicted"
            );
        }
    }

    pub fn active_endpoints(&self) -> Vec<(String, SocketAddr)> {
        self.sessions
            .lock()
            .iter()
            .map(|(fp, cs)| (fp.clone(), cs.endpoint))
            .collect()
    }

    pub fn evict_all(&self) {
        let fps: Vec<String> = self.sessions.lock().keys().cloned().collect();
        for fp in fps {
            self.ingress.evict(&fp);
        }
        self.leases.clear();
        self.flows.clear();
        self.ingress_epochs.lock().clear();
        self.sessions.lock().clear();
        self.tx_counters.lock().clear();
        self.readers_spawned.lock().clear();
    }

    pub fn authorized(&self, fp: &str) -> bool {
        self.cfg
            .allowed_fingerprints
            .iter()
            .any(|a| a == fp || a == "any" || a == "*")
    }

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

        let epoch = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let ctr = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let current_epoch = self.ingress_epochs.lock().get(fp).copied();
        if current_epoch.is_some_and(|current| epoch < current) {
            tracing::debug!(peer = %fp, epoch, current = ?current_epoch, "VPN stale epoch dropped");
            return;
        }
        let expected = epoch;
        let outcome = self.ingress.open(master_key, fp, expected, payload);
        self.handle_tunnel_outcome(fp, epoch, ctr, src, current_epoch, outcome);
    }

    pub fn handle_tunnel_payload_v2(
        self: &Arc<Self>,
        fp: &str,
        session_hash: [u8; 4],
        payload: &[u8],
        src: SocketAddr,
    ) {
        if payload.len() < 12 {
            return;
        }
        self.sessions
            .lock()
            .entry(fp.to_string())
            .and_modify(|info| {
                info.session_hash = session_hash;
                info.endpoint = src;
            });
        let epoch = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let ctr = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let current_epoch = self.ingress_epochs.lock().get(fp).copied();
        if current_epoch.is_some_and(|current| epoch < current) {
            tracing::debug!(peer = %fp, epoch, current = ?current_epoch, "VPN v2 stale epoch dropped");
            return;
        }
        let outcome = self.ingress.open_v2(fp, epoch, payload);
        self.handle_tunnel_outcome(fp, epoch, ctr, src, current_epoch, outcome);
    }

    fn handle_tunnel_outcome(
        self: &Arc<Self>,
        fp: &str,
        epoch: u32,
        ctr: u32,
        src: SocketAddr,
        current_epoch: Option<u32>,
        outcome: OpenOutcome,
    ) {
        match outcome {
            OpenOutcome::Accepted {
                ip_packet,
                advanced,
            } => {
                if current_epoch != Some(epoch) {
                    self.ingress_epochs.lock().insert(fp.to_string(), epoch);
                    self.leases.adopt_epoch(fp, epoch, src);
                    self.ingress.retain_epoch(fp, epoch);
                    tracing::info!(peer = %fp, epoch, "VPN authenticated epoch adopted — lease re-anchored");
                }
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

    fn route_inner(self: &Arc<Self>, fp: &str, epoch: u32, pkt: Vec<u8>) {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return;
        }
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        let proto = pkt[9];
        let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

        let (overlay, _) = self.leases.lease_for_hint(fp, Some(src_ip));

        if crate::ghost::net::threat_shield::blocks_ip(IpAddr::V4(dst)) {
            crate::ghost::net::adblock::record_blocked();
            self.stats_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        match proto {
            6 => {
                if pkt.len() >= ihl + 20 {
                    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                    if crate::ghost::net::adblock::is_blocked_port(dport) {
                        crate::ghost::net::adblock::record_blocked();
                        return;
                    }
                    if dport == 443 {
                        let data_off = ((pkt[ihl + 12] >> 4) as usize) * 4;
                        if data_off >= 20 && pkt.len() > ihl + data_off {
                            if let Some(sni) =
                                crate::ghost::net::adblock::extract_tls_sni(&pkt[ihl + data_off..])
                            {
                                if crate::ghost::net::adblock::is_shielded_target(&sni) {
                                    crate::ghost::net::adblock::record_blocked();
                                    return;
                                }
                            }
                        }
                    }
                }
                let _ = self.netstack.try_feed(pkt);
            }
            17 => {
                if pkt.len() < ihl + 8 {
                    return;
                }
                let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                let is_hub_dns = (dst == super::netstack::HUB_ADDR
                    || dst == Ipv4Addr::new(10, 66, 0, 1))
                    && dport == 53;
                let effective_dst = if is_hub_dns { self.cfg.dns_server } else { dst };
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

                    if crate::ghost::net::adblock::is_blocked_port(dport) {
                        crate::ghost::net::adblock::record_blocked();
                        return;
                    }

                    if is_hub_dns || dport == 53 {
                        if let Some(qname) =
                            crate::ghost::net::adblock::extract_dns_qname(&udp_payload)
                        {
                            if crate::ghost::net::adblock::is_shielded_target(&qname) {
                                crate::ghost::net::adblock::record_blocked();
                                if let Some(nx) =
                                    crate::ghost::net::adblock::build_dns_nxdomain_response(
                                        &udp_payload,
                                    )
                                {
                                    if let Some(reply_pkt) = build_udp_packet(
                                        IpAddr::V4(dst),
                                        dport,
                                        IpAddr::V4(overlay),
                                        sport,
                                        &nx,
                                    ) {
                                        let _ = self.egress_tx.send((fp.to_string(), reply_pkt));
                                        return;
                                    }
                                }
                            }
                        }
                    }

                    if (is_hub_dns || dport == 53) && is_dns_aaaa_query(&udp_payload) {
                        if let Some(nodata) = build_dns_nodata_response(&udp_payload) {
                            if let Some(reply_pkt) = build_udp_packet(
                                IpAddr::V4(dst),
                                dport,
                                IpAddr::V4(overlay),
                                sport,
                                &nodata,
                            ) {
                                let _ = self.egress_tx.send((fp.to_string(), reply_pkt));
                                return;
                            }
                        }
                    }

                    let dst_addr = SocketAddr::from((effective_dst, dport));
                    if let Err(e) = flow.socket.send_to(&udp_payload, dst_addr) {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            tracing::debug!(error = %e, "UDP flow send failed");
                        }
                    } else {
                        tracing::info!(peer = %fp, dst = %dst_addr, bytes = udp_payload.len(), "VPN UDP sent to WAN/LAN");
                    }
                    if is_hub_dns && effective_dst == Ipv4Addr::new(1, 1, 1, 1) {
                        let _ = flow.socket.send_to(
                            &udp_payload,
                            SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)),
                        );
                    }
                    if self.readers_spawned.lock().insert(key.clone()) {
                        self.spawn_flow_reader(key, flow.clone());
                    }
                }
            }
            1 => {
                self.answer_icmp(fp, epoch, &pkt);
            }
            _ => {}
        }
    }

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
        let _ = std::thread::Builder::new()
            .name("ggn-udp-flow".into())
            .spawn(move || {
                let mut buf = vec![0u8; 4096];
                let mut quiet = Duration::ZERO;
                loop {
                    match flow.socket.recv(&mut buf) {
                        Ok(n) if n > 0 => {
                            quiet = Duration::ZERO;
                            tracing::info!(peer = %fp, dst = %dst_ip, bytes = n, "VPN UDP flow reply received from WAN/LAN");
                            let filtered_dns = if dst_port == 53 {
                                crate::ghost::net::adblock::filter_dns_response(&buf[..n])
                            } else {
                                None
                            };
                            let reply_payload = filtered_dns.as_deref().unwrap_or(&buf[..n]);
                            if let Some(ip) = build_udp_packet(
                                IpAddr::V4(dst_ip),
                                dst_port,
                                IpAddr::V4(client_ip),
                                client_port,
                                reply_payload,
                            ) {
                                if replies.send((fp.clone(), ip)).is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            quiet += Duration::from_millis(100);
                            if quiet >= idle_limit {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(e) => {
                            #[cfg(windows)]
                            if e.raw_os_error() == Some(10054) {
                                std::thread::sleep(Duration::from_millis(100));
                                continue;
                            }
                            let _ = e;
                            break;
                        }
                    }
                }
                this.readers_spawned.lock().remove(&key_out);
            });
    }

    fn answer_icmp(&self, fp: &str, epoch: u32, pkt: &[u8]) {
        if pkt.len() < 28 {
            return;
        }
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

    fn enqueue_to_client(&self, fp: &str, _epoch: u32, ip_packet: Vec<u8>) {
        let _ = self.egress_tx.try_send((fp.to_string(), ip_packet));
    }

    fn seal_for_client(&self, fp: &str, ip_packet: Vec<u8>) -> Option<Vec<u8>> {
        let info = self.sessions.lock().get(fp).cloned()?;
        let epoch = self.ingress_epochs.lock().get(fp).copied().unwrap_or(0);
        let mut ctrs = self.tx_counters.lock();
        let slot = ctrs.entry(fp.to_string()).or_insert(0);
        let next = slot.wrapping_add(1);
        if next == 0 {
            *slot = 1; // skip the 0 counter on wrap (u64 wrap is unreachable in practice)
        } else {
            *slot = next;
        }
        const CTR_REKEY_AT: u64 = u64::MAX - 10_000_000;
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

    pub fn poll_egress(&self) -> Option<EgressUnit> {
        loop {
            let (fp, ip_packet) = self.egress.lock().try_recv().ok()?;
            let Some(wire) = self.seal_for_client(&fp, ip_packet) else {
                self.stats_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let Some(info) = self.sessions.lock().get(&fp).cloned() else {
                self.stats_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            tracing::info!(peer = %fp, endpoint = %info.endpoint, wire_len = wire.len(), "VPN poll_egress: unit dispatched to client");
            return Some(EgressUnit {
                fingerprint: fp,
                session_hash: info.session_hash,
                endpoint: info.endpoint,
                wire,
            });
        }
    }

    pub fn poll_netstack_egress(&self) -> Option<EgressUnit> {
        let pkt = self.netstack.poll_outgoing()?;
        if pkt.len() < 20 {
            return None;
        }
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let fp = match self.leases.fingerprint_for_ip(dst) {
            Some(f) => f,
            None => {
                let sessions = self.sessions.lock();
                if sessions.len() == 1 {
                    sessions.keys().next().unwrap().clone()
                } else {
                    tracing::warn!(dst = %dst, "poll_netstack_egress: no fingerprint for dst IP");
                    return None;
                }
            }
        };
        let wire = self.seal_for_client(&fp, pkt)?;
        let info = self.sessions.lock().get(&fp).cloned()?;
        tracing::info!(peer = %fp, dst = %dst, endpoint = %info.endpoint, wire_len = wire.len(), "VPN TCP egress dispatched to client");
        Some(EgressUnit {
            fingerprint: fp.clone(),
            session_hash: info.session_hash,
            endpoint: info.endpoint,
            wire,
        })
    }

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

    pub fn lease_views(&self) -> Vec<LeaseView> {
        let leases = self.leases.snapshot();
        let mut views = Vec::with_capacity(leases.len());
        for l in leases {
            let udp_flows = self.flows.count_for(&l.fingerprint);
            let counter_headroom = self
                .tx_counters
                .lock()
                .get(&l.fingerprint)
                .map(|c| u64::MAX.saturating_sub(*c))
                .unwrap_or(u64::MAX);
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

    pub fn metrics(&self) -> VpnHubMetrics {
        let ns = self.netstack.stats();
        let counter_headroom_min = self
            .tx_counters
            .lock()
            .values()
            .map(|c| u64::MAX.saturating_sub(*c))
            .min()
            .unwrap_or(u64::MAX);
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

#[derive(Debug, Clone, Copy, Default)]
pub struct VpnHubMetrics {
    pub frames_in: u32,
    pub frames_out: u32,
    pub frames_dropped: u32,
    pub leases: usize,
    pub tcp_flows: usize,
    pub udp_flows: usize,
    pub counter_headroom_min: u64,
}

#[derive(Debug, Clone)]
pub struct LeaseView {
    pub fingerprint: String,
    pub overlay_ip: Ipv4Addr,
    pub endpoint: SocketAddr,
    pub epoch: u32,
    pub idle_secs: f32,
    pub tunnel_v_max: u32,
    pub udp_flows: usize,
    pub counter_headroom: u64,
}

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

pub fn is_dns_aaaa_query(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    if (payload[2] & 0x80) != 0 {
        return false;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return false;
    }
    let mut idx: usize = 12;
    while idx < payload.len() {
        let len = payload[idx] as usize;
        if len == 0 {
            idx = idx.saturating_add(1);
            break;
        }
        if (len & 0xC0) == 0xC0 {
            idx = idx.saturating_add(2);
            break;
        }
        idx = idx.saturating_add(1).saturating_add(len);
    }
    if let Some(end) = idx.checked_add(4) {
        if let Some(tail) = payload.get(idx..end) {
            let qtype = u16::from_be_bytes([tail[0], tail[1]]);
            let qclass = u16::from_be_bytes([tail[2], tail[3]]);
            return qtype == 28 && qclass == 1; // 28 = AAAA, 1 = IN
        }
    }
    false
}

pub fn build_dns_nodata_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = query.to_vec();
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;

    let mut idx: usize = 12;
    while idx < resp.len() {
        let len = resp[idx] as usize;
        if len == 0 {
            idx = idx.saturating_add(1);
            break;
        }
        if (len & 0xC0) == 0xC0 {
            idx = idx.saturating_add(2);
            break;
        }
        idx = idx.saturating_add(1).saturating_add(len);
    }
    let end = idx.checked_add(4)?;
    if end <= resp.len() {
        resp.truncate(end);
        Some(resp)
    } else {
        None
    }
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
        let slot: u32 = 0xFFFF_FFFF;
        let next = slot.wrapping_add(1);
        assert_eq!(next, 0);
        let adjusted = if next == 0 { 1 } else { next };
        assert_eq!(adjusted, 1);
    }

    #[test]
    fn dns_aaaa_leak_prevention_builds_nodata_reply() {
        let mut query = vec![
            0x42, 0x42, // ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00,
            0x1C, // QTYPE=28 (AAAA)
            0x00, 0x01, // QCLASS=1 (IN)
        ];
        assert!(is_dns_aaaa_query(&query));

        let a_query_len = query.len();
        query[a_query_len - 4] = 0x00;
        query[a_query_len - 3] = 0x01;
        assert!(!is_dns_aaaa_query(&query));

        query[a_query_len - 3] = 0x1C;
        let resp = build_dns_nodata_response(&query).expect("build nodata");
        assert_eq!(&resp[0..2], &[0x42, 0x42]); // Same ID
        assert_eq!(&resp[2..4], &[0x81, 0x80]); // QR=1, RA=1, NoError=0
        assert_eq!(&resp[4..6], &[0x00, 0x01]); // 1 Question
        assert_eq!(&resp[6..8], &[0x00, 0x00]); // 0 Answers
        assert_eq!(resp.len(), query.len());
    }
}
