//! Hub-side userspace TCP stack (smoltcp) — the L4 endpoint for the VPN.
//!
//! Full-cone 5-tuple NAT in front of smoltcp, driven by ONE synchronous
//! thread (smoltcp's native model — no async interplay, no locks around
//! smoltcp state):
//!
//! ```text
//! phone packet:  src 10.66.0.x:p  dst 192.168.1.T:q     (raw IP via mesh)
//!      │ NAT ingress: tuple (C,p,T,q) → local port L
//!      ▼
//!                src 10.200.0.2:p  dst 10.200.0.1:L
//!      │ smoltcp socket (listening on L since SYN)
//!      ▼
//!      ESTABLISHED → proxy thread: std::net::TcpStream → 192.168.1.T:q
//!      │ bounded sync_channels both directions
//!      ▼
//! reply packet:  src 192.168.1.T:q  dst 10.66.0.x:p     (reverse-NAT)
//! ```
//!
//! UDP does NOT traverse this stack (UdpFlowTable handles it with real OS
//! sockets). ICMP echo to the hub is answered by the mesh layer.
//!
//! Invariants (PROTOTYPE.md rule 4 + audit round 3):
//! - Interface+SocketSet live in ONE thread.
//! - LAN readers pause at TX headroom < 25 %, resume > 75 %. Signalling is
//!   STATE-based (Condvar around the headroom value) — a reader that starts
//!   late always sees current truth, never a missed edge.
//! - Driver sleep capped at `iface.poll_delay()`.
//! - Teardown wakes everything (done-flag Condvar).
//! - Every channel bounded (sync_channel). SocketSet fixed-size:
//!   SYN overflow → SYN dropped → client TCP retries (L4 backpressure).
//! - No unbounded_channel anywhere in the data path.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use super::OVERLAY_MSS;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpCidr};

// ── Address plan ────────────────────────────────────────────────────

/// Overlay address clients use to reach the hub.
pub const HUB_ADDR: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
/// smoltcp interface address (link /30 with the NAT alias).
pub const NETSTACK_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
/// NAT source address for rewritten client packets.
pub const NAT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);

/// Exclusive end of the per-flow local port pool (20000..40000: 20k flows max).
const LOCAL_PORT_END: u16 = 40000;

// ── Capacity constants ──────────────────────────────────────────────

const MAX_TCP_SOCKETS: usize = 256;
const SOCK_BUF: usize = 64 * 1024;
const RX_QUEUE: usize = 512;
const TX_QUEUE: usize = 1024;
const FLOW_QUEUE: usize = 256;
/// Cap on per-flow stack→LAN pending bytes (full proxy channel). Matches the
/// channel bound × chunk size in spirit: bounded memory, never unbounded.
const S2C_PENDING_CAP: usize = 256;
const PAUSE_AT: f64 = 0.25;
const RESUME_AT: f64 = 0.75;
const POLL_CAP_MS: u64 = 10;
/// Idle TCP flows are torn down after this long without traffic.
const FLOW_IDLE: Duration = Duration::from_secs(300);

// ── Signalling primitives (state-based, no missed wakeups) ──────────

/// TX-headroom fraction (0.0..1.0) broadcast to the LAN reader.
pub struct Headroom {
    v: Mutex<f64>,
    cv: Condvar,
}

impl Headroom {
    pub fn new(h: f64) -> Self {
        Self {
            v: Mutex::new(h),
            cv: Condvar::new(),
        }
    }
    pub fn set(&self, h: f64) {
        *self.v.lock() = h;
        self.cv.notify_all();
    }
    pub fn get(&self) -> f64 {
        *self.v.lock()
    }
    /// Block until headroom >= `min` or shutdown.
    ///
    /// Uses a bounded wait so a teardown (`done.set()`) is observed within
    /// WAKE_LATENCY even though `Done` has its own Condvar: the loop
    /// re-checks BOTH conditions (state-based — no missed wakeups possible).
    pub fn wait_resume(&self, min: f64, done: &Done) {
        let mut g = self.v.lock();
        while *g < min && !done.is_set() {
            self.cv.wait_for(&mut g, WAKE_LATENCY);
        }
    }
}

/// Max latency for observing a done-flag while blocked on headroom.
const WAKE_LATENCY: std::time::Duration = std::time::Duration::from_millis(10);

/// Teardown flag.
pub struct Done {
    v: Mutex<bool>,
    cv: Condvar,
}

impl Done {
    pub fn new() -> Self {
        Self {
            v: Mutex::new(false),
            cv: Condvar::new(),
        }
    }
    pub fn set(&self) {
        *self.v.lock() = true;
        self.cv.notify_all();
    }
    pub fn is_set(&self) -> bool {
        *self.v.lock()
    }
    /// Block until set.
    pub fn wait(&self) {
        let mut g = self.v.lock();
        while !*g {
            self.cv.wait(&mut g);
        }
    }
}

// ── Handle ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum NetstackError {
    QueueFull,
    Stopped,
}

/// Statistics snapshot for the console.
#[derive(Debug, Clone, Default)]
pub struct NetstackStats {
    pub tcp_flows: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub refused_syns: u64,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
}

#[derive(Default)]
struct DriverStats {
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    refused_syns: AtomicU64,
    tcp_flows: AtomicU64,
    bytes_c2s: AtomicU64,
    bytes_s2c: AtomicU64,
}

/// Handle to a running netstack.
pub struct Netstack {
    rx_tx: mpsc::SyncSender<Vec<u8>>,
    out_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    stats: Arc<DriverStats>,
    stop: Arc<Done>,
    join: std::thread::JoinHandle<()>,
}

impl Netstack {
    /// Spawn the driver thread.
    pub fn start() -> Self {
        let (rx_tx, rx_q) = mpsc::sync_channel::<Vec<u8>>(RX_QUEUE);
        let (tx_q, out_rx) = mpsc::sync_channel::<Vec<u8>>(TX_QUEUE);
        let stats = Arc::new(DriverStats::default());
        let stop = Arc::new(Done::new());
        let join = std::thread::Builder::new()
            .name("ggn-netstack".into())
            .spawn({
                let stats = Arc::clone(&stats);
                let stop = Arc::clone(&stop);
                move || driver_loop(rx_q, tx_q, stats, stop)
            })
            .expect("spawn netstack thread");
        Self {
            rx_tx,
            out_rx: Mutex::new(out_rx),
            stats,
            stop,
            join,
        }
    }

    /// Feed one decrypted mesh packet (raw IPv4, dst = hub overlay IP).
    /// Non-blocking: a full RX queue drops the packet (IP is lossy by
    /// design; inner TCP retransmits). This is the tunnel-datagram rule.
    pub fn try_feed(&self, packet: Vec<u8>) -> Result<(), NetstackError> {
        if self.stop.is_set() {
            return Err(NetstackError::Stopped);
        }
        match self.rx_tx.try_send(packet) {
            Ok(()) => {
                self.stats.packets_in.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::TrySendError::Full(_)) => Err(NetstackError::QueueFull),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(NetstackError::Stopped),
        }
    }

    /// Pop one emitted packet (stack → mesh). Non-blocking.
    pub fn poll_outgoing(&self) -> Option<Vec<u8>> {
        self.out_rx.lock().try_recv().ok()
    }

    pub fn stats(&self) -> NetstackStats {
        NetstackStats {
            tcp_flows: self.stats.tcp_flows.load(Ordering::Relaxed),
            packets_in: self.stats.packets_in.load(Ordering::Relaxed),
            packets_out: self.stats.packets_out.load(Ordering::Relaxed),
            refused_syns: self.stats.refused_syns.load(Ordering::Relaxed),
            bytes_c2s: self.stats.bytes_c2s.load(Ordering::Relaxed),
            bytes_s2c: self.stats.bytes_s2c.load(Ordering::Relaxed),
        }
    }

    /// Stop the driver thread.
    pub fn shutdown(self) {
        self.stop.set();
        let _ = self.join.join();
    }
}

// ── Per-flow driver-side state ──────────────────────────────────────

type Tuple = (std::net::Ipv4Addr, u16, std::net::Ipv4Addr, u16);

struct Flow {
    handle: SocketHandle,
    tuple: Tuple,
    /// LAN → stack (proxy thread pushes; driver drains into smoltcp).
    lan_in_rx: mpsc::Receiver<Vec<u8>>,
    lan_in_tx: mpsc::SyncSender<Vec<u8>>,
    /// Stack → LAN (driver pushes; proxy drains to the OS socket).
    stack_out_tx: mpsc::SyncSender<Vec<u8>>,
    /// Receiver handed to the proxy thread at spawn (taken once).
    stack_out_rx: Option<mpsc::Receiver<Vec<u8>>>,
    headroom: Arc<Headroom>,
    done: Arc<Done>,
    spawned: bool,
    paused: bool,
    last_activity: Instant,
    bytes_c2s: u64,
    bytes_s2c: u64,
    /// Partially accepted LAN→stack chunk (ring was full mid-chunk).
    /// Queued — dropping ACKed bytes would corrupt the inner stream.
    c2s_pending: VecDeque<Vec<u8>>,
    /// Consumed-from-ring stack→LAN bytes when the proxy channel is full.
    /// recv_slice already consumed them; the only alternatives are queueing
    /// or stream corruption. Capped at S2C_PENDING_CAP.
    s2c_pending: VecDeque<Vec<u8>>,
}

// ── Driver loop ─────────────────────────────────────────────────────

fn driver_loop(
    rx_q: mpsc::Receiver<Vec<u8>>,
    tx_q: mpsc::SyncSender<Vec<u8>>,
    stats: Arc<DriverStats>,
    stop: Arc<Done>,
) {
    let reverse: Arc<Mutex<HashMap<u16, Tuple>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut device = VirtualDevice::new(Arc::clone(&reverse));
    device.attach_tx(tx_q.clone());
    let mut iface = smoltcp::iface::Interface::new(
        smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip),
        &mut device,
        smoltcp::time::Instant::from_millis(0),
    );
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::Ipv4(NETSTACK_ADDR), 30));
    });
    let mut sockets: SocketSet<'static> = SocketSet::new(Vec::new());

    let mut nat: HashMap<Tuple, u16> = HashMap::new();
    let mut flows: HashMap<u16, Flow> = HashMap::new();
    let mut next_port: u16 = 20000;
    let mut t_ms: i64 = 0;
    let mut rx_buf = vec![0u8; 65536];

    while !stop.is_set() {
        // ── 1. Ingest mesh packets ──
        while let Ok(pkt) = rx_q.try_recv() {
            let Some((rewritten, tuple, is_syn, local_port)) =
                nat_ingress(&pkt, &mut next_port, &mut nat)
            else {
                continue;
            };
            if !flows.contains_key(&local_port) {
                if !is_syn {
                    continue; // mid-flow packet for an unknown tuple
                }
                if sockets.iter().count() >= MAX_TCP_SOCKETS {
                    stats.refused_syns.fetch_add(1, Ordering::Relaxed);
                    continue; // SYN dropped → client TCP retries
                }
                let Some(h) = make_listen_socket(&mut sockets, local_port) else {
                    continue;
                };
                let (lan_in_tx, lan_in_rx) = mpsc::sync_channel::<Vec<u8>>(FLOW_QUEUE);
                let (stack_out_tx, stack_out_rx) = mpsc::sync_channel::<Vec<u8>>(FLOW_QUEUE);
                let headroom = Arc::new(Headroom::new(1.0));
                let done = Arc::new(Done::new());
                flows.insert(
                    local_port,
                    Flow {
                        handle: h,
                        tuple,
                        lan_in_rx,
                        lan_in_tx,
                        stack_out_tx,
                        stack_out_rx: Some(stack_out_rx),
                        headroom: Arc::clone(&headroom),
                        done: Arc::clone(&done),
                        spawned: false,
                        paused: false,
                        last_activity: Instant::now(),
                        bytes_c2s: 0,
                        bytes_s2c: 0,
                        c2s_pending: VecDeque::new(),
                        s2c_pending: VecDeque::new(),
                    },
                );
                reverse.lock().insert(local_port, tuple);
                stats.tcp_flows.store(flows.len() as u64, Ordering::Relaxed);
            }
            device.rx_push(rewritten);
        }

        // ── 2. Pump every flow ──
        let ports: Vec<u16> = flows.keys().copied().collect();
        for local_port in ports {
            let Some(f) = flows.get_mut(&local_port) else {
                continue;
            };
            let sock = sockets.get_mut::<tcp::Socket>(f.handle);

            if !f.spawned && sock.state() == tcp::State::Established {
                f.spawned = true;
                if let Some(rx) = f.stack_out_rx.take() {
                    spawn_proxy(
                        f.tuple,
                        f.lan_in_tx.clone(),
                        rx,
                        Arc::clone(&f.headroom),
                        Arc::clone(&f.done),
                    );
                }
            }

            // LAN → stack. Pending remainder first: send_slice may accept
            // less than a full chunk; the rest is queued (never dropped —
            // these bytes are already ACKed to the phone). When can_send()
            // goes false we stop; smoltcp's window to the phone closes and
            // the LAN reader pauses on the headroom signal (rule 4).
            while sock.can_send() {
                let data = if let Some(front) = f.c2s_pending.pop_front() {
                    front
                } else {
                    match f.lan_in_rx.try_recv() {
                        Ok(data) => data,
                        Err(_) => break,
                    }
                };
                let n = sock.send_slice(&data).unwrap_or(0);
                f.bytes_c2s += n as u64;
                f.last_activity = Instant::now();
                if n < data.len() {
                    f.c2s_pending.push_back(data[n..].to_vec());
                    break; // ring full — window throttles the phone
                }
            }

            // headroom state → LAN reader (hysteresis tracked here)
            let cap = sock.send_capacity() as f64;
            if cap > 0.0 {
                let headroom = 1.0 - (sock.send_queue() as f64 / cap);
                if !f.paused && headroom < PAUSE_AT {
                    f.paused = true;
                } else if f.paused && headroom > RESUME_AT {
                    f.paused = false;
                }
                f.headroom.set(headroom);
            }

            // stack → LAN. Pending first, then freshly received bytes. On a
            // full proxy channel the consumed bytes stay in s2c_pending
            // (recv_slice already consumed them — dropping would corrupt the
            // stream); the queue is capped, and overflowing it marks the flow
            // dead rather than growing memory unboundedly.
            loop {
                if f.s2c_pending.len() >= S2C_PENDING_CAP {
                    break; // proxy backed up: stop draining the ring — its
                           // advertised window to the phone shrinks (rule 4)
                }
                let chunk = if let Some(front) = f.s2c_pending.pop_front() {
                    front
                } else {
                    match sock.recv_slice(&mut rx_buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            f.bytes_s2c += n as u64;
                            f.last_activity = Instant::now();
                            rx_buf[..n].to_vec()
                        }
                    }
                };
                match f.stack_out_tx.try_send(chunk) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(c)) => {
                        f.s2c_pending.push_back(c);
                        break;
                    }
                    Err(mpsc::TrySendError::Disconnected(c)) => {
                        drop(c);
                        f.done.set();
                        break;
                    }
                }
            }

            let st = sock.state();
            if st == tcp::State::Closed || st == tcp::State::TimeWait {
                f.done.set();
            }
        }

        // ── 3. GC: dead flows + idle teardown (BEFORE poll — a socket
        // flagged dead must never serve another poll) ──
        let dead: Vec<u16> = flows
            .iter()
            .filter(|(_, f)| f.done.is_set() && f.last_activity.elapsed() > Duration::from_secs(2))
            .map(|(local_port, _)| *local_port)
            .collect();
        for local_port in dead {
            if let Some(f) = flows.remove(&local_port) {
                sockets.remove(f.handle);
                nat.remove(&f.tuple);
                reverse.lock().remove(&local_port);
                stats.bytes_c2s.fetch_add(f.bytes_c2s, Ordering::Relaxed);
                stats.bytes_s2c.fetch_add(f.bytes_s2c, Ordering::Relaxed);
            }
        }
        flows.retain(|local_port, f| {
            if f.last_activity.elapsed() > FLOW_IDLE {
                // Aggregate the flow's byte counters into the global stats
                // (same as the dead path) — VPNSTATS must not undercount.
                stats.bytes_c2s.fetch_add(f.bytes_c2s, Ordering::Relaxed);
                stats.bytes_s2c.fetch_add(f.bytes_s2c, Ordering::Relaxed);
                // Close the socket and free the tuple/port — same invariants
                // as the dead path above (empty slot panics get_mut).
                sockets.remove(f.handle);
                nat.remove(&f.tuple);
                reverse.lock().remove(local_port);
                f.done.set();
                return false;
            }
            true
        });
        stats.tcp_flows.store(flows.len() as u64, Ordering::Relaxed);

        // ── 4. smoltcp poll (device RX → sockets → device TX → mesh queue) ──
        let ts = smoltcp::time::Instant::from_millis(t_ms);
        iface.poll(ts, &mut device, &mut sockets);
        t_ms += POLL_CAP_MS as i64;
        stats
            .packets_out
            .store(device.tx_count.load(Ordering::Relaxed), Ordering::Relaxed);

        // ── 5. Sleep capped by poll_delay ──
        let ts2 = smoltcp::time::Instant::from_millis(t_ms);
        let delay = iface.poll_delay(ts2, &sockets);
        let sleep_for = match delay {
            Some(d) if d.total_millis() == 0 => Duration::ZERO,
            Some(d) => Duration::from_millis(d.total_millis() as u64)
                .min(Duration::from_millis(POLL_CAP_MS)),
            None => Duration::from_millis(POLL_CAP_MS),
        };
        if sleep_for.is_zero() {
            std::thread::yield_now();
        } else {
            // wake early on stop
            let deadline = Instant::now() + sleep_for;
            while Instant::now() < deadline {
                if stop.is_set() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    stats.bytes_c2s.fetch_add(0, Ordering::Relaxed);
}

fn make_listen_socket(sockets: &mut SocketSet<'static>, local_port: u16) -> Option<SocketHandle> {
    let rx_buf = vec![0u8; SOCK_BUF];
    let tx_buf = vec![0u8; SOCK_BUF];
    let mut sock = tcp::Socket::new(
        tcp::SocketBuffer::new(rx_buf),
        tcp::SocketBuffer::new(tx_buf),
    );
    sock.listen(SocketAddrV4::new(NETSTACK_ADDR, local_port))
        .ok()?;
    Some(sockets.add(sock))
}

/// Spawn the LAN proxy thread for an established flow.
fn spawn_proxy(
    tuple: Tuple,
    lan_in_tx: mpsc::SyncSender<Vec<u8>>,
    stack_out_rx: mpsc::Receiver<Vec<u8>>,
    headroom: Arc<Headroom>,
    done: Arc<Done>,
) {
    let (_c, _cp, t, tp) = tuple;
    let target = SocketAddr::from((std::net::Ipv4Addr::from(t.octets()), tp));
    let ok = std::thread::Builder::new()
        .name("ggn-flow".into())
        .spawn(move || {
            let lan = match TcpStream::connect(target) {
                Ok(s) => s,
                Err(_) => {
                    done.set();
                    return;
                }
            };
            lan.set_nodelay(true).ok();
            let rd = match lan.try_clone() {
                Ok(r) => r,
                Err(_) => {
                    done.set();
                    return;
                }
            };
            let done_r = Arc::clone(&done);
            // LAN reader → stack
            let reader = std::thread::spawn(move || {
                use std::io::Read;
                let mut rd = rd;
                let mut buf = vec![0u8; 8192];
                loop {
                    if done_r.is_set() {
                        break;
                    }
                    if headroom.get() < PAUSE_AT {
                        headroom.wait_resume(RESUME_AT, &done_r);
                        if done_r.is_set() {
                            break;
                        }
                    }
                    match rd.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            // bounded blocking send: backpressure into the
                            // LAN socket; give up after ~500 ms or shutdown
                            let mut sent = false;
                            for _ in 0..50 {
                                match lan_in_tx.try_send(buf[..n].to_vec()) {
                                    Ok(()) => {
                                        sent = true;
                                        break;
                                    }
                                    Err(mpsc::TrySendError::Full(_)) => {
                                        if done_r.is_set() {
                                            break;
                                        }
                                        std::thread::sleep(Duration::from_millis(10));
                                    }
                                    Err(mpsc::TrySendError::Disconnected(_)) => break,
                                }
                            }
                            if !sent {
                                break;
                            }
                        }
                    }
                }
                done_r.set();
            });
            // stack → LAN writer
            {
                use std::io::Write;
                let mut wr = &lan;
                for chunk in stack_out_rx.iter() {
                    if wr.write_all(&chunk).is_err() {
                        break;
                    }
                }
                let _ = wr.flush();
            }
            done.set();
            let _ = reader.join();
        });
    drop(ok);
}

// ── MSS clamp (PMTUD blackhole guard) ───────────────────────────────

/// Clamp the TCP MSS option of a SYN/SYN-ACK to OVERLAY_MSS. Only shrinks:
/// a smaller advertised MSS is kept. Walks the TCP option list in place
/// (kind 2), fixes the checksum, and leaves non-TCP or option-less packets
/// untouched. Returns true when the packet was modified.
fn clamp_mss(pkt: &mut [u8], ihl: usize) -> bool {
    if pkt.len() < ihl + 20 || pkt[9] != 6 {
        return false;
    }
    let doff = ((pkt[ihl + 12] >> 4) as usize) * 4;
    if doff < 20 || pkt.len() < ihl + doff {
        return false;
    }
    let mut off = ihl + 20;
    let end = ihl + doff;
    while off + 1 < end {
        let kind = pkt[off];
        if kind == 0 {
            break; // EOL
        }
        if kind == 1 {
            off += 1;
            continue; // NOP
        }
        let len = pkt[off + 1] as usize;
        if len < 2 || off + len > end {
            break; // malformed — leave the packet alone
        }
        if kind == 2 && len == 4 {
            let mss = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
            if mss > OVERLAY_MSS {
                pkt[off + 2..off + 4].copy_from_slice(&OVERLAY_MSS.to_be_bytes());
                fix_checksums(pkt, ihl, true);
                return true;
            }
            return false;
        }
        off += len;
    }
    false
}

/// Rewrite client→hub: src C:p → NAT_ADDR:p, dst T:q → NETSTACK_ADDR:L.
/// Allocates L for new tuples. Returns (packet, tuple, is_syn, L).
fn nat_ingress(
    pkt: &[u8],
    next_port: &mut u16,
    nat: &mut HashMap<Tuple, u16>,
) -> Option<(Vec<u8>, Tuple, bool, u16)> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if pkt.len() < ihl + 4 {
        return None;
    }
    let proto = pkt[9];
    if proto != 6 && proto != 17 {
        return None; // ICMP handled elsewhere
    }
    let oct = |o: usize| std::net::Ipv4Addr::new(pkt[o], pkt[o + 1], pkt[o + 2], pkt[o + 3]);
    let src = oct(12);
    let dst = oct(16);
    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    let tuple: Tuple = (src, sport, dst, dport);
    let is_syn = {
        let off = ihl + 13;
        pkt.len() > off && (pkt[off] & 0x12) == 0x02 && (pkt[off] & 0x10) == 0
    };
    // New tuple → allocate a unique local port for this flow. Non-SYN packets
    // for unknown tuples are dropped here (mid-flow race after GC).
    let local_port = match nat.get(&tuple) {
        Some(&l) => l,
        None if is_syn => {
            if *next_port >= LOCAL_PORT_END {
                return None; // port space exhausted — SYN dropped, client retries
            }
            let l = *next_port;
            *next_port += 1;
            nat.insert(tuple, l);
            l
        }
        None => return None,
    };
    let mut out = pkt.to_vec();
    out[12..16].copy_from_slice(&NAT_ADDR.octets()); // src addr → NAT alias
    out[16..20].copy_from_slice(&NETSTACK_ADDR.octets()); // dst addr → stack
    out[ihl + 2] = (local_port >> 8) as u8; // dst port → local port
    out[ihl + 3] = (local_port & 0xFF) as u8;
    fix_checksums(&mut out, ihl, proto == 6);
    if is_syn {
        // PMTUD guard: the client's advertised MSS must fit the tunnel MTU
        // (audit round 2, rule 3). Applied AFTER the port/addr rewrite.
        clamp_mss(&mut out, ihl);
    }
    Some((out, tuple, is_syn, local_port))
}

/// Rewrite hub→client: src NETSTACK_ADDR:L stays, src port L stays,
/// dst NAT_ADDR:p → client C:p, src addr NETSTACK_ADDR → T:q... precisely:
/// src T:q (the real target), dst C:p (the real client).
pub fn nat_egress(pkt: &[u8], reverse: &HashMap<u16, Tuple>) -> Option<Vec<u8>> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if pkt.len() < ihl + 4 {
        return None;
    }
    let proto = pkt[9];
    if proto != 6 && proto != 17 {
        return None;
    }
    // Demux key = reply SOURCE port (the unique local port of the flow).
    let local_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let (c, cp, t, tp) = *reverse.get(&local_port)?;
    let mut out = pkt.to_vec();
    out[12..16].copy_from_slice(&t.octets()); // src addr = real target
    out[16..20].copy_from_slice(&c.octets()); // dst addr = real client
    out[ihl] = (tp >> 8) as u8; // src port = target port
    out[ihl + 1] = (tp & 0xFF) as u8;
    out[ihl + 2] = (cp >> 8) as u8; // dst port = client port
    out[ihl + 3] = (cp & 0xFF) as u8;
    fix_checksums(&mut out, ihl, proto == 6);
    // Defense-in-depth for the hub→client direction: smoltcp already derives
    // its own MSS from the 1280 device MTU, but a LAN server's SYN-ACK that
    // somehow carries a larger option must not survive egress.
    clamp_mss(&mut out, ihl);
    Some(out)
}

fn fix_checksums(pkt: &mut [u8], ihl: usize, is_tcp: bool) {
    pkt[10] = 0;
    pkt[11] = 0;
    let sum = internet_checksum(&pkt[..ihl]);
    pkt[10] = (sum >> 8) as u8;
    pkt[11] = (sum & 0xFF) as u8;
    let csum_off = ihl + if is_tcp { 16 } else { 6 };
    if pkt.len() < csum_off + 2 {
        return;
    }
    pkt[csum_off] = 0;
    pkt[csum_off + 1] = 0;
    let l4_len = pkt.len() - ihl;
    let mut buf = Vec::with_capacity(12 + l4_len);
    buf.extend_from_slice(&pkt[12..20]);
    buf.push(0);
    buf.push(pkt[9]);
    buf.extend_from_slice(&(l4_len as u16).to_be_bytes());
    buf.extend_from_slice(&pkt[ihl..]);
    let sum = internet_checksum(&buf);
    pkt[csum_off] = (sum >> 8) as u8;
    pkt[csum_off + 1] = (sum & 0xFF) as u8;
}

fn internet_checksum(buf: &[u8]) -> u16 {
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

// ── Virtual device ──────────────────────────────────────────────────

/// smoltcp Device: RX from an internal queue, TX reverse-NATed into the
/// mesh-bound bounded queue.
pub struct VirtualDevice {
    rx: Arc<Mutex<std::collections::VecDeque<Vec<u8>>>>,
    reverse: Arc<Mutex<HashMap<u16, Tuple>>>,
    tx: Option<mpsc::SyncSender<Vec<u8>>>,
    pub tx_count: Arc<AtomicU64>,
}

impl VirtualDevice {
    pub fn new(reverse: Arc<Mutex<HashMap<u16, Tuple>>>) -> Self {
        Self {
            rx: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            reverse,
            tx: None,
            tx_count: Arc::new(AtomicU64::new(0)),
        }
    }
    pub fn rx_push(&mut self, pkt: Vec<u8>) {
        self.rx.lock().push_back(pkt);
    }
    pub fn attach_tx(&mut self, tx: mpsc::SyncSender<Vec<u8>>) {
        self.tx = Some(tx);
    }
    fn emit(&self, pkt: Vec<u8>) {
        self.tx_count.fetch_add(1, Ordering::Relaxed);
        if let Some(tx) = &self.tx {
            // bounded queue: full → drop (IP lossy; inner TCP retransmits)
            let _ = tx.try_send(pkt);
        }
    }
}

impl std::fmt::Debug for VirtualDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VirtualDevice")
    }
}

impl smoltcp::phy::Device for VirtualDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(
        &mut self,
        _ts: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.lock().pop_front()?;
        Some((
            RxTok { buf: pkt },
            TxTok {
                reverse: Arc::clone(&self.reverse),
                emit: Emit::Owned(self),
            },
        ))
    }

    fn transmit(&mut self, _ts: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok {
            reverse: Arc::clone(&self.reverse),
            emit: Emit::Borrowed(self),
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut c = smoltcp::phy::DeviceCapabilities::default();
        c.medium = smoltcp::phy::Medium::Ip;
        c.max_transmission_unit = 1280;
        c
    }
}

enum Emit<'a> {
    Owned(&'a VirtualDevice),
    Borrowed(&'a mut VirtualDevice),
}

impl Emit<'_> {
    fn send(&self, pkt: Vec<u8>) {
        match self {
            Emit::Owned(d) => d.emit(pkt),
            Emit::Borrowed(d) => d.emit(pkt),
        }
    }
}

pub struct RxTok {
    buf: Vec<u8>,
}

impl smoltcp::phy::RxToken for RxTok {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf)
    }
}

pub struct TxTok<'a> {
    reverse: Arc<Mutex<HashMap<u16, Tuple>>>,
    emit: Emit<'a>,
}

impl smoltcp::phy::TxToken for TxTok<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let out = f(&mut buf);
        if let Some(pkt) = nat_egress(&buf, &self.reverse.lock()) {
            self.emit.send(pkt);
        }
        out
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet(src: ([u8; 4], u16), dst: ([u8; 4], u16), flags: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 20];
        pkt[0] = 0x45;
        let total_len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes()); // smoltcp validates this on ingest
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src.0);
        pkt[16..20].copy_from_slice(&dst.0);
        pkt[20..22].copy_from_slice(&src.1.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst.1.to_be_bytes());
        pkt[32] = 0x50; // data offset 5 (20-byte TCP header)
        pkt[33] = flags;
        pkt[34..36].copy_from_slice(&0xFFFFu16.to_be_bytes()); // advertised window — 0 blocks all sends
        fix_checksums(&mut pkt, 20, true);
        pkt
    }

    #[test]
    fn nat_ingress_egress_roundtrip() {
        let mut next_port = 20000u16;
        let mut nat = HashMap::new();
        let syn = tcp_packet(([10, 66, 0, 10], 51234), ([192, 168, 1, 50], 445), 0x02);
        // first pass: unknown SYN tuple → nat_ingress allocates port 20000
        // (first from the pool) and registers it.
        let tuple = (
            std::net::Ipv4Addr::new(10, 66, 0, 10),
            51234,
            std::net::Ipv4Addr::new(192, 168, 1, 50),
            445,
        );
        let (rewritten, t2, is_syn, local_port) =
            nat_ingress(&syn, &mut next_port, &mut nat).unwrap();
        assert_eq!(t2, tuple);
        assert!(is_syn);
        assert_eq!(local_port, 20000);
        assert_eq!(nat.get(&tuple), Some(&20000));
        // rewritten packet must carry a valid checksum
        assert_eq!(internet_checksum(&rewritten[..20]), 0);
        assert_eq!(rewritten[12..16], NAT_ADDR.octets());
        assert_eq!(rewritten[16..20], NETSTACK_ADDR.octets());
        // egress of a reply restores the original 5-tuple
        let mut reply = rewritten.clone();
        reply[12..16].copy_from_slice(&NETSTACK_ADDR.octets());
        reply[16..20].copy_from_slice(&NAT_ADDR.octets());
        reply[20..22].copy_from_slice(&20000u16.to_be_bytes());
        reply[22..24].copy_from_slice(&51234u16.to_be_bytes());
        fix_checksums(&mut reply, 20, true);
        let mut reverse = HashMap::new();
        reverse.insert(20000u16, tuple);
        let out = nat_egress(&reply, &reverse).unwrap();
        assert_eq!(&out[12..16], &[192, 168, 1, 50]); // src = target
        assert_eq!(&out[16..20], &[10, 66, 0, 10]); // dst = client
        assert_eq!(u16::from_be_bytes([out[20], out[21]]), 445);
        assert_eq!(u16::from_be_bytes([out[22], out[23]]), 51234);
        assert_eq!(internet_checksum(&out[..20]), 0);
    }

    #[test]
    fn nat_ingress_requires_registered_tuple() {
        // non-SYN packets for unknown tuples are dropped (mid-flow race)
        let mut next_port = 20000u16;
        let mut nat = HashMap::new();
        let data = tcp_packet(([10, 66, 0, 10], 999), ([192, 168, 1, 1], 80), 0x18);
        assert!(nat_ingress(&data, &mut next_port, &mut nat).is_none());
        // unknown SYN tuples are auto-allocated (the fix for dead flow creation)
        let syn = tcp_packet(([10, 66, 0, 10], 999), ([192, 168, 1, 1], 80), 0x02);
        let (_, _, is_syn, local_port) = nat_ingress(&syn, &mut next_port, &mut nat).unwrap();
        assert!(is_syn);
        assert_eq!(local_port, 20000);
        assert_eq!(next_port, 20001);
    }

    #[test]
    fn headroom_and_done_signalling() {
        let done = Arc::new(Done::new());
        let h = Arc::new(Headroom::new(0.1));
        let d2 = Arc::clone(&done);
        let h2 = Arc::clone(&h);
        let t = std::thread::spawn(move || {
            h2.wait_resume(0.75, &d2);
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(!t.is_finished());
        h.set(0.9); // state change wakes the waiter
        std::thread::sleep(Duration::from_millis(50));
        assert!(t.is_finished());
        t.join().unwrap();

        let t2 = {
            let d = Arc::clone(&done);
            std::thread::spawn(move || d.wait())
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(!t2.is_finished());
        done.set();
        t2.join().unwrap();
    }

    #[test]
    fn proxy_pump_end_to_end_localhost() {
        // Real end-to-end through the proxy plumbing (no smoltcp):
        // a local listener acts as the LAN target; bytes flow both ways and
        // backpressure wakes correctly.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            use std::io::{Read, Write};
            let mut buf = [0u8; 16];
            let n = s.read(&mut buf).unwrap();
            s.write_all(&buf[..n]).unwrap();
        });
        let (lan_in_tx, lan_in_rx) = mpsc::sync_channel::<Vec<u8>>(FLOW_QUEUE);
        let (stack_out_tx, stack_out_rx) = mpsc::sync_channel::<Vec<u8>>(FLOW_QUEUE);
        let headroom = Arc::new(Headroom::new(1.0));
        let done = Arc::new(Done::new());
        let t = (
            std::net::Ipv4Addr::new(127, 0, 0, 1),
            0,
            std::net::Ipv4Addr::new(127, 0, 0, 1),
            addr.port(),
        );
        spawn_proxy(
            t,
            lan_in_tx,
            stack_out_rx,
            Arc::clone(&headroom),
            Arc::clone(&done),
        );
        std::thread::sleep(Duration::from_millis(100));
        stack_out_tx.send(b"ping".to_vec()).unwrap();
        let echo = lan_in_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(echo, b"ping");
        drop(stack_out_tx); // writer side ends → done
        done.wait_timeout(Duration::from_secs(2));
        assert!(done.is_set());
    }

    #[test]
    fn netstack_syn_establish_echo() {
        // The critical path the unit tests miss: a client SYN must create a
        // flow, complete a handshake with smoltcp, spawn the LAN proxy, and
        // deliver stack→client data through the real driver thread.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                }
            }
        });

        let ns = Netstack::start();
        let target_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
        let client_ip = std::net::Ipv4Addr::new(10, 66, 0, 10);
        let cport = 40000u16;
        let cisn: u32 = 1000;

        // 1. SYN → driver must create the flow and smoltcp must SYN-ACK.
        let mut syn = tcp_packet(
            (client_ip.octets(), cport),
            (target_ip.octets(), addr.port()),
            0x02,
        );
        syn[24..28].copy_from_slice(&cisn.to_be_bytes()); // client ISN — helper leaves seq/ack zeroed
        fix_checksums(&mut syn, 20, true);
        ns.try_feed(syn).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut synack_seq: Option<u32> = None;
        while Instant::now() < deadline {
            if let Some(pkt) = ns.poll_outgoing() {
                let flags = pkt[33];
                if flags & 0x12 == 0x12 {
                    synack_seq = Some(u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]));
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let sisn = synack_seq.expect("no SYN-ACK from netstack — flow creation broken");

        // 2. ACK the handshake (client seq cisn+1, ack sisn+1).
        let mut ack = tcp_packet(
            (client_ip.octets(), cport),
            (target_ip.octets(), addr.port()),
            0x10,
        );
        ack[24..28].copy_from_slice(&(cisn + 1).to_be_bytes());
        ack[28..32].copy_from_slice(&sisn.wrapping_add(1).to_be_bytes());
        fix_checksums(&mut ack, 20, true);
        ns.try_feed(ack).unwrap();
        std::thread::sleep(Duration::from_millis(50));

        // 3. Push data: "hello" must reach the echo server and come back.
        let mut data = tcp_packet(
            (client_ip.octets(), cport),
            (target_ip.octets(), addr.port()),
            0x18,
        );
        data[24..28].copy_from_slice(&(cisn + 1).to_be_bytes()); // SYN consumed cisn; bare ACK consumed none
        data[28..32].copy_from_slice(&sisn.wrapping_add(1).to_be_bytes());
        data.extend_from_slice(b"hello");
        let dl = data.len() as u16;
        data[2..4].copy_from_slice(&dl.to_be_bytes()); // total_len must cover the payload
        fix_checksums(&mut data, 20, true);
        ns.try_feed(data).unwrap();

        // 4. Drain egress for the echoed payload (seq advances by 1+5).
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut got: Option<Vec<u8>> = None;
        while Instant::now() < deadline {
            while let Some(pkt) = ns.poll_outgoing() {
                let ihl = ((pkt[0] & 0x0F) as usize) * 4;
                if pkt.len() > ihl + 20 && pkt[ihl + 13] & 0x08 != 0 {
                    // PSH-ACK from the stack side — extract payload after the
                    // data offset.
                    let off = ((pkt[ihl + 12] >> 4) as usize) * 4;
                    let payload = &pkt[ihl + off..];
                    if payload == b"hello" {
                        got = Some(payload.to_vec());
                        break;
                    }
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            got.as_deref(),
            Some(b"hello".as_slice()),
            "echo never returned — NAT egress / proxy path broken"
        );
        let st = ns.stats();
        assert!(st.tcp_flows >= 1);
        ns.shutdown();
    }

    // ── MSS clamp ──

    /// Build a TCP packet with an MSS option (data offset 6, 24-byte header).
    fn syn_with_mss(src: ([u8; 4], u16), dst: ([u8; 4], u16), mss: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 24];
        pkt[0] = 0x45;
        let total_len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src.0);
        pkt[16..20].copy_from_slice(&dst.0);
        pkt[20..22].copy_from_slice(&src.1.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst.1.to_be_bytes());
        pkt[32] = 0x60; // data offset 6 → 4 bytes of options
        pkt[33] = 0x02; // SYN
        pkt[34..36].copy_from_slice(&0xFFFFu16.to_be_bytes());
        // MSS option: kind 2, len 4, value
        pkt[40] = 2;
        pkt[41] = 4;
        pkt[42..44].copy_from_slice(&mss.to_be_bytes());
        fix_checksums(&mut pkt, 20, true);
        pkt
    }

    fn read_mss(pkt: &[u8]) -> u16 {
        u16::from_be_bytes([pkt[42], pkt[43]])
    }

    #[test]
    fn clamp_mss_shrinks_oversized_and_keeps_smaller() {
        // 1460 → 1240, checksum stays valid
        let mut pkt = syn_with_mss(([10, 66, 0, 10], 500), ([192, 168, 1, 1], 80), 1460);
        assert!(clamp_mss(&mut pkt, 20));
        assert_eq!(read_mss(&pkt), OVERLAY_MSS);
        assert_eq!(internet_checksum(&pkt[..20]), 0, "IP checksum");
        // TCP checksum via pseudo-header
        let mut buf = Vec::new();
        buf.extend_from_slice(&pkt[12..20]);
        buf.extend_from_slice(&[0, 6]);
        buf.extend_from_slice(&((pkt.len() - 20) as u16).to_be_bytes()); // L4 segment len
        buf.extend_from_slice(&pkt[20..]);
        assert_eq!(internet_checksum(&buf), 0, "TCP checksum");

        // a smaller advertised MSS is kept (clamp only shrinks)
        let mut pkt = syn_with_mss(([10, 66, 0, 10], 500), ([192, 168, 1, 1], 80), 1000);
        assert!(!clamp_mss(&mut pkt, 20));
        assert_eq!(read_mss(&pkt), 1000);
    }

    #[test]
    fn clamp_mss_ignores_non_tcp_and_optionless() {
        // UDP packet: untouched
        let mut pkt = tcp_packet(([10, 66, 0, 10], 500), ([192, 168, 1, 1], 53), 0);
        pkt[9] = 17;
        assert!(!clamp_mss(&mut pkt, 20));
        // TCP without options (doff 5): untouched
        let mut pkt = tcp_packet(([10, 66, 0, 10], 500), ([192, 168, 1, 1], 80), 0x02);
        assert!(!clamp_mss(&mut pkt, 20));
        // malformed option length: left alone, no panic
        let mut pkt = syn_with_mss(([10, 66, 0, 10], 500), ([192, 168, 1, 1], 80), 1460);
        pkt[41] = 1; // bogus len < 2
        assert!(!clamp_mss(&mut pkt, 20));
    }

    #[test]
    fn nat_ingress_clamps_client_syn_mss() {
        let mut next_port = 20000u16;
        let mut nat = HashMap::new();
        let syn = syn_with_mss(([10, 66, 0, 10], 51000), ([192, 168, 1, 50], 445), 1460);
        let (rewritten, _, is_syn, _) = nat_ingress(&syn, &mut next_port, &mut nat).unwrap();
        assert!(is_syn);
        assert_eq!(
            read_mss(&rewritten),
            OVERLAY_MSS,
            "client SYN must be clamped before smoltcp sees it"
        );
        assert_eq!(internet_checksum(&rewritten[..20]), 0);
    }

    impl Done {
        fn wait_timeout(&self, d: Duration) {
            let deadline = Instant::now() + d;
            let mut g = self.v.lock();
            while !*g && Instant::now() < deadline {
                self.cv.wait_for(&mut g, Duration::from_millis(10));
            }
        }
    }
}
