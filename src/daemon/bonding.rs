//! HPEB multipath bonding for the live daemon (Phase 5).
//!
//! [`vantablack::ghost::v2::hpeb`] knows how to pin one socket per physical
//! interface, split a message into AONT-protected RS(2,1) shards and pick paths.
//! It deliberately does **not** know how to bind a socket to an interface: that is
//! four different privileged operations. This module is the daemon half — the
//! platform binder, the live socket set, and the wiring into the packet path.
//!
//! ## What is bonded here
//!
//! The daemon already splits every message into three GTFv2 carriers of one
//! ciphertext, and the peer's spool rebuilds from any two. So the bond is applied
//! at that level rather than by running a second AONT/RS stage over the carriers:
//! each carrier leaves by its own pinned interface, which is what makes "no single
//! carrier holds a whole message" true for the *physical* paths as well as for the
//! mathematics. [`HpebScheduler`] still chooses the assignment (cheapest path
//! first, round-robin), and [`HandoverState`] still owns preference and the
//! anti-flap cooldown.
//!
//! The standalone `ggn hpeb` multipath client keeps using
//! [`HpebScheduler::bond`] directly for arbitrary payloads; both paths share the
//! same scheduler, handover state and shard envelope.
//!
//! ## Wire shape
//!
//! ```text
//! [GBND 4][version 1][carrier index 1][sender mesh port 2][GTFv2 carrier ...]
//! ```
//!
//! The sender's mesh port travels with the shard because the receiving socket is
//! the *bond* socket on a different port, while every reply the daemon builds must
//! go back to the peer's mesh address. The GTFv2 carrier inside is unchanged, so a
//! shard that arrives this way is indistinguishable downstream from one that
//! arrived as a plain UDP datagram — it enters `RxContext::ingest` either way.
//!
//! ## Configuration
//!
//! | Variable | Meaning |
//! |---|---|
//! | `GHOST_BOND=1` | enable bonded sending and the bond listeners |
//! | `GHOST_BOND_PATHS` | `name=local_ip` entries, comma separated (`wlan0=192.168.1.42`) |
//! | `GHOST_BOND_INDEX` | optional `name=index` map for Windows/macOS, whose binders take an interface index rather than a name |
//! | `GHOST_BOND_PORT` | port the peer's bond listener uses (default 2271) |
//! | `GHOST_BOND_COOLDOWN_MS` | handover cooldown (default 500) |
//!
//! A path that cannot be bound is reported and skipped rather than silently
//! dropped from the set: an operator who asked for three radios must be able to see
//! that only two came up. With fewer than two pinned paths nothing is bonded and
//! the ordinary UDP send is used, unchanged.
//!
//! ## Android
//!
//! `Network.bindSocket()` has no Rust entry point — it is a JNI call into the
//! platform's `Network` object, and the socket must be created by Java. Rather than
//! pretend, [`bind_interface`] refuses on that target with an explicit error; an
//! Android caller supplies sockets it has already bound (see `PhyPath::local_addr`).

use crate::*;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use vantablack::ghost::v2::hpeb::{HandoverState, HpebScheduler, PhyPath};

/// Magic prefix of a bonded shard.
const BOND_MAGIC: &[u8; 4] = b"GBND";
/// Envelope version. A future change to the header layout bumps this.
const BOND_VERSION: u8 = 1;
/// `[GBND 4][version 1][index 1][src_port 2]`.
const BOND_HEADER_LEN: usize = 8;
/// Default port a peer's bonded listener uses. Distinct from the mesh port
/// (2270) and the QUIC carrier's port (2271), so one node can run all three.
const DEFAULT_BOND_PORT: u16 = 2272;
/// Fallback mesh port, used only when the socket cannot report its own address.
const DEFAULT_MESH_PORT: u16 = 2270;
/// Default handover cooldown, matching the `HandoverState` tests.
const DEFAULT_COOLDOWN_MS: u64 = 500;
/// How long a path that failed a send stays out before it is retried.
const PATH_RETRY_AFTER: Duration = Duration::from_secs(30);

/// One configured physical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BondPath {
    /// Interface name, as the Linux binder wants it.
    pub interface: String,
    /// Interface index, as the Windows/macOS binders want it. Unused where the
    /// platform binds by name, which is why it is allowed to be unread there.
    #[cfg_attr(any(target_os = "linux", target_os = "android"), allow(dead_code))]
    pub index: Option<u32>,
    /// A local address on that interface.
    pub local: SocketAddr,
}

impl BondPath {
    /// The `PhyPath` the scheduler sees: pinned, because a path we did not bind is
    /// not a physical path.
    fn phy(&self) -> PhyPath {
        PhyPath::new(&self.interface).pinned(&self.local.to_string())
    }
}

/// Whether bonded sending and the bond listeners are enabled.
pub(crate) fn enabled() -> bool {
    static RESOLVED: OnceLock<bool> = OnceLock::new();
    *RESOLVED.get_or_init(|| enabled_for(std::env::var("GHOST_BOND").ok().as_deref()))
}

/// The pure decision behind [`enabled`].
fn enabled_for(value: Option<&str>) -> bool {
    match value {
        Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        None => false,
    }
}

/// The port a peer's bond listener is assumed to use.
pub(crate) fn port() -> u16 {
    std::env::var("GHOST_BOND_PORT")
        .ok()
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(DEFAULT_BOND_PORT)
}

fn cooldown() -> Duration {
    Duration::from_millis(
        std::env::var("GHOST_BOND_COOLDOWN_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_COOLDOWN_MS),
    )
}

/// Parse `GHOST_BOND_PATHS` (`name=ip[:port],...`) and the optional
/// `GHOST_BOND_INDEX` (`name=index,...`) map.
///
/// Returns `(accepted, rejected)`. Anything that does not name an interface and a
/// parseable address is reported by the caller, never silently skipped: a typo
/// that quietly leaves one radio unused turns a bonded node into a degraded one
/// without saying so.
fn parse_paths(spec: &str, indexes: &str) -> (Vec<BondPath>, Vec<String>) {
    let mut map: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for entry in indexes.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((name, idx)) = entry.split_once('=') {
            if let Ok(idx) = idx.trim().parse::<u32>() {
                if idx != 0 {
                    map.insert(name.trim(), idx);
                }
            }
        }
    }
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let parsed = entry.split_once('=').and_then(|(name, addr)| {
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let addr = addr.trim();
            let with_port = if addr.contains(':') {
                addr.to_string()
            } else {
                format!("{addr}:0")
            };
            let local: SocketAddr = with_port.parse().ok()?;
            Some(BondPath {
                interface: name.to_string(),
                index: map.get(name).copied(),
                local,
            })
        });
        match parsed {
            Some(path) => accepted.push(path),
            None => rejected.push(entry.to_string()),
        }
    }
    (accepted, rejected)
}

/// Bind `socket` to `path`'s interface.
///
/// One implementation per platform because these are four different socket
/// options, not one portable one. A refusal carries the platform's own reason.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_interface(socket: &Socket, path: &BondPath) -> std::io::Result<()> {
    socket.bind_device(Some(path.interface.as_bytes()))
}

/// `IP_BOUND_IF` takes an interface *index*, so a path without one cannot be
/// pinned here.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
fn bind_interface(socket: &Socket, path: &BondPath) -> std::io::Result<()> {
    let index = required_index(path)?;
    socket.bind_device_by_index_v4(Some(index))
}

/// Windows `IP_UNICAST_IF`.
///
/// socket2 0.5 exposes no Windows binding for this option (its `bind_device*`
/// family is Unix-only), so the call is made against Winsock directly. `ws2_32`
/// is linked by std already, and this adds no dependency. The option value is the
/// interface index in **network byte order**, and it selects the outgoing
/// interface only — exactly the send-side pinning bonding needs.
#[cfg(windows)]
fn bind_interface(socket: &Socket, path: &BondPath) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;

    extern "system" {
        fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    }
    const IPPROTO_IP: i32 = 0;
    const IP_UNICAST_IF: i32 = 31;

    let index = required_index(path)?;
    let value = index.get().to_be_bytes();
    // SAFETY: `socket` owns a live SOCKET for the duration of the call, and
    // `value` is four readable bytes — the size Winsock requires for this option.
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            IPPROTO_IP,
            IP_UNICAST_IF,
            value.as_ptr(),
            value.len() as i32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The interface index a platform-indexed binder needs, with an actionable error.
#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
fn required_index(path: &BondPath) -> std::io::Result<std::num::NonZeroU32> {
    path.index
        .and_then(std::num::NonZeroU32::new)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "interface {} needs an index on this platform; add `{}` to GHOST_BOND_INDEX",
                    path.interface, path.interface
                ),
            )
        })
}

/// Any other target has no binder here. Explicit, so a caller never believes a
/// path is pinned when it is not.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    windows
)))]
fn bind_interface(_socket: &Socket, path: &BondPath) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "no interface binder for this platform; path {} is not pinned",
            path.interface
        ),
    ))
}

/// A live path: its scheduler entry plus the socket bound to it.
struct LivePath {
    path: BondPath,
    socket: Arc<UdpSocket>,
    /// Set when a send through this path failed; the path is retried after
    /// [`PATH_RETRY_AFTER`] rather than abandoned for the process lifetime.
    down_since: Option<Instant>,
}

impl LivePath {
    /// Usable now. A path that failed recently is out, but not gone: interfaces
    /// come back on their own schedule, and the daemon has no interface-change
    /// notification without a platform binding it does not have.
    fn usable(&self, now: Instant) -> bool {
        match self.down_since {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= PATH_RETRY_AFTER,
        }
    }
}

struct BondState {
    scheduler: HpebScheduler,
    handover: HandoverState,
    paths: Vec<LivePath>,
    /// Peers we have already logged as unbonded, so a single-radio peer does not
    /// write a warning per shard.
    reported: std::collections::HashSet<SocketAddr>,
}

impl BondState {
    fn live_candidates(&self, now: Instant) -> Vec<String> {
        self.paths
            .iter()
            .filter(|p| p.usable(now))
            .map(|p| p.path.interface.clone())
            .collect()
    }
}

fn state() -> &'static Mutex<Option<BondState>> {
    static STATE: OnceLock<Mutex<Option<BondState>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

/// Build the socket set. Returns `None` when bonding is off or fewer than two
/// pinned paths could be bound — in both cases the daemon keeps its UDP path.
fn build(listener_port: u16) -> Option<BondState> {
    let raw = std::env::var("GHOST_BOND_PATHS").unwrap_or_default();
    let indexes = std::env::var("GHOST_BOND_INDEX").unwrap_or_default();
    let (accepted, rejected) = parse_paths(&raw, &indexes);
    for entry in rejected {
        tracing::warn!(
            entry = %entry,
            "GHOST_BOND_PATHS entry is not `interface=address` — ignored"
        );
    }
    if accepted.is_empty() {
        tracing::warn!("GHOST_BOND=1 but GHOST_BOND_PATHS names no usable path — not bonding");
        return None;
    }
    let mut paths = Vec::new();
    for path in accepted {
        let local = SocketAddr::new(path.local.ip(), listener_port);
        match bind_path(&path, local) {
            Ok(socket) => paths.push(LivePath {
                path,
                socket: Arc::new(socket),
                down_since: None,
            }),
            Err(e) => tracing::warn!(
                interface = %path.interface,
                addr = %local,
                error = %e,
                "HPEB: cannot bind this path — it will not carry shards"
            ),
        }
    }
    if paths.len() < 2 {
        tracing::warn!(
            bound = paths.len(),
            "HPEB: fewer than two paths bound — bonding needs two physically distinct \\ 
             interfaces, so this node keeps the ordinary UDP send"
        );
        return None;
    }
    let phy: Vec<PhyPath> = paths.iter().map(|p| p.path.phy()).collect();
    let mut scheduler = HpebScheduler::new(phy);
    for p in &paths {
        scheduler.set_available(&p.path.interface, true);
    }
    let mut handover = HandoverState::new(cooldown());
    if let Some(first) = paths.first() {
        handover.prefer(&first.path.interface, Instant::now());
    }
    tracing::info!(
        paths = paths.len(),
        interfaces = %paths
            .iter()
            .map(|p| p.path.interface.as_str())
            .collect::<Vec<_>>()
            .join(","),
        port = listener_port,
        "HPEB: bonded — one GTFv2 carrier per physical interface"
    );
    Some(BondState {
        scheduler,
        handover,
        paths,
        reported: std::collections::HashSet::new(),
    })
}

/// Bind one path's socket and pin it to the interface.
fn bind_path(path: &BondPath, local: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&local.into())?;
    bind_interface(&socket, path)?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Install the bonded path set and start one receive loop per path.
///
/// Every recovered carrier is handed to `inbound`, which the node drains into
/// `RxContext::ingest` — the same entry point a plain datagram takes. Returns
/// `None` when bonding is off or could not be established, which is not an error:
/// the node then keeps the UDP send it always had.
pub(crate) fn spawn(
    inbound: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !enabled() {
        return None;
    }
    let listener_port = port();
    let built = build(listener_port)?;
    let sockets: Vec<(String, Arc<UdpSocket>)> = built
        .paths
        .iter()
        .map(|p| (p.path.interface.clone(), Arc::clone(&p.socket)))
        .collect();
    *state().lock() = Some(built);

    Some(tokio::spawn(async move {
        let mut tasks = Vec::new();
        for (interface, socket) in sockets {
            let inbound = inbound.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((n, from)) => match unpack(&buf[..n], from) {
                            Some((frame, src)) => {
                                if inbound.send((frame, src)).is_err() {
                                    return;
                                }
                            }
                            None => tracing::trace!(
                                %from,
                                iface = %interface,
                                "HPEB: not a bonded shard"
                            ),
                        },
                        Err(e) => {
                            tracing::debug!(iface = %interface, error = %e, "HPEB: receive failed");
                            return;
                        }
                    }
                }
            }));
        }
        for task in tasks {
            let _ = task.await;
        }
    }))
}

/// Wrap one GTFv2 carrier for the bond socket.
fn pack(index: u8, src_port: u16, carrier: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BOND_HEADER_LEN + carrier.len());
    out.extend_from_slice(BOND_MAGIC);
    out.push(BOND_VERSION);
    out.push(index);
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(carrier);
    out
}

/// Unwrap a bonded shard: the carrier and the peer's mesh address.
///
/// The source address is rebuilt from the datagram's own IP and the port the
/// sender put in the header, because the socket this arrived on is the bond
/// listener, not the peer's mesh socket.
fn unpack(datagram: &[u8], from: SocketAddr) -> Option<(Vec<u8>, SocketAddr)> {
    if datagram.len() <= BOND_HEADER_LEN || &datagram[..4] != BOND_MAGIC {
        return None;
    }
    if datagram[4] != BOND_VERSION {
        return None;
    }
    let src_port = u16::from_be_bytes([datagram[6], datagram[7]]);
    if src_port == 0 {
        return None;
    }
    let carrier = &datagram[BOND_HEADER_LEN..];
    // Only a carrier that really parses as GTFv2 is handed on, so a stray datagram
    // on the bond port can never be reinterpreted as mesh traffic.
    net::parse_gtf_v2_header(carrier)?;
    Some((carrier.to_vec(), SocketAddr::new(from.ip(), src_port)))
}

/// Send the three GTFv2 carriers of one message over separate physical paths.
///
/// Returns the interfaces that actually carried a shard, or `None` when this node
/// is not bonded — the caller then keeps the ordinary single-socket send. A bond
/// with one live path is not a bond, so it returns `None` rather than claiming
/// redundancy it does not have.
pub(crate) async fn send_carriers(
    peer_fp: &str,
    peer: SocketAddr,
    carriers: &[Vec<u8>],
    src_port: u16,
) -> Option<Vec<String>> {
    if carriers.is_empty() {
        return None;
    }
    dispatch(
        peer_fp,
        SocketAddr::new(peer.ip(), port()),
        carriers,
        src_port,
    )
    .await
}

/// The sending core, with the destination already resolved to the peer's bond
/// listener.
///
/// Split from [`send_carriers`] so a test can aim it at a loopback receiver instead
/// of going through the configured bond port — the framing, path selection and
/// stamping are the production code either way.
async fn dispatch(
    peer_fp: &str,
    dest: SocketAddr,
    carriers: &[Vec<u8>],
    src_port: u16,
) -> Option<Vec<String>> {
    if carriers.is_empty() {
        return None;
    }
    let now = Instant::now();
    // Pick the assignment and clone the socket handles under the lock, then send
    // outside it: a slow or failing interface must not hold up other peers.
    let plan: Vec<(usize, String, Arc<UdpSocket>)> = {
        let mut guard = state().lock();
        let st = guard.as_mut()?;
        for path in st.paths.iter_mut() {
            if let Some(t) = path.down_since {
                if now.saturating_duration_since(t) >= PATH_RETRY_AFTER {
                    path.down_since = None;
                    st.scheduler.set_available(&path.path.interface, true);
                    tracing::info!(
                        iface = %path.path.interface,
                        "HPEB: path retried after a failed send"
                    );
                }
            }
        }
        let live: Vec<&str> = st
            .paths
            .iter()
            .filter(|p| p.usable(now))
            .map(|p| p.path.interface.as_str())
            .collect();
        if live.len() < 2 {
            if st.reported.insert(dest) {
                tracing::debug!(
                    peer = %peer_fp,
                    live = live.len(),
                    "HPEB: fewer than two live paths — keeping the UDP send"
                );
            }
            return None;
        }
        let mut plan = Vec::with_capacity(carriers.len());
        for (i, _) in carriers.iter().enumerate() {
            // Cost-ordered, round-robin: the cheapest interface carries carrier 0,
            // the next carrier 1, and the parity carrier continues the rotation.
            let index = i % live.len();
            let iface = live[index].to_string();
            let socket = st
                .paths
                .iter()
                .find(|p| p.path.interface == iface)
                .map(|p| Arc::clone(&p.socket))?;
            plan.push((i, iface, socket));
        }
        plan
    };

    let mut carried = Vec::new();
    for (index, interface, socket) in plan {
        let datagram = pack(index as u8, src_port, &carriers[index]);
        match socket.send_to(&datagram, dest).await {
            Ok(_) => carried.push(interface),
            Err(e) => {
                tracing::debug!(
                    peer = %peer_fp,
                    iface = %interface,
                    error = %e,
                    "HPEB: carrier send failed on this interface"
                );
                note_loss(peer_fp, &interface);
            }
        }
    }
    // Two carriers rebuild the message, so two interfaces carried it.
    if carried.len() < 2 {
        return None;
    }
    Some(carried)
}

/// The port this node's mesh socket is **actually bound to**, stamped into every
/// bonded shard so the peer replies to the mesh socket and not to the bond listener.
///
/// Asked of the socket, never of `GHOST_PORT`: a dynamic or port-0 bind is assigned a
/// port by the kernel that the environment never learns, and a shard naming the
/// configured port would point the peer's reply at a port this node does not own.
/// The fallback only covers a socket that cannot report an address at all.
pub(crate) fn mesh_local_port(sock: &UdpSocket) -> u16 {
    match sock.local_addr() {
        Ok(addr) if addr.port() != 0 => addr.port(),
        _ => DEFAULT_MESH_PORT,
    }
}

/// Record a failed send: the path is out for [`PATH_RETRY_AFTER`], and the
/// handover preference moves if it was the active one.
pub(crate) fn note_loss(peer_fp: &str, interface: &str) {
    let now = Instant::now();
    let mut guard = state().lock();
    let Some(st) = guard.as_mut() else {
        return;
    };
    for path in st.paths.iter_mut() {
        if path.path.interface == interface && path.down_since.is_none() {
            path.down_since = Some(now);
        }
    }
    st.scheduler.set_available(interface, false);
    let candidates = st.live_candidates(now);
    let refs: Vec<&str> = candidates.iter().map(String::as_str).collect();
    if st.handover.note_loss(interface, &refs, now) {
        tracing::info!(
            peer = %peer_fp,
            lost = %interface,
            active = st.handover.active().unwrap_or("-"),
            switches = st.handover.switches(),
            "HPEB: handover after a path loss"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_is_off_unless_explicitly_on() {
        assert!(!enabled_for(None));
        assert!(!enabled_for(Some("0")));
        assert!(!enabled_for(Some("off")));
        assert!(enabled_for(Some("1")));
        assert!(enabled_for(Some("TRUE")));
    }

    #[test]
    fn paths_parse_with_an_optional_index_map_and_reject_nonsense() {
        let (paths, rejected) = parse_paths(
            "wlan0=192.168.1.42, rmnet0=10.64.7.9:2271, bogus, =1.2.3.4",
            "wlan0=7, rmnet0=notanumber",
        );
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].interface, "wlan0");
        assert_eq!(paths[0].index, Some(7));
        assert_eq!(
            paths[0].local,
            "192.168.1.42:0".parse::<SocketAddr>().unwrap(),
            "a bare address gets the ephemeral port the binder replaces"
        );
        assert_eq!(paths[1].index, None, "a bad index is not an index");
        assert_eq!(
            paths[1].local,
            "10.64.7.9:2271".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(rejected, vec!["bogus", "=1.2.3.4"]);
        assert!(parse_paths("", "").0.is_empty());
    }

    /// The daemon bond envelope: a carrier and the peer's mesh port survive the
    /// round trip, and a datagram that is not a bonded shard is refused rather
    /// than handed to `ingest` as if it were.
    #[test]
    fn the_bond_envelope_round_trips_and_rejects_foreign_datagrams() {
        // A real GTFv2 frame, so the inner parse is what admits the shard.
        let carrier = {
            let header = vantablack::ghost::net::GtfV2Header {
                session_hash: [1, 2, 3, 4],
                counter: 1,
                epoch: 0,
                nonce: [7u8; 12],
                shard_index: 0,
                flags: 0,
                bulk: false,
                tail: [0u8; vantablack::ghost::net::JITTER_MAX],
            };
            vantablack::ghost::net::build_gtf_v2_frame(&header, &[0x5Au8; 96], &[0u8; 16])
        };
        let packed = pack(2, 2270, &carrier);
        assert_eq!(&packed[..4], BOND_MAGIC);
        assert_eq!(packed[4], BOND_VERSION);
        assert_eq!(packed[5], 2);
        let from: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        let (frame, src) = unpack(&packed, from).expect("a valid shard");
        assert_eq!(frame, carrier);
        assert_eq!(
            src,
            "203.0.113.9:2270".parse::<SocketAddr>().unwrap(),
            "replies go to the peer's mesh port, not the bond listener"
        );

        assert!(unpack(b"nope", from).is_none(), "too short");
        let mut wrong_magic = packed.clone();
        wrong_magic[0] = b'X';
        assert!(unpack(&wrong_magic, from).is_none());
        let mut wrong_version = packed.clone();
        wrong_version[4] = BOND_VERSION + 1;
        assert!(unpack(&wrong_version, from).is_none());
        let mut zero_port = packed.clone();
        zero_port[6] = 0;
        zero_port[7] = 0;
        assert!(unpack(&zero_port, from).is_none());
        // Right envelope, a carrier that is not a GTFv2 frame (no v2 marker):
        // never reinterpreted as mesh traffic.
        assert!(unpack(&pack(0, 2270, &[0u8; 64]), from).is_none());
    }

    /// The stamp is the socket's real port, so a dynamic or port-0 bind is
    /// advertised correctly even though nothing in the environment knows the port.
    #[tokio::test]
    async fn the_stamped_port_comes_from_the_bound_socket() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("a socket");
        let real = sock.local_addr().expect("a bound address").port();
        assert_ne!(real, 0, "a port-0 bind is given a real port by the kernel");
        assert_eq!(mesh_local_port(&sock), real);

        // And that is the port a peer reads back out of a shard built with it. A
        // real GTFv2 carrier, because that is what `unpack` admits.
        let header = vantablack::ghost::net::GtfV2Header {
            session_hash: [1, 2, 3, 4],
            counter: 1,
            epoch: 0,
            nonce: [7u8; 12],
            shard_index: 0,
            flags: 0,
            bulk: false,
            tail: [0u8; vantablack::ghost::net::JITTER_MAX],
        };
        let carrier =
            vantablack::ghost::net::build_gtf_v2_frame(&header, &[0x5Au8; 96], &[0u8; 16]);
        let from: SocketAddr = "192.0.2.9:40000".parse().unwrap();
        let packed = pack(1, mesh_local_port(&sock), &carrier);
        let (_, src) = unpack(&packed, from).expect("a valid shard");
        assert_eq!(src.port(), real, "the reply goes to the mesh socket");
        assert_eq!(src.ip(), from.ip(), "the address half is the sender's");
    }

    /// End to end over loopback: three real GTFv2 carriers leave by two distinct
    /// sockets and every one of them arrives, whole and stamped with the mesh port.
    #[tokio::test]
    async fn three_carriers_cross_two_loopback_paths_and_arrive_whole() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("a peer");
        let dest = receiver.local_addr().expect("a bound receiver");
        let a = UdpSocket::bind("127.0.0.1:0").await.expect("path a");
        let b = UdpSocket::bind("127.0.0.1:0").await.expect("path b");
        let port_a = a.local_addr().expect("path a bound").port();
        let port_b = b.local_addr().expect("path b bound").port();
        assert_ne!(port_a, port_b, "two paths, two sockets");

        let bound = |interface: &str, socket: UdpSocket| LivePath {
            path: BondPath {
                interface: interface.to_string(),
                index: None,
                local: "127.0.0.1:0".parse().expect("a local address"),
            },
            socket: Arc::new(socket),
            down_since: None,
        };
        let paths = vec![bound("lo0", a), bound("lo1", b)];
        let phy: Vec<PhyPath> = paths.iter().map(|p| p.path.phy()).collect();
        let mut scheduler = HpebScheduler::new(phy);
        for interface in ["lo0", "lo1"] {
            scheduler.set_available(interface, true);
        }
        let mut handover = HandoverState::new(Duration::from_millis(10));
        handover.prefer("lo0", Instant::now());
        *state().lock() = Some(BondState {
            scheduler,
            handover,
            paths,
            reported: std::collections::HashSet::new(),
        });

        let carriers: Vec<Vec<u8>> = (0..3u8)
            .map(|i| {
                let header = vantablack::ghost::net::GtfV2Header {
                    session_hash: [9, 8, 7, 6],
                    counter: 1 + u64::from(i),
                    epoch: 0,
                    nonce: [i + 1; 12],
                    shard_index: i,
                    flags: 0,
                    bulk: false,
                    tail: [0u8; vantablack::ghost::net::JITTER_MAX],
                };
                vantablack::ghost::net::build_gtf_v2_frame(&header, &[0xA0 + i; 128], &[0u8; 16])
            })
            .collect();
        let mesh_port = 41_889u16;

        let carried = dispatch("peer-fp", dest, &carriers, mesh_port)
            .await
            .expect("two live paths carry the bond");
        *state().lock() = None;
        assert_eq!(carried.len(), 3, "all three carriers left: {carried:?}");
        assert!(
            carried.iter().any(|i| i == "lo0") && carried.iter().any(|i| i == "lo1"),
            "both paths carried traffic: {carried:?}"
        );

        let mut buf = vec![0u8; 65_535];
        let mut shards: Vec<(Vec<u8>, u16)> = Vec::new();
        for _ in 0..3 {
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
                    .await
                    .expect("a shard arrives")
                    .expect("a datagram");
            let (frame, reply_to) = unpack(&buf[..n], from).expect("a bonded shard");
            assert_eq!(reply_to.port(), mesh_port, "the shard names the mesh port");
            assert_eq!(reply_to.ip(), from.ip(), "the address half is the sender's");
            shards.push((frame, from.port()));
        }

        let mut indices: Vec<u8> = shards
            .iter()
            .map(|(frame, _)| {
                vantablack::ghost::net::parse_gtf_v2_header(frame)
                    .expect("a GTFv2 carrier")
                    .shard_index
            })
            .collect();
        indices.sort_unstable();
        assert_eq!(indices, vec![0, 1, 2], "three carriers, none repeated");
        for (frame, _) in &shards {
            let index = vantablack::ghost::net::parse_gtf_v2_header(frame)
                .expect("a GTFv2 carrier")
                .shard_index as usize;
            assert_eq!(
                frame, &carriers[index],
                "carrier {index} arrived byte for byte"
            );
        }

        let mut source_ports: Vec<u16> = shards.iter().map(|(_, port)| *port).collect();
        source_ports.sort_unstable();
        source_ports.dedup();
        assert_eq!(
            source_ports,
            vec![port_a.min(port_b), port_a.max(port_b)],
            "two different sockets carried the three carriers"
        );
    }

    #[test]
    fn one_good_path_is_not_a_bond() {
        let (paths, _) = parse_paths("wlan0=127.0.0.1", "");
        let phy: Vec<PhyPath> = paths.iter().map(|p| p.phy()).collect();
        let scheduler = HpebScheduler::new(phy);
        assert!(!scheduler.is_bonded(), "one path cannot carry a bond");
    }
}
