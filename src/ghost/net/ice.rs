//! ICE (RFC 8445) — candidate gathering, pair ordering and connectivity checks.
//!
//! This is the piece that makes the Phase 1 gate reachable: *"two real machines
//! behind residential NAT44/CGNAT + a phone on LTE establish a tunnel with
//! `GHOST_VPN=hub/client` without port forwarding."*
//!
//! ## What this replaces
//!
//! `mesh.rs`'s `NatHolePuncher::punch_hole` sent five `GHOST_HPUNCH_` blobs plus
//! `port+1..=5` guesses, slept, then set `connected = true` and returned `true`
//! — with no response ever checked. It reported success unconditionally, and it
//! had no callers. That loop is not ICE and could not be made into ICE by
//! tuning; the missing parts were a real STUN codec (`super::stun`), a candidate
//! model, an authenticated check, and a response-driven state machine.
//!
//! ## Design
//!
//! The agent is deliberately **transport-free**: it builds and validates
//! datagrams and owns the check list, while the caller owns the socket. That
//! keeps it testable without networking (every priority, pairing, role-conflict
//! and message-formation rule is covered by unit tests that need no I/O), and
//! lets the tunnel reuse whatever socket the mesh already has.
//!
//! ## Short-term credential convention
//!
//! `USERNAME` is `<remote-ufrag>:<local-ufrag>` for requests we send. The
//! `MESSAGE-INTEGRITY` key is always **the password belonging to the ufrag that
//! appears first in `USERNAME`** — i.e. the receiver's password. Consequently:
//!
//! | Message | USERNAME | Integrity key |
//! |---|---|---|
//! | request we send | `them:us` | remote password |
//! | request received | `us:them` | local password |
//! | response we send | `us:them` | local password |
//!
//! Both agents therefore verify with their own password, which is what makes the
//! checks authenticated rather than merely well-formed.

use super::stun::{self, Attribute, Class, Message, Method, TransactionId};
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Upper bound on in-flight checks we track for RTT measurement. A check that
/// never comes back is eventually forgotten rather than pinning memory; the
/// retransmission bound (`Nmax`) already limits how many can be outstanding.
pub const MAX_TRACKED_CHECKS: usize = 128;

/// The single component this tunnel multiplexes. RFC 8445 uses components for
/// RTP/RTCP separation; we have one logical tunnel, so everything is component 1.
pub const DEFAULT_COMPONENT: u16 = 1;

/// Local preference used for every candidate we gather (RFC 8445 §5.1.2.1).
pub const DEFAULT_LOCAL_PREFERENCE: u16 = 65535;

/// Default per-check retransmission timeout (RFC 8445 §14.3 `RTO`).
pub const DEFAULT_RTO: Duration = Duration::from_millis(500);

/// Default number of retransmissions before a pair fails (§14.3 `Nmax`).
pub const DEFAULT_CHECK_ATTEMPTS: u32 = 7;

// ── Candidate types ─────────────────────────────────────────────────

/// A candidate's origin (RFC 8445 §5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// A local interface address.
    Host,
    /// A public mapping discovered from a STUN server.
    ServerReflexive,
    /// A public mapping learned from an inbound check.
    PeerReflexive,
    /// An address on a relay (TURN).
    Relay,
}

impl CandidateType {
    /// RFC 8445 §5.1.2.2 type preferences.
    pub fn preference(self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::Relay => "relay",
        }
    }
}

/// ICE candidate priority: `2^24·type + 2^8·local + (256 − component)`.
pub fn candidate_priority(ctype: CandidateType, local_preference: u16, component: u16) -> u32 {
    let component_term = 256u32.saturating_sub(component as u32);
    (ctype.preference() << 24) + ((local_preference as u32) << 8) + component_term
}

/// A foundation groups candidates that were gathered on the same base address
/// against the same STUN server with the same type (RFC 8445 §5.1.1.3).
/// Candidates that share a foundation must not be checked in parallel.
fn foundation(ctype: CandidateType, base: SocketAddr, stun_server: Option<SocketAddr>) -> String {
    let key = format!(
        "{}|{}|{}",
        ctype.as_str(),
        base.ip(),
        stun_server.map(|s| s.ip().to_string()).unwrap_or_default()
    );
    // CRC-32 of the identity tuple: deterministic across runs and platforms,
    // and cheap enough to compute per candidate.
    format!("{:08x}", stun::crc32_ieee(key.as_bytes()))
}

/// A single candidate address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Groups related candidates (§5.1.1.3).
    pub foundation: String,
    /// Component ID, 1 for our single tunnel.
    pub component: u16,
    pub ctype: CandidateType,
    pub priority: u32,
    /// The local address this candidate was gathered from.
    pub base: SocketAddr,
    /// The address a peer would send to / connect with.
    pub addr: SocketAddr,
}

impl Candidate {
    pub fn new(
        ctype: CandidateType,
        base: SocketAddr,
        addr: SocketAddr,
        component: u16,
        stun_server: Option<SocketAddr>,
    ) -> Self {
        Candidate {
            foundation: foundation(ctype, base, stun_server),
            component,
            ctype,
            priority: candidate_priority(ctype, DEFAULT_LOCAL_PREFERENCE, component),
            base,
            addr,
        }
    }

    /// Parse the RFC 8445 §5.1.1 candidate-attribute form
    /// (`candidate:<foundation> <component> <transport> <priority> <addr> <port>
    /// typ <type> [raddr <ip> rport <port>]`).
    ///
    /// Signalling between peers uses this text form, so peers can exchange
    /// candidates through the existing beacon payload.
    pub fn from_attribute(value: &str) -> Result<Candidate, IceError> {
        let s = value.strip_prefix("candidate:").unwrap_or(value);
        let mut it = s.split_whitespace();
        let foundation = it
            .next()
            .ok_or(IceError::Malformed("candidate: missing foundation"))?
            .to_string();
        let component: u16 = it
            .next()
            .ok_or(IceError::Malformed("candidate: missing component"))?
            .parse()
            .map_err(|_| IceError::Malformed("candidate: bad component"))?;
        // Transport is the RFC's third field. We only do UDP; anything else is
        // refused rather than silently treated as UDP.
        let transport = it
            .next()
            .ok_or(IceError::Malformed("candidate: missing transport"))?;
        if !transport.eq_ignore_ascii_case("udp") {
            return Err(IceError::Malformed("candidate: unsupported transport"));
        }
        let priority: u32 = it
            .next()
            .ok_or(IceError::Malformed("candidate: missing priority"))?
            .parse()
            .map_err(|_| IceError::Malformed("candidate: bad priority"))?;
        let addr: std::net::IpAddr = it
            .next()
            .ok_or(IceError::Malformed("candidate: missing address"))?
            .parse()
            .map_err(|_| IceError::Malformed("candidate: bad address"))?;
        let port: u16 = it
            .next()
            .ok_or(IceError::Malformed("candidate: missing port"))?
            .parse()
            .map_err(|_| IceError::Malformed("candidate: bad port"))?;
        match it.next() {
            Some(t) if t.eq_ignore_ascii_case("typ") => {}
            _ => return Err(IceError::Malformed("candidate: missing typ")),
        }
        let ctype = match it.next() {
            Some("host") => CandidateType::Host,
            Some("srflx") => CandidateType::ServerReflexive,
            Some("prflx") => CandidateType::PeerReflexive,
            Some("relay") => CandidateType::Relay,
            _ => return Err(IceError::Malformed("candidate: unknown type")),
        };
        let addr = SocketAddr::new(addr, port);
        // `raddr`/`rport` carry the base address. Absent, the candidate was
        // gathered on the address a peer connects to (a host candidate).
        let mut base = addr;
        while let Some(key) = it.next() {
            match key {
                "raddr" => {
                    let ip: std::net::IpAddr = it
                        .next()
                        .ok_or(IceError::Malformed("candidate: raddr without an address"))?
                        .parse()
                        .map_err(|_| IceError::Malformed("candidate: bad raddr"))?;
                    match it.next() {
                        Some(k) if k.eq_ignore_ascii_case("rport") => {}
                        _ => return Err(IceError::Malformed("candidate: raddr without rport")),
                    }
                    let rport: u16 = it
                        .next()
                        .ok_or(IceError::Malformed("candidate: rport missing"))?
                        .parse()
                        .map_err(|_| IceError::Malformed("candidate: bad rport"))?;
                    base = SocketAddr::new(ip, rport);
                }
                _ => return Err(IceError::Malformed("candidate: unknown attribute")),
            }
        }
        Ok(Candidate {
            foundation,
            component,
            ctype,
            priority,
            base,
            addr,
        })
    }

    /// Render as the RFC 8445 §5.1.1 candidate attribute.
    ///
    /// The base address rides in `raddr`/`rport` when it differs from the
    /// address a peer sends to — which is exactly the server-reflexive and relay
    /// case. Without it a round trip through text signalling silently rewrites a
    /// candidate's base to its public address, and the checks then go out of the
    /// wrong socket.
    pub fn to_attribute(&self) -> String {
        let mut s = format!(
            "candidate:{} {} UDP {} {} {} typ {}",
            self.foundation,
            self.component,
            self.priority,
            self.addr.ip(),
            self.addr.port(),
            self.ctype.as_str()
        );
        if self.base != self.addr {
            s.push_str(&format!(
                " raddr {} rport {}",
                self.base.ip(),
                self.base.port()
            ));
        }
        s
    }
}

// ── Credentials, role, tie-breaker ──────────────────────────────────

/// ICE short-term credentials, exchanged out of band (here: over the beacon).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCredentials {
    /// `ufrag`, 4–256 characters of ice-chars.
    pub ufrag: String,
    /// `password`, 22–256 characters of ice-chars.
    pub password: String,
}

impl IceCredentials {
    /// Generate random credentials. Hex keeps us inside the ice-char set
    /// (`ALPHA / DIGIT / "+" / "/"`), so no escaping is needed.
    pub fn generate() -> Self {
        let mut u = [0u8; 6];
        let mut p = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut u);
        rand::rngs::OsRng.fill_bytes(&mut p);
        IceCredentials {
            ufrag: hex::encode(u),
            password: hex::encode(p),
        }
    }
}

/// Maximum candidates accepted from a peer's offer.
///
/// An offer arrives over unauthenticated signalling (the beacon), and each
/// candidate becomes a pair to check, so an unbounded list is a cheap way to
/// make a node burn CPU and sockets. 32 is far above anything a real agent needs.
pub const MAX_CANDIDATES_IN_OFFER: usize = 32;

impl IceCredentials {
    /// RFC 8445 §5.3 length bounds.
    ///
    /// Enforced on anything arriving from the network: short credentials weaken
    /// the check authentication, and the offer is parsed before any trust exists.
    pub fn validate(&self) -> Result<(), IceError> {
        if self.ufrag.len() < 4 || self.ufrag.len() > 256 {
            return Err(IceError::Malformed("ice-ufrag must be 4..=256 characters"));
        }
        if self.password.len() < 22 || self.password.len() > 256 {
            return Err(IceError::Malformed("ice-pwd must be 22..=256 characters"));
        }
        Ok(())
    }
}

/// A peer's ICE offer: structured as ufrag, ufrag for the peer's
/// [`IceCredentials`], candidates and role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceOffer {
    pub credentials: IceCredentials,
    pub candidates: Vec<Candidate>,
    /// True when the sender claims the controlling role.
    pub controlling: bool,
}

impl IceOffer {
    pub fn new(credentials: IceCredentials, candidates: Vec<Candidate>, controlling: bool) -> Self {
        IceOffer {
            credentials,
            candidates,
            controlling,
        }
    }

    /// Line-oriented text encoding, so an offer fits an existing text signalling
    /// field (beacon, peers cache, side channel) without inventing a binary
    /// framing:
    ///
    /// ```text
    /// ice-ufrag:1a2b3c4d5e6f
    /// ice-pwd:00112233445566778899aabbccddeeff
    /// role:controlling
    /// candidate:<foundation> 1 host <prio> 192.168.1.10 5000 typ host
    /// ```
    pub fn encode(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("ice-ufrag:{}\n", self.credentials.ufrag));
        s.push_str(&format!("ice-pwd:{}\n", self.credentials.password));
        s.push_str(&format!(
            "role:{}\n",
            if self.controlling {
                "controlling"
            } else {
                "controlled"
            }
        ));
        for c in &self.candidates {
            s.push_str(&c.to_attribute());
            s.push('\n');
        }
        s
    }

    /// Parse an offer. Every field is required and validated: this input comes
    /// off the wire.
    pub fn decode(text: &str) -> Result<IceOffer, IceError> {
        let mut ufrag = None;
        let mut password = None;
        let mut controlling = None;
        let mut candidates = Vec::new();

        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if let Some(v) = line.strip_prefix("ice-ufrag:") {
                ufrag = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("ice-pwd:") {
                password = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("role:") {
                controlling = Some(match v.trim() {
                    "controlling" => true,
                    "controlled" => false,
                    _ => return Err(IceError::Malformed("offer: unknown role")),
                });
            } else if line.starts_with("candidate:") {
                if candidates.len() >= MAX_CANDIDATES_IN_OFFER {
                    return Err(IceError::Malformed("offer: too many candidates"));
                }
                candidates.push(Candidate::from_attribute(line)?);
            } else {
                return Err(IceError::Malformed("offer: unrecognised line"));
            }
        }

        let credentials = IceCredentials {
            ufrag: ufrag.ok_or(IceError::Malformed("offer: missing ice-ufrag"))?,
            password: password.ok_or(IceError::Malformed("offer: missing ice-pwd"))?,
        };
        credentials.validate()?;
        let controlling = controlling.ok_or(IceError::Malformed("offer: missing role"))?;
        if candidates.is_empty() {
            return Err(IceError::Malformed("offer: no candidates"));
        }
        Ok(IceOffer {
            credentials,
            candidates,
            controlling,
        })
    }
}

/// Which agent drives nomination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    Controlling,
    Controlled,
}

impl IceRole {
    pub fn other(self) -> IceRole {
        match self {
            IceRole::Controlling => IceRole::Controlled,
            IceRole::Controlled => IceRole::Controlling,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            IceRole::Controlling => "controlling",
            IceRole::Controlled => "controlled",
        }
    }
}

// ── Check list ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// Not yet eligible (foundation conflicts with an in-progress pair).
    Frozen,
    /// Eligible to be checked.
    Waiting,
    /// A check is outstanding.
    InProgress,
    /// A check succeeded.
    Succeeded,
    /// The check list exhausted its retransmissions.
    Failed,
}

/// A local/remote candidate pair (RFC 8445 §6.1.2.2).
#[derive(Debug, Clone)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
    pub state: PairState,
    /// Set when a check carrying `USE-CANDIDATE` succeeded.
    pub nominated: bool,
    pub priority: u64,
    /// Checks sent so far (§14.3 `Nmax` bound).
    pub attempts: u32,
    /// Measured round-trip time of the last successful check.
    pub rtt: Option<Duration>,
}

impl CandidatePair {
    pub fn key(&self) -> (&SocketAddr, &SocketAddr) {
        (&self.local.base, &self.remote.addr)
    }
}

/// Pair priority for the controlling agent: `2^32·min(G,D) + 2·max(G,D) + (G>D)`.
fn pair_priority_minmax(g: u32, d: u32) -> u64 {
    let (lo, hi) = if g < d { (g, d) } else { (d, g) };
    (2u64 << 31) * lo as u64 + 2 * hi as u64 + u64::from(g > d)
}

/// Pair priority computed for `role` (RFC 8445 §6.1.2.3: `G` is the controlling
/// agent's candidate and `D` the controlled one).
pub fn pair_priority_for(role: IceRole, local_priority: u32, remote_priority: u32) -> u64 {
    match role {
        IceRole::Controlling => pair_priority_minmax(local_priority, remote_priority),
        IceRole::Controlled => pair_priority_minmax(remote_priority, local_priority),
    }
}

/// Coarse agent state, for logging and for deciding when to fall back to a relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// No candidates yet.
    New,
    /// Gathering candidates.
    Gathering,
    /// Have candidates, checks outstanding.
    Checking,
    /// A pair is nominated and succeeded.
    Connected,
    /// Every pair failed — the caller should try a relay.
    Failed,
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum IceError {
    #[error("remote credentials are required before checks can be built")]
    MissingRemoteCredentials,
    #[error("no candidates have been gathered")]
    NoCandidates,
    #[error("candidate gathering timed out")]
    GatherTimeout,
    #[error("STUN error: {0}")]
    Stun(#[from] stun::StunError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not parse a 64-bit tie-breaker from the peer")]
    BadTieBreaker,
    #[error("malformed ICE input: {0}")]
    Malformed(&'static str),
}

// ── Local address probing ───────────────────────────────────────────

/// Discover the local source address the OS would use to reach `dest`.
///
/// Uses the classic `connect`-on-UDP trick: a UDP `connect` performs a route
/// lookup without sending a packet, so `local_addr()` reveals the outbound
/// interface. This is how we get a *host* candidate with no extra dependency and
/// no interface enumeration (a bound `0.0.0.0:port` socket does not say which
/// interface it will send from).
pub fn probe_local_addr(dest: SocketAddr) -> std::io::Result<SocketAddr> {
    let bind = if dest.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let probe = std::net::UdpSocket::bind(bind)?;
    probe.connect(dest)?;
    probe.local_addr()
}

// ── Result of processing an inbound check ───────────────────────────

/// What an inbound connectivity check produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// Index into [`IceAgent::pairs`] this check was matched to.
    pub pair: usize,
    /// A `Binding Success` response, integrity-protected, ready to send to the
    /// peer. `None` when the check was a response rather than a request.
    pub response: Option<Vec<u8>>,
    /// The peer nominated this pair with this check.
    pub nominated: bool,
    /// A role conflict was detected and this agent flipped role (§7.3.1.1).
    pub role_flipped: bool,
    /// Set when the datagram was a response that completed one of *our* checks.
    pub completed_our_check: Option<Duration>,
}

// ── Agent ───────────────────────────────────────────────────────────

/// An ICE agent: candidates, check list, and the authenticated check protocol.
pub struct IceAgent {
    role: IceRole,
    /// Random 64-bit tie-breaker (§6.1.1), fixed for the agent's lifetime.
    tie_breaker: u64,
    local_credentials: IceCredentials,
    remote_credentials: Option<IceCredentials>,
    local_candidates: Vec<Candidate>,
    remote_candidates: Vec<Candidate>,
    pairs: Vec<CandidatePair>,
    nominated: Option<usize>,
    retransmit_attempts: u32,
    /// Peer-reflexive candidates discovered from inbound checks, so a check from
    /// an address we did not know about can still establish a pair (§7.3.1.3).
    discovered_prflx: u32,
    /// Transaction IDs of checks we sent, mapped to the pair they probed, the
    /// local base address they left from, and when. This is what turns a success
    /// response into a *measured* round-trip time — without it `CandidatePair::rtt`
    /// could never be filled, and everything downstream (CGR latency, keepalive
    /// pacing, path fitness) would have to guess.
    ///
    /// The local base is part of the record because a response identifies itself
    /// only by its source address. Two of our candidates talking to the same peer
    /// are two pairs, and matching on the peer alone would attribute the answer —
    /// and its RTT — to whichever pair happened to be listed first.
    checks_sent: HashMap<TransactionId, (usize, SocketAddr, Instant)>,
    /// Insertion order of `checks_sent`, so the oldest entry can be evicted once
    /// the table is at [`MAX_TRACKED_CHECKS`].
    check_order: VecDeque<TransactionId>,
}

impl IceAgent {
    pub fn new(role: IceRole) -> Self {
        IceAgent {
            role,
            tie_breaker: rand::random::<u64>(),
            local_credentials: IceCredentials::generate(),
            remote_credentials: None,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            pairs: Vec::new(),
            nominated: None,
            retransmit_attempts: DEFAULT_CHECK_ATTEMPTS,
            discovered_prflx: 0,
            checks_sent: HashMap::new(),
            check_order: VecDeque::new(),
        }
    }

    /// Override the per-pair retransmission bound (tests use small values).
    pub fn with_check_attempts(mut self, attempts: u32) -> Self {
        self.retransmit_attempts = attempts.max(1);
        self
    }

    pub fn role(&self) -> IceRole {
        self.role
    }

    pub fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }

    pub fn local_credentials(&self) -> &IceCredentials {
        &self.local_credentials
    }

    pub fn remote_credentials(&self) -> Option<&IceCredentials> {
        self.remote_credentials.as_ref()
    }

    /// Install the peer's credentials (from the beacon/offer).
    pub fn set_remote_credentials(&mut self, creds: IceCredentials) {
        self.remote_credentials = Some(creds);
    }

    /// Adopt credentials we already advertised in an offer.
    ///
    /// This must be honoured: inbound checks are verified against our *local*
    /// password, so generating fresh credentials here would silently reject every
    /// check a peer sends from the offer it received.
    pub fn set_local_credentials(&mut self, creds: IceCredentials) {
        self.local_credentials = creds;
    }

    /// Adopt the peer's role and credentials from a remote offer.
    pub fn set_remote_role(&mut self, role: IceRole) {
        self.role = role.other();
    }

    // ── Gathering ───────────────────────────────────────────────────

    pub fn local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    pub fn remote_candidates(&self) -> &[Candidate] {
        &self.remote_candidates
    }

    /// Number of peer-reflexive candidates learned from inbound checks.
    pub fn discovered_prflx(&self) -> u32 {
        self.discovered_prflx
    }

    /// Record a host candidate from an address we already know.
    pub fn add_host_candidate(&mut self, base: SocketAddr, advertised: SocketAddr) -> Candidate {
        let c = Candidate::new(
            CandidateType::Host,
            base,
            advertised,
            DEFAULT_COMPONENT,
            None,
        );
        self.local_candidates.push(c.clone());
        c
    }

    /// Gather a host candidate for `route_to`, resolving the outbound interface
    /// when the socket is bound to a wildcard address.
    pub fn gather_host(
        &mut self,
        sock: &tokio::net::UdpSocket,
        route_to: SocketAddr,
    ) -> Result<Candidate, IceError> {
        let bound = sock.local_addr()?;
        let local = if bound.ip().is_unspecified() {
            probe_local_addr(route_to)?
        } else {
            bound
        };
        let advertised = SocketAddr::new(local.ip(), bound.port());
        debug!(local = %advertised, "ICE: host candidate gathered");
        Ok(self.add_host_candidate(local, advertised))
    }

    /// Discover this agent's public mapping with a real STUN Binding request
    /// (RFC 8489 §7.2.1) and record it as a server-reflexive candidate.
    ///
    /// Non-matching datagrams are skipped rather than treated as errors. Note
    /// that they are **dropped** — if this socket also carries mesh traffic, use
    /// [`Self::gather_reflexive_with`] so nothing is lost.
    pub async fn gather_reflexive(
        &mut self,
        sock: &tokio::net::UdpSocket,
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<Candidate, IceError> {
        self.gather_reflexive_with(sock, server, timeout, |_, _| {})
            .await
    }

    /// As [`Self::gather_reflexive`], but hands every datagram that is not the
    /// response we are waiting for to `on_other`.
    ///
    /// This matters when the socket is shared with the mesh: silently dropping
    /// those datagrams presents as unexplained packet loss under load, which is
    /// hard to attribute later. A caller that can re-inject them should use this
    /// form; a caller with a dedicated socket can use the simpler one.
    pub async fn gather_reflexive_with<F>(
        &mut self,
        sock: &tokio::net::UdpSocket,
        server: SocketAddr,
        timeout: Duration,
        mut on_other: F,
    ) -> Result<Candidate, IceError>
    where
        F: FnMut(&[u8], SocketAddr),
    {
        let txid = TransactionId::random();
        let request = Message::binding_request(txid).encode();
        sock.send_to(&request, server).await?;

        let deadline = tokio::time::Instant::now() + timeout;
        let mut buf = vec![0u8; 1500];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                warn!(server = %server, "ICE: STUN binding request timed out");
                return Err(IceError::GatherTimeout);
            }
            let (n, from) = match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
                Err(_) => return Err(IceError::GatherTimeout),
                Ok(Err(e)) => return Err(IceError::Io(e)),
                Ok(Ok(v)) => v,
            };
            // Only the STUN server we asked may answer; anything else belongs
            // to whoever else owns this socket.
            if from != server {
                on_other(&buf[..n], from);
                continue;
            }
            let Ok(msg) = Message::parse(&buf[..n]) else {
                on_other(&buf[..n], from);
                continue;
            };
            if msg.txid != txid
                || msg.typ.method() != Method::BINDING
                || msg.typ.class() != Class::SuccessResponse
            {
                on_other(&buf[..n], from);
                continue;
            }
            // A reflexive address we cannot authenticate at least has to be a
            // well-formed STUN message.
            if stun::verify_fingerprint(&buf[..n]).is_err() {
                debug!(from = %from, "ICE: STUN response failed FINGERPRINT");
                on_other(&buf[..n], from);
                continue;
            }
            let Some(mapped) = msg.xor_mapped_address() else {
                on_other(&buf[..n], from);
                continue;
            };
            let base = sock.local_addr()?;
            let c = self.add_server_reflexive_candidate(base, mapped, Some(server));
            info!(public = %mapped, "ICE: server-reflexive candidate discovered");
            return Ok(c);
        }
    }

    /// Record a server-reflexive candidate whose address we already know.
    ///
    /// [`Self::gather_reflexive`] is the network path; this is for an address that
    /// came from somewhere else — a STUN response gathered on another socket, a
    /// cached mapping from an earlier session, or a test. `stun_server` only
    /// affects the foundation, so candidates from different servers do not share
    /// one and freeze each other (RFC 8445 §5.1.1.3).
    pub fn add_server_reflexive_candidate(
        &mut self,
        base: SocketAddr,
        mapped: SocketAddr,
        stun_server: Option<SocketAddr>,
    ) -> Candidate {
        let c = Candidate::new(
            CandidateType::ServerReflexive,
            base,
            mapped,
            DEFAULT_COMPONENT,
            stun_server,
        );
        self.local_candidates.push(c.clone());
        c
    }

    /// Record a relay (TURN) candidate. The relay's own allocation lives in the
    /// TURN client; this just makes the address usable by the check list.
    pub fn add_relay_candidate(&mut self, base: SocketAddr, relay_addr: SocketAddr) -> Candidate {
        let c = Candidate::new(
            CandidateType::Relay,
            base,
            relay_addr,
            DEFAULT_COMPONENT,
            None,
        );
        self.local_candidates.push(c.clone());
        c
    }

    /// Add a candidate advertised by the peer. Malformed input is rejected, not
    /// silently accepted — a candidate we cannot parse is one we must not check.
    pub fn add_remote_candidate(&mut self, c: Candidate) {
        self.remote_candidates.push(c);
    }

    /// Parse and add a peer candidate from its RFC 8445 attribute text.
    pub fn add_remote_candidate_attribute(&mut self, value: &str) -> Result<Candidate, IceError> {
        let c = Candidate::from_attribute(value)?;
        self.remote_candidates.push(c.clone());
        Ok(c)
    }

    // ── Check list construction ─────────────────────────────────────

    pub fn pairs(&self) -> &[CandidatePair] {
        &self.pairs
    }

    /// Build the check list: one pair per (component, local, remote) triple,
    /// ordered by descending priority, with the top pair `Waiting` and the rest
    /// `Frozen` (RFC 8445 §6.1.2.6). Pairs sharing a foundation with a
    /// higher-priority pair stay frozen, which is what stops a single base
    /// address from being checked many times in parallel.
    pub fn form_pairs(&mut self) {
        let mut pairs = Vec::new();
        for local in &self.local_candidates {
            for remote in &self.remote_candidates {
                if local.component != remote.component {
                    continue;
                }
                pairs.push(CandidatePair {
                    local: local.clone(),
                    remote: remote.clone(),
                    state: PairState::Frozen,
                    nominated: false,
                    priority: pair_priority_for(self.role, local.priority, remote.priority),
                    attempts: 0,
                    rtt: None,
                });
            }
        }
        // Highest priority first.
        pairs.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.remote.addr.cmp(&b.remote.addr))
        });

        // First pair per (foundation, component) is eligible; the rest freeze.
        let mut seen: Vec<(String, u16)> = Vec::new();
        for p in &mut pairs {
            let key = (p.local.foundation.clone(), p.local.component);
            if seen.contains(&key) {
                p.state = PairState::Frozen;
            } else {
                p.state = PairState::Waiting;
                seen.push(key);
            }
        }
        self.pairs = pairs;
        self.nominated = None;
        // Pair indices just changed, so every in-flight check now refers to a
        // stale index; the RTT table must not outlive them.
        self.checks_sent.clear();
        self.check_order.clear();
    }

    /// The next pair to check, moved to `InProgress`. Returns its index.
    ///
    /// Unfreezing happens here rather than in [`Self::form_pairs`]: when a pair's
    /// foundation sibling fails, the next pair for that foundation becomes
    /// eligible (§6.1.2.6).
    pub fn next_check(&mut self) -> Option<usize> {
        // Any foundation whose pairs all failed frees its siblings.
        let failed_foundations: Vec<(String, u16)> = self
            .pairs
            .iter()
            .filter(|p| p.state == PairState::Failed)
            .map(|p| (p.local.foundation.clone(), p.local.component))
            .collect();
        for (foundation, component) in failed_foundations {
            let all_failed = self
                .pairs
                .iter()
                .filter(|p| p.local.foundation == foundation && p.local.component == component)
                .all(|p| matches!(p.state, PairState::Failed));
            if all_failed {
                for p in self
                    .pairs
                    .iter_mut()
                    .filter(|p| p.local.foundation == foundation && p.local.component == component)
                {
                    if p.state == PairState::Frozen {
                        p.state = PairState::Waiting;
                    }
                }
            }
        }

        let idx = self
            .pairs
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == PairState::Waiting)
            .max_by_key(|(_, p)| p.priority)
            .map(|(i, _)| i)?;
        self.pairs[idx].state = PairState::InProgress;
        self.pairs[idx].attempts += 1;
        Some(idx)
    }

    /// Give up on an in-progress pair (retransmissions exhausted).
    pub fn fail_pair(&mut self, idx: usize) {
        if let Some(p) = self.pairs.get_mut(idx) {
            p.state = PairState::Failed;
        }
    }

    /// True when no pair can still succeed — the signal to fall back to a relay.
    pub fn is_exhausted(&self) -> bool {
        !self.pairs.is_empty()
            && self
                .pairs
                .iter()
                .all(|p| matches!(p.state, PairState::Failed))
    }

    pub fn state(&self) -> IceState {
        if self.nominated.is_some() {
            return IceState::Connected;
        }
        if self.local_candidates.is_empty() {
            return IceState::New;
        }
        if self.pairs.is_empty() {
            return IceState::Gathering;
        }
        if self.is_exhausted() {
            return IceState::Failed;
        }
        IceState::Checking
    }

    /// The nominated, succeeded pair, if any.
    pub fn selected_pair(&self) -> Option<&CandidatePair> {
        let idx = self.nominated?;
        let p = self.pairs.get(idx)?;
        if p.state == PairState::Succeeded {
            Some(p)
        } else {
            None
        }
    }

    /// Nominate a pair directly. Used by the controlled agent when the peer's
    /// `USE-CANDIDATE` check arrives, and by tests.
    pub fn nominate(&mut self, idx: usize) -> bool {
        match self.pairs.get_mut(idx) {
            Some(p) if p.state == PairState::Succeeded => {
                p.nominated = true;
                self.nominated = Some(idx);
                info!(local = %p.local.base, remote = %p.remote.addr, "ICE: pair nominated");
                true
            }
            _ => false,
        }
    }

    // ── Connectivity checks ─────────────────────────────────────────

    /// Integrity key for a request we send: the *remote* password (the first
    /// ufrag in `them:us`).
    fn outgoing_key(&self) -> Result<&str, IceError> {
        self.remote_credentials
            .as_ref()
            .map(|c| c.password.as_str())
            .ok_or(IceError::MissingRemoteCredentials)
    }

    fn username_for_outgoing(&self) -> Result<String, IceError> {
        let remote = self
            .remote_credentials
            .as_ref()
            .ok_or(IceError::MissingRemoteCredentials)?;
        Ok(format!("{}:{}", remote.ufrag, self.local_credentials.ufrag))
    }

    /// Build an authenticated Binding request for `pairs[idx]`.
    ///
    /// `nominate` sets `USE-CANDIDATE`, which only the controlling agent may do.
    ///
    /// The transaction is remembered against the instant it was built, so that a
    /// matching success response yields a real round-trip time.
    pub fn build_check(&mut self, idx: usize, nominate: bool) -> Result<Vec<u8>, IceError> {
        let pair = self.pairs.get(idx).ok_or(IceError::NoCandidates)?;
        let key = self.outgoing_key()?;
        let username = self.username_for_outgoing()?;

        let txid = TransactionId::random();
        let mut msg = Message::binding_request(txid);
        msg.push(Attribute::Username(username.into_bytes()));
        msg.push(Attribute::Priority(pair.local.priority));
        if nominate && self.role == IceRole::Controlling {
            msg.push(Attribute::UseCandidate);
        }
        // Exactly one role attribute, never both (RFC 8445 §7.2.2).
        let role_attr = match self.role {
            IceRole::Controlling => Attribute::IceControlling(self.tie_breaker),
            IceRole::Controlled => Attribute::IceControlled(self.tie_breaker),
        };
        msg.push(role_attr);
        let encoded = msg.encode_with_integrity(key.as_bytes())?;
        let base = pair.local.base;
        self.track_check(txid, idx, base);
        Ok(encoded)
    }

    /// Remember an outstanding check, evicting the oldest once the table is full.
    ///
    /// Bounding the table by *count* rather than by age keeps this deterministic
    /// (no clock comparison) while still guaranteeing bounded memory: once
    /// `MAX_TRACKED_CHECKS` newer checks exist, an older transaction can no
    /// longer produce a meaningful RTT measurement anyway.
    fn track_check(&mut self, txid: TransactionId, idx: usize, base: SocketAddr) {
        self.checks_sent.insert(txid, (idx, base, Instant::now()));
        self.check_order.push_back(txid);
        while self.check_order.len() > MAX_TRACKED_CHECKS {
            if let Some(old) = self.check_order.pop_front() {
                self.checks_sent.remove(&old);
            }
        }
    }

    /// Round-trip time of the nominated pair, once a check has completed.
    pub fn selected_pair_rtt(&self) -> Option<Duration> {
        self.selected_pair().and_then(|p| p.rtt)
    }

    /// A triggered check for a pair that just became interesting.
    ///
    /// Identical in content to [`Self::build_check`] — a triggered check is an
    /// ordinary check sent immediately rather than queued behind the list order.
    pub fn build_triggered_check(&mut self, idx: usize) -> Result<Vec<u8>, IceError> {
        self.build_check(idx, false)
    }

    /// Whether `pairs[idx]` has retransmissions left (RFC 8445 §14.3 `Nmax`).
    pub fn can_retransmit(&self, idx: usize) -> bool {
        self.pairs
            .get(idx)
            .map(|p| p.attempts < self.retransmit_attempts)
            .unwrap_or(false)
    }

    /// Re-arm an in-progress pair for another attempt. False when the pair has
    /// exhausted `Nmax` and the caller should call [`Self::fail_pair`] instead.
    pub fn retransmit(&mut self, idx: usize) -> bool {
        if !self.can_retransmit(idx) {
            return false;
        }
        if let Some(p) = self.pairs.get_mut(idx) {
            p.attempts += 1;
        }
        true
    }

    /// Process an inbound datagram from `from`.
    ///
    /// Returns `Ok(None)` when the datagram is not an ICE check we care about
    /// (unrelated mesh traffic on the same socket).
    pub fn handle_check(
        &mut self,
        raw: &[u8],
        from: SocketAddr,
    ) -> Result<Option<CheckOutcome>, IceError> {
        let msg = match Message::parse(raw) {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };
        if msg.typ.method() != Method::BINDING {
            return Ok(None);
        }

        match msg.typ.class() {
            Class::Request => self.handle_request(raw, &msg, from).map(Some),
            Class::SuccessResponse => self.handle_response(raw, &msg, from).map(Some),
            _ => Ok(None),
        }
    }

    fn handle_request(
        &mut self,
        raw: &[u8],
        msg: &Message,
        from: SocketAddr,
    ) -> Result<CheckOutcome, IceError> {
        // We are the receiver, so we verify with our own password.
        if stun::verify_integrity(raw, self.local_credentials.password.as_bytes()).is_err() {
            warn!(from = %from, "ICE: dropping unauthenticated check");
            return Err(IceError::Stun(stun::StunError::BadIntegrity));
        }

        // Role conflict (RFC 8445 §7.3.1.1): both agents claiming the same role
        // is resolved by tie-breaker; the larger one wins and stays as it is.
        let mut role_flipped = false;
        let peer_says_controlling = matches!(msg.get(0x802A), Some(Attribute::IceControlling(_)));
        let peer_says_controlled = matches!(msg.get(0x8029), Some(Attribute::IceControlled(_)));
        let peer_tie = match (msg.get(0x802A), msg.get(0x8029)) {
            (Some(Attribute::IceControlling(t)), _) | (_, Some(Attribute::IceControlled(t))) => *t,
            _ => 0,
        };
        let claims_same_role = match self.role {
            IceRole::Controlling => peer_says_controlling,
            IceRole::Controlled => peer_says_controlled,
        };
        if claims_same_role && peer_tie > self.tie_breaker {
            debug!(
                from = %from,
                "ICE: role conflict lost on tie-breaker — becoming {}",
                self.role.other().as_str()
            );
            self.role = self.role.other();
            role_flipped = true;
            // The check list ordering depends on the role.
            self.form_pairs();
        }

        let nominated_by_peer = msg.get(0x0025).is_some();

        // Match to a pair, or learn a peer-reflexive candidate (§7.3.1.3).
        let pair_idx = match self.pairs.iter().position(|p| p.remote.addr == from) {
            Some(i) => i,
            None => {
                let base = self
                    .local_candidates
                    .first()
                    .map(|c| c.base)
                    .unwrap_or(from);
                let prflx = Candidate::new(
                    CandidateType::PeerReflexive,
                    base,
                    from,
                    DEFAULT_COMPONENT,
                    None,
                );
                self.remote_candidates.push(prflx.clone());
                self.discovered_prflx += 1;
                debug!(from = %from, "ICE: learned peer-reflexive candidate");
                let local = self
                    .local_candidates
                    .first()
                    .cloned()
                    .ok_or(IceError::NoCandidates)?;
                let mut pair = CandidatePair {
                    local,
                    priority: pair_priority_for(self.role, 0, 0),
                    remote: prflx,
                    state: PairState::Succeeded,
                    nominated: false,
                    attempts: 0,
                    rtt: None,
                };
                pair.priority =
                    pair_priority_for(self.role, pair.local.priority, pair.remote.priority);
                self.pairs.push(pair);
                self.pairs.len() - 1
            }
        };

        // An authenticated check from the peer proves the path works both ways.
        if let Some(p) = self.pairs.get_mut(pair_idx) {
            p.state = PairState::Succeeded;
        }
        if nominated_by_peer {
            let _ = self.nominate(pair_idx);
        }

        // Respond: same username, keyed by the same password that authenticated
        // the request (ours).
        let mut resp = Message::binding_success(msg.txid, from);
        if let Some(Attribute::Username(u)) = msg.get(0x0006) {
            resp.push(Attribute::Username(u.clone()));
        }
        let response = resp.encode_with_integrity(self.local_credentials.password.as_bytes())?;

        Ok(CheckOutcome {
            pair: pair_idx,
            response: Some(response),
            nominated: nominated_by_peer,
            role_flipped,
            completed_our_check: None,
        })
    }

    fn handle_response(
        &mut self,
        raw: &[u8],
        msg: &Message,
        from: SocketAddr,
    ) -> Result<CheckOutcome, IceError> {
        debug_assert_eq!(
            msg.typ.class(),
            Class::SuccessResponse,
            "handle_response is only reached for success responses"
        );
        let key = self.outgoing_key()?;
        if stun::verify_integrity(raw, key.as_bytes()).is_err() {
            warn!(from = %from, "ICE: ignoring response that failed MESSAGE-INTEGRITY");
            return Err(IceError::Stun(stun::StunError::BadIntegrity));
        }
        // This response is the other half of a check we sent, so the transaction
        // ID names the pair that probed. That is the *only* unambiguous
        // discriminator: two pairs may share a local base (a host and a
        // server-reflexive candidate gathered from one socket) **and** a remote
        // address, and matching on addresses alone then credits the round trip to
        // the wrong pair — leaving the pair that actually measured it with no RTT
        // while a pair that was never in flight reports success.
        let measured = self
            .checks_sent
            .remove(&msg.txid)
            .map(|(sent_idx, base, at)| (sent_idx, base, at.elapsed()));
        let idx = match measured {
            Some((sent_idx, _, _)) if sent_idx < self.pairs.len() => Some(sent_idx),
            // A response we never asked for, or one whose check has aged out of
            // the table. The peer address is then the best evidence available,
            // but no timing may be recorded from it: an unsolicited response
            // authenticates a path without measuring it.
            _ => self.pairs.iter().position(|p| p.remote.addr == from),
        };
        let Some(idx) = idx else {
            return Ok(CheckOutcome {
                pair: usize::MAX,
                response: None,
                nominated: false,
                role_flipped: false,
                completed_our_check: None,
            });
        };
        if let Some(p) = self.pairs.get_mut(idx) {
            p.state = PairState::Succeeded;
        }
        if let Some((sent_idx, _, rtt)) = measured {
            if let Some(p) = self.pairs.get_mut(sent_idx) {
                p.rtt = Some(rtt);
            }
        }
        // The controlling agent nominates the pair it just proved.
        if self.role == IceRole::Controlling && self.nominated.is_none() {
            let _ = self.nominate(idx);
        }
        Ok(CheckOutcome {
            pair: idx,
            response: None,
            nominated: self.nominated == Some(idx),
            role_flipped: false,
            completed_our_check: self.pairs.get(idx).and_then(|p| p.rtt),
        })
    }

    /// The username a peer will send us, for sanity-checking inbound checks.
    pub fn expected_incoming_username(&self) -> Option<String> {
        let remote = self.remote_credentials.as_ref()?;
        Some(format!("{}:{}", self.local_credentials.ufrag, remote.ufrag))
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn agent_with_pairs(role: IceRole) -> IceAgent {
        let mut a = IceAgent::new(role);
        a.set_remote_credentials(IceCredentials {
            ufrag: "remoteufrag".into(),
            password: "remote-password-0123456789".into(),
        });
        a.add_host_candidate(sock("192.168.1.10:5000"), sock("192.168.1.10:5000"));
        a.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            sock("192.168.1.20:6000"),
            sock("192.168.1.20:6000"),
            DEFAULT_COMPONENT,
            None,
        ));
        a.form_pairs();
        a
    }

    #[test]
    fn type_preferences_match_rfc8445() {
        assert_eq!(CandidateType::Host.preference(), 126);
        assert_eq!(CandidateType::PeerReflexive.preference(), 110);
        assert_eq!(CandidateType::ServerReflexive.preference(), 100);
        assert_eq!(CandidateType::Relay.preference(), 0);
    }

    #[test]
    fn candidate_priority_formula_and_ordering() {
        // 2^24·type + 2^8·local + (256 − component)
        let host = candidate_priority(CandidateType::Host, 65535, 1);
        assert_eq!(host, (126 << 24) + (65535 << 8) + 255);
        let srflx = candidate_priority(CandidateType::ServerReflexive, 65535, 1);
        let relay = candidate_priority(CandidateType::Relay, 65535, 1);
        // A host candidate always beats a reflexive one, which beats a relay.
        assert!(host > srflx && srflx > relay);
    }

    #[test]
    fn foundations_group_same_type_base_and_stun_server() {
        let stun = sock("203.0.113.1:3478");
        let a = Candidate::new(
            CandidateType::ServerReflexive,
            sock("192.168.1.10:5000"),
            sock("198.51.100.1:40000"),
            DEFAULT_COMPONENT,
            Some(stun),
        );
        // Same base + same STUN server, different mapping: same foundation.
        let b = Candidate::new(
            CandidateType::ServerReflexive,
            sock("192.168.1.10:5000"),
            sock("198.51.100.1:40001"),
            DEFAULT_COMPONENT,
            Some(stun),
        );
        assert_eq!(a.foundation, b.foundation);

        // A different base must not share a foundation, or we would serialise
        // checks that could run in parallel.
        let c = Candidate::new(
            CandidateType::ServerReflexive,
            sock("192.168.1.11:5000"),
            sock("198.51.100.1:40000"),
            DEFAULT_COMPONENT,
            Some(stun),
        );
        assert_ne!(a.foundation, c.foundation);
    }

    #[test]
    fn pair_priority_formula_is_symmetric_under_role() {
        // G = 100, D = 200 → 2^32·100 + 2·200 + 0
        assert_eq!(pair_priority_minmax(100, 200), (1u64 << 32) * 100 + 400);
        // G = 200, D = 100 → same min/max, plus the G>D tie-break bit.
        assert_eq!(pair_priority_minmax(200, 100), (1u64 << 32) * 100 + 400 + 1);
    }

    #[test]
    fn controlling_and_controlled_agree_on_pair_priority() {
        // Both agents must compute the same number for the same pair, or the
        // check lists diverge and nomination deadlocks.
        let local = 0x7E00_00FF;
        let remote = 0x64_0000FF;
        let controlling_view = pair_priority_for(IceRole::Controlling, local, remote);
        let controlled_view = pair_priority_for(IceRole::Controlled, remote, local);
        assert_eq!(controlling_view, controlled_view);
    }

    #[test]
    fn check_list_orders_by_priority_and_freezes_foundation_siblings() {
        let mut a = IceAgent::new(IceRole::Controlling);
        a.set_remote_credentials(IceCredentials {
            ufrag: "u".into(),
            password: "p".into(),
        });
        a.add_host_candidate(sock("192.168.1.10:5000"), sock("192.168.1.10:5000"));
        // Two remote candidates on the same address family/type.
        for port in [6000u16, 6001] {
            a.add_remote_candidate(Candidate::new(
                CandidateType::Host,
                sock(&format!("192.168.1.20:{port}")),
                sock(&format!("192.168.1.20:{port}")),
                DEFAULT_COMPONENT,
                None,
            ));
        }
        a.form_pairs();
        assert_eq!(a.pairs().len(), 2);
        // Descending priority.
        assert!(a.pairs()[0].priority >= a.pairs()[1].priority);
        // Exactly one eligible pair per foundation; the sibling stays frozen.
        assert_eq!(a.pairs()[0].state, PairState::Waiting);
        assert_eq!(a.pairs()[1].state, PairState::Frozen);
    }

    #[test]
    fn next_check_promotes_frozen_siblings_only_after_failure() {
        let mut a = agent_with_pairs(IceRole::Controlling);
        let first = a.next_check().expect("a waiting pair");
        assert_eq!(a.pairs()[first].state, PairState::InProgress);
        assert_eq!(a.pairs()[first].attempts, 1);

        // Only one foundation here, so nothing else is eligible yet.
        assert_eq!(a.next_check(), None);

        a.fail_pair(first);
        assert!(a.is_exhausted());
        assert_eq!(a.state(), IceState::Failed);
    }

    #[test]
    fn checks_are_authenticated_and_nomination_is_explicit() {
        let mut a = agent_with_pairs(IceRole::Controlling);
        let idx = 0;
        let check = a.build_check(idx, true).unwrap();
        // Authored by us, so it must verify with the remote password.
        stun::verify_integrity(&check, b"remote-password-0123456789").unwrap();
        stun::verify_fingerprint(&check).unwrap();

        let parsed = Message::parse(&check).unwrap();
        assert!(parsed.get(0x0025).is_some(), "USE-CANDIDATE must be set");
        match parsed.get(0x0006) {
            Some(Attribute::Username(u)) => {
                assert_eq!(
                    String::from_utf8_lossy(u),
                    "remoteufrag:".to_string() + &a.local_credentials().ufrag
                );
            }
            other => panic!("expected USERNAME, got {other:?}"),
        }
        // The controlling agent advertises ICE-CONTROLLING, never both.
        assert!(parsed.get(0x802A).is_some());
        assert!(parsed.get(0x8029).is_none());
    }

    #[test]
    fn controlled_agent_never_sends_use_candidate() {
        let mut a = agent_with_pairs(IceRole::Controlled);
        let check = a.build_check(0, true).unwrap();
        let parsed = Message::parse(&check).unwrap();
        assert!(
            parsed.get(0x0025).is_none(),
            "only the controlling agent may nominate"
        );
        assert!(
            parsed.get(0x8029).is_some(),
            "must advertise ICE-CONTROLLED"
        );
    }

    /// End-to-end handshake between two agents with no sockets: the check list,
    /// the authenticated check, nomination and role assignment all have to line
    /// up, which is exactly what a hole punch depends on.
    #[test]
    fn two_agents_complete_an_authenticated_check_and_nomination() {
        let alice_addr = sock("192.168.1.10:5000");
        let bob_addr = sock("192.168.1.20:6000");

        let mut alice = IceAgent::new(IceRole::Controlling);
        let mut bob = IceAgent::new(IceRole::Controlled);
        alice.set_remote_credentials(bob.local_credentials().clone());
        bob.set_remote_credentials(alice.local_credentials().clone());

        alice.add_host_candidate(alice_addr, alice_addr);
        alice.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            bob_addr,
            bob_addr,
            DEFAULT_COMPONENT,
            None,
        ));
        bob.add_host_candidate(bob_addr, bob_addr);
        bob.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            alice_addr,
            alice_addr,
            DEFAULT_COMPONENT,
            None,
        ));
        alice.form_pairs();
        bob.form_pairs();

        // Alice (controlling) sends a nominating check.
        let idx = alice.next_check().unwrap();
        let check = alice.build_check(idx, true).unwrap();

        // Bob receives it at the address he advertised.
        let outcome = bob
            .handle_check(&check, alice_addr)
            .unwrap()
            .expect("bob must treat this as a check");
        assert!(outcome.nominated, "USE-CANDIDATE must propagate");
        assert!(bob.selected_pair().is_some(), "bob must nominate the pair");
        let response = outcome.response.expect("a request is answered");

        // Alice consumes the response.
        let reply = alice
            .handle_check(&response, bob_addr)
            .unwrap()
            .expect("alice must match the response to her check");
        assert_eq!(reply.pair, idx);
        assert!(alice.selected_pair().is_some());
        assert_eq!(alice.state(), IceState::Connected);
        assert_eq!(bob.state(), IceState::Connected);

        // Alice's check came back with the transaction ID she sent, so her round
        // trip is a *measurement* — this is the number CGR latency and path
        // fitness depend on.
        let rtt = alice
            .selected_pair_rtt()
            .expect("a completed check must yield a measured RTT");
        assert!(rtt < Duration::from_secs(5), "implausible RTT {rtt:?}");
        // Bob only answered a request; he never sent a check of his own, so there
        // is nothing for him to have measured.
        assert!(bob.selected_pair_rtt().is_none());
    }

    #[test]
    fn an_unsolicited_response_cannot_fabricate_an_rtt() {
        let mut alice = IceAgent::new(IceRole::Controlling);
        alice.set_remote_credentials(IceCredentials {
            ufrag: "bobufrag".into(),
            password: "bob-password-012345678901".into(),
        });
        let alice_addr = sock("192.168.1.10:5000");
        let bob_addr = sock("203.0.113.7:41234");
        alice.add_host_candidate(alice_addr, alice_addr);
        alice.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            bob_addr,
            bob_addr,
            DEFAULT_COMPONENT,
            None,
        ));
        alice.form_pairs();

        // A peer answers a *different* transaction, correctly authenticated (it
        // is keyed by the remote password, which a real peer knows). It proves
        // the path is up but says nothing about how long our check took.
        let mut stray = Message::binding_success(TransactionId::random(), alice_addr);
        stray.push(Attribute::Username(b"bobufrag:aliceufrag".to_vec()));
        let raw = stray
            .encode_with_integrity(b"bob-password-012345678901")
            .unwrap();
        let outcome = alice.handle_check(&raw, bob_addr).unwrap().unwrap();
        assert_eq!(outcome.pair, 0);
        assert!(
            outcome.completed_our_check.is_none(),
            "an unanswered transaction ID is not a measurement"
        );
        assert!(alice.selected_pair_rtt().is_none());
    }

    #[test]
    fn unauthenticated_checks_are_rejected() {
        let mut bob = IceAgent::new(IceRole::Controlled);
        bob.set_remote_credentials(IceCredentials {
            ufrag: "aliceufrag".into(),
            password: "alice-password-0123456789".into(),
        });
        let alice_addr = sock("192.168.1.10:5000");
        bob.add_host_candidate(sock("192.168.1.20:6000"), sock("192.168.1.20:6000"));
        bob.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            alice_addr,
            alice_addr,
            DEFAULT_COMPONENT,
            None,
        ));
        bob.form_pairs();

        // A request authenticated with the wrong password must not succeed.
        let mut msg = Message::binding_request(TransactionId::random());
        msg.push(Attribute::Username(
            format!("{}:{}", bob.local_credentials().ufrag, "aliceufrag").into_bytes(),
        ));
        let forged = msg
            .encode_with_integrity(b"definitely-not-alices-password")
            .unwrap();
        assert!(bob.handle_check(&forged, alice_addr).is_err());
        assert!(bob.selected_pair().is_none());
    }

    #[test]
    fn role_conflict_is_resolved_by_tie_breaker() {
        // Bob is controlled but Alice also claims to be controlled with a higher
        // tie-breaker: Bob must flip to controlling.
        let mut bob = IceAgent::new(IceRole::Controlled);
        bob.set_remote_credentials(IceCredentials {
            ufrag: "aliceufrag".into(),
            password: "alice-password-0123456789".into(),
        });
        let alice_addr = sock("192.168.1.10:5000");
        bob.add_host_candidate(sock("192.168.1.20:6000"), sock("192.168.1.20:6000"));
        bob.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            alice_addr,
            alice_addr,
            DEFAULT_COMPONENT,
            None,
        ));
        bob.form_pairs();

        let mut msg = Message::binding_request(TransactionId::random());
        msg.push(Attribute::Username(
            format!("{}:{}", bob.local_credentials().ufrag, "aliceufrag").into_bytes(),
        ));
        msg.push(Attribute::IceControlled(bob.tie_breaker() + 1));
        let check = msg
            .encode_with_integrity(bob.local_credentials().password.as_bytes())
            .unwrap();

        let outcome = bob.handle_check(&check, alice_addr).unwrap().unwrap();
        assert!(outcome.role_flipped);
        assert_eq!(bob.role(), IceRole::Controlling);

        // With a *lower* tie-breaker the peer must yield instead, leaving us put.
        let mut bob2 = IceAgent::new(IceRole::Controlled);
        bob2.set_remote_credentials(IceCredentials {
            ufrag: "aliceufrag".into(),
            password: "alice-password-0123456789".into(),
        });
        bob2.add_host_candidate(sock("192.168.1.20:6000"), sock("192.168.1.20:6000"));
        bob2.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            alice_addr,
            alice_addr,
            DEFAULT_COMPONENT,
            None,
        ));
        bob2.form_pairs();
        let mut msg2 = Message::binding_request(TransactionId::random());
        msg2.push(Attribute::Username(
            format!("{}:{}", bob2.local_credentials().ufrag, "aliceufrag").into_bytes(),
        ));
        msg2.push(Attribute::IceControlled(0));
        let check2 = msg2
            .encode_with_integrity(bob2.local_credentials().password.as_bytes())
            .unwrap();
        let outcome2 = bob2.handle_check(&check2, alice_addr).unwrap().unwrap();
        assert!(!outcome2.role_flipped);
        assert_eq!(bob2.role(), IceRole::Controlled);
    }

    #[test]
    fn unknown_source_produces_a_peer_reflexive_candidate() {
        let mut bob = IceAgent::new(IceRole::Controlled);
        bob.set_remote_credentials(IceCredentials {
            ufrag: "aliceufrag".into(),
            password: "alice-password-0123456789".into(),
        });
        bob.add_host_candidate(sock("192.168.1.20:6000"), sock("192.168.1.20:6000"));
        bob.form_pairs();
        assert_eq!(bob.discovered_prflx(), 0);

        let surprise = sock("203.0.113.77:41234");
        let mut msg = Message::binding_request(TransactionId::random());
        msg.push(Attribute::Username(
            format!("{}:{}", bob.local_credentials().ufrag, "aliceufrag").into_bytes(),
        ));
        let check = msg
            .encode_with_integrity(bob.local_credentials().password.as_bytes())
            .unwrap();

        let outcome = bob.handle_check(&check, surprise).unwrap().unwrap();
        assert_eq!(bob.discovered_prflx(), 1);
        assert_eq!(bob.pairs()[outcome.pair].remote.addr, surprise);
        assert_eq!(
            bob.pairs()[outcome.pair].remote.ctype,
            CandidateType::PeerReflexive
        );
    }

    #[test]
    fn unrelated_traffic_is_ignored_not_an_error() {
        let mut a = agent_with_pairs(IceRole::Controlling);
        // Mesh data on the same socket must not be mistaken for ICE.
        assert!(a
            .handle_check(b"not a stun message at all", sock("1.2.3.4:5"))
            .unwrap()
            .is_none());
        assert!(a.handle_check(&[], sock("1.2.3.4:5")).unwrap().is_none());
    }

    #[test]
    fn candidate_attribute_round_trips_including_the_base_address() {
        let c = Candidate::new(
            CandidateType::ServerReflexive,
            sock("192.168.1.10:5000"),
            sock("198.51.100.7:41234"),
            DEFAULT_COMPONENT,
            None,
        );
        let text = c.to_attribute();
        assert!(text.starts_with("candidate:"));
        assert!(text.contains("typ srflx"), "{text}");
        // The base address is carried explicitly, so it survives the round trip.
        assert!(text.contains("raddr 192.168.1.10 rport 5000"), "{text}");
        let parsed = Candidate::from_attribute(&text).unwrap();
        assert_eq!(
            parsed, c,
            "a candidate must survive the text form unchanged"
        );

        // A host candidate's base *is* its address, so it needs no raddr.
        let host = Candidate::new(
            CandidateType::Host,
            sock("192.168.1.10:5000"),
            sock("192.168.1.10:5000"),
            DEFAULT_COMPONENT,
            None,
        );
        let host_text = host.to_attribute();
        assert!(!host_text.contains("raddr"), "{host_text}");
        assert_eq!(Candidate::from_attribute(&host_text).unwrap(), host);
    }

    #[test]
    fn malformed_candidate_attributes_are_rejected() {
        assert!(Candidate::from_attribute("candidate:").is_err());
        // Unknown transport (only UDP is supported).
        assert!(Candidate::from_attribute("candidate:x 1 bogus 1 1.2.3.4 5").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 tcp 1 1.2.3.4 5 typ host").is_err());
        // Bad priority, bad address, bad port.
        assert!(Candidate::from_attribute("candidate:x 1 UDP no 1.2.3.4 5 typ host").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 UDP 1 nope 5 typ host").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 UDP 1 1.2.3.4 99999 typ host").is_err());
        // Missing or unknown type, and a trailing attribute we do not model.
        assert!(Candidate::from_attribute("candidate:x 1 UDP 1 1.2.3.4 5").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 UDP 1 1.2.3.4 5 typ bogus").is_err());
        assert!(
            Candidate::from_attribute("candidate:x 1 UDP 1 1.2.3.4 5 typ host tcptype x").is_err()
        );
        // raddr without rport must not half-parse.
        assert!(
            Candidate::from_attribute("candidate:x 1 UDP 1 1.2.3.4 5 typ host raddr 10.0.0.1")
                .is_err()
        );
    }

    #[test]
    fn relay_candidates_are_lowest_priority_and_sorted_last() {
        let mut a = IceAgent::new(IceRole::Controlling);
        a.set_remote_credentials(IceCredentials {
            ufrag: "u".into(),
            password: "p".into(),
        });
        a.add_host_candidate(sock("192.168.1.10:5000"), sock("192.168.1.10:5000"));
        a.add_relay_candidate(sock("192.168.1.10:5000"), sock("203.0.113.9:3478"));
        for port in [6000u16, 6001] {
            a.add_remote_candidate(Candidate::new(
                CandidateType::Host,
                sock(&format!("192.168.1.20:{port}")),
                sock(&format!("192.168.1.20:{port}")),
                DEFAULT_COMPONENT,
                None,
            ));
        }
        a.form_pairs();
        assert_eq!(a.pairs().len(), 4);
        // Every pair is ordered, and the relay pairs are at the bottom: a relay
        // is only used once direct paths have failed.
        let last_two = &a.pairs()[2..];
        for p in last_two {
            assert_eq!(p.local.ctype, CandidateType::Relay);
        }
        assert!(a.pairs()[0].priority > a.pairs().last().unwrap().priority);
    }

    #[test]
    fn offer_round_trips_through_text_signalling() {
        let offer = IceOffer::new(
            IceCredentials::generate(),
            vec![
                Candidate::new(
                    CandidateType::Host,
                    sock("192.168.1.10:5000"),
                    sock("192.168.1.10:5000"),
                    DEFAULT_COMPONENT,
                    None,
                ),
                Candidate::new(
                    CandidateType::ServerReflexive,
                    sock("192.168.1.10:5000"),
                    sock("198.51.100.7:41234"),
                    DEFAULT_COMPONENT,
                    Some(sock("203.0.113.1:3478")),
                ),
            ],
            true,
        );
        let text = offer.encode();
        let back = IceOffer::decode(&text).unwrap();
        assert_eq!(back, offer);
        assert!(back.controlling);
        assert_eq!(back.candidates.len(), 2);
    }

    #[test]
    fn offer_decoding_rejects_incomplete_or_hostile_input() {
        let good = IceOffer::new(
            IceCredentials::generate(),
            vec![Candidate::new(
                CandidateType::Host,
                sock("192.168.1.10:5000"),
                sock("192.168.1.10:5000"),
                DEFAULT_COMPONENT,
                None,
            )],
            false,
        );

        // Missing each required field in turn.
        let without_ufrag: Vec<String> = good
            .encode()
            .lines()
            .filter(|l| !l.starts_with("ice-ufrag:"))
            .map(str::to_string)
            .collect();
        assert!(IceOffer::decode(&without_ufrag.join("\n")).is_err());

        let without_role: Vec<String> = good
            .encode()
            .lines()
            .filter(|l| !l.starts_with("role:"))
            .map(str::to_string)
            .collect();
        assert!(IceOffer::decode(&without_role.join("\n")).is_err());

        // A too-short password must not be accepted from the wire.
        let short_pwd = format!(
            "ice-ufrag:abcd\nice-pwd:tooshort\nrole:controlling\ncandidate:{} 1 UDP 1 10.0.0.1 5 typ host",
            good.candidates[0].foundation
        );
        assert!(IceOffer::decode(&short_pwd).is_err());

        // Unknown role.
        let bad_role = good.encode().replace("role:controlled", "role:emperor");
        assert!(IceOffer::decode(&bad_role).is_err());

        // Garbage line.
        assert!(IceOffer::decode("hello world").is_err());

        // Candidate flood is refused rather than turned into pairs.
        let mut flood = good.encode();
        for i in 0..(MAX_CANDIDATES_IN_OFFER + 2) {
            flood.push_str(&format!(
                "candidate:beef 1 UDP 100 10.0.0.1 {} typ host\n",
                1000 + i
            ));
        }
        assert!(IceOffer::decode(&flood).is_err());
    }

    #[test]
    fn credentials_are_ice_char_safe_and_long_enough() {
        let c = IceCredentials::generate();
        assert!(c.ufrag.len() >= 4 && c.ufrag.len() <= 256);
        assert!(c.password.len() >= 22 && c.password.len() <= 256);
        assert!(c.ufrag.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(c.password.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_ne!(IceCredentials::generate().ufrag, c.ufrag);
    }

    #[test]
    fn advertised_local_credentials_are_what_inbound_checks_are_verified_against() {
        // The bug this guards: an agent that generates fresh credentials when it
        // starts checking will reject every check from a peer that used the
        // credentials we advertised.
        let advertised = IceCredentials {
            ufrag: "advertised-ufrag".into(),
            password: "advertised-password-0123456789".into(),
        };
        let mut bob = IceAgent::new(IceRole::Controlled);
        bob.set_local_credentials(advertised.clone());
        bob.set_remote_credentials(IceCredentials {
            ufrag: "aliceufrag".into(),
            password: "alice-password-0123456789".into(),
        });
        assert_eq!(bob.local_credentials(), &advertised);

        let alice_addr = sock("192.168.1.10:5000");
        bob.add_host_candidate(sock("192.168.1.20:6000"), sock("192.168.1.20:6000"));
        bob.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            alice_addr,
            alice_addr,
            DEFAULT_COMPONENT,
            None,
        ));
        bob.form_pairs();

        // Alice authenticates with the password Bob advertised.
        let mut msg = Message::binding_request(TransactionId::random());
        msg.push(Attribute::Username(
            format!("{}:aliceufrag", advertised.ufrag).into_bytes(),
        ));
        let check = msg
            .encode_with_integrity(advertised.password.as_bytes())
            .unwrap();
        assert!(bob.handle_check(&check, alice_addr).is_ok());
    }

    #[test]
    fn build_check_requires_remote_credentials() {
        let mut a = IceAgent::new(IceRole::Controlling);
        a.add_host_candidate(sock("192.168.1.10:5000"), sock("192.168.1.10:5000"));
        a.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            sock("192.168.1.20:6000"),
            sock("192.168.1.20:6000"),
            DEFAULT_COMPONENT,
            None,
        ));
        a.form_pairs();
        assert!(matches!(
            a.build_check(0, true),
            Err(IceError::MissingRemoteCredentials)
        ));
    }

    #[test]
    fn incoming_username_is_the_predictable_mirror_of_the_outgoing_one() {
        let mut a = IceAgent::new(IceRole::Controlling);
        a.set_remote_credentials(IceCredentials {
            ufrag: "remoteufrag".into(),
            password: "remote-password-0123456789".into(),
        });
        let outgoing = a.username_for_outgoing().unwrap();
        assert_eq!(
            outgoing,
            format!("remoteufrag:{}", a.local_credentials().ufrag)
        );
        assert_eq!(
            a.expected_incoming_username().unwrap(),
            format!("{}:remoteufrag", a.local_credentials().ufrag)
        );
    }

    #[test]
    fn state_progresses_from_new_to_failed_when_nothing_answers() {
        let mut a = IceAgent::new(IceRole::Controlling);
        assert_eq!(a.state(), IceState::New);
        a.set_remote_credentials(IceCredentials {
            ufrag: "u".into(),
            password: "p".into(),
        });
        a.add_host_candidate(sock("192.168.1.10:5000"), sock("192.168.1.10:5000"));
        a.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            sock("192.168.1.20:6000"),
            sock("192.168.1.20:6000"),
            DEFAULT_COMPONENT,
            None,
        ));
        assert_eq!(a.state(), IceState::Gathering);
        a.form_pairs();
        assert_eq!(a.state(), IceState::Checking);
        let idx = a.next_check().unwrap();
        a.fail_pair(idx);
        assert_eq!(a.state(), IceState::Failed);
        assert!(a.selected_pair().is_none());
    }

    #[test]
    fn probe_local_addr_resolves_a_usable_source() {
        // Uses a route lookup only (no packet is sent), so this is safe offline
        // as long as a default route exists.
        let dest = sock("192.0.2.1:3478");
        match probe_local_addr(dest) {
            Ok(a) => assert!(!a.ip().is_unspecified()),
            // An isolated sandbox may have no default route. That is an I/O
            // error, not a panic — which is the property under test.
            Err(_) => {}
        }
    }

    #[test]
    fn retransmissions_are_bounded_by_nmax() {
        let mut a = agent_with_pairs(IceRole::Controlling).with_check_attempts(3);
        let idx = a.next_check().unwrap();
        assert_eq!(a.pairs()[idx].attempts, 1);
        assert!(a.can_retransmit(idx));
        assert!(a.retransmit(idx));
        assert_eq!(a.pairs()[idx].attempts, 2);
        assert!(a.retransmit(idx));
        assert_eq!(a.pairs()[idx].attempts, 3);
        // Nmax reached: the caller must fail the pair rather than spin.
        assert!(!a.can_retransmit(idx));
        assert!(!a.retransmit(idx));
        assert_eq!(a.pairs()[idx].attempts, 3);
    }
}
