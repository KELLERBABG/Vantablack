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

pub const MAX_TRACKED_CHECKS: usize = 128;

pub const DEFAULT_COMPONENT: u16 = 1;

pub const DEFAULT_LOCAL_PREFERENCE: u16 = 65535;

pub const DEFAULT_RTO: Duration = Duration::from_millis(500);

pub const DEFAULT_CHECK_ATTEMPTS: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
}

impl CandidateType {
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

pub fn candidate_priority(ctype: CandidateType, local_preference: u16, component: u16) -> u32 {
    let component_term = 256u32.saturating_sub(component as u32);
    (ctype.preference() << 24) + ((local_preference as u32) << 8) + component_term
}

fn foundation(ctype: CandidateType, base: SocketAddr, stun_server: Option<SocketAddr>) -> String {
    let key = format!(
        "{}|{}|{}",
        ctype.as_str(),
        base.ip(),
        stun_server.map(|s| s.ip().to_string()).unwrap_or_default()
    );
    format!("{:08x}", stun::crc32_ieee(key.as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub foundation: String,
    pub component: u16,
    pub ctype: CandidateType,
    pub priority: u32,
    pub base: SocketAddr,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCredentials {
    pub ufrag: String,
    pub password: String,
}

impl IceCredentials {
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

pub const MAX_CANDIDATES_IN_OFFER: usize = 32;

impl IceCredentials {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceOffer {
    pub credentials: IceCredentials,
    pub candidates: Vec<Candidate>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    Frozen,
    Waiting,
    InProgress,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
    pub state: PairState,
    pub nominated: bool,
    pub priority: u64,
    pub attempts: u32,
    pub rtt: Option<Duration>,
}

impl CandidatePair {
    pub fn key(&self) -> (&SocketAddr, &SocketAddr) {
        (&self.local.base, &self.remote.addr)
    }
}

fn pair_priority_minmax(g: u32, d: u32) -> u64 {
    let (lo, hi) = if g < d { (g, d) } else { (d, g) };
    ((1u64 << 32).wrapping_mul(lo as u64))
        .wrapping_add((hi as u64).wrapping_mul(2))
        .wrapping_add(u64::from(g > d))
}

pub fn pair_priority_for(role: IceRole, local_priority: u32, remote_priority: u32) -> u64 {
    match role {
        IceRole::Controlling => pair_priority_minmax(local_priority, remote_priority),
        IceRole::Controlled => pair_priority_minmax(remote_priority, local_priority),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    New,
    Gathering,
    Checking,
    Connected,
    Failed,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    pub pair: usize,
    pub response: Option<Vec<u8>>,
    pub nominated: bool,
    pub role_flipped: bool,
    pub completed_our_check: Option<Duration>,
}

pub struct IceAgent {
    role: IceRole,
    tie_breaker: u64,
    local_credentials: IceCredentials,
    remote_credentials: Option<IceCredentials>,
    local_candidates: Vec<Candidate>,
    remote_candidates: Vec<Candidate>,
    pairs: Vec<CandidatePair>,
    nominated: Option<usize>,
    retransmit_attempts: u32,
    discovered_prflx: u32,
    checks_sent: HashMap<TransactionId, (usize, SocketAddr, Instant)>,
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

    pub fn set_remote_credentials(&mut self, creds: IceCredentials) {
        self.remote_credentials = Some(creds);
    }

    pub fn set_local_credentials(&mut self, creds: IceCredentials) {
        self.local_credentials = creds;
    }

    pub fn set_remote_role(&mut self, role: IceRole) {
        self.role = role.other();
    }

    pub fn local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    pub fn remote_candidates(&self) -> &[Candidate] {
        &self.remote_candidates
    }

    pub fn discovered_prflx(&self) -> u32 {
        self.discovered_prflx
    }

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

    pub async fn gather_reflexive(
        &mut self,
        sock: &tokio::net::UdpSocket,
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<Candidate, IceError> {
        self.gather_reflexive_with(sock, server, timeout, |_, _| {})
            .await
    }

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
            if let Some(c) =
                self.try_complete_reflexive(&buf[..n], from, server, txid, sock.local_addr()?)
            {
                return Ok(c);
            }
            on_other(&buf[..n], from);
        }
    }

    pub async fn gather_reflexive_mux(
        &mut self,
        sock: &tokio::net::UdpSocket,
        server: SocketAddr,
        timeout: Duration,
        rx: &mut tokio::sync::broadcast::Receiver<(Vec<u8>, SocketAddr)>,
    ) -> Result<Candidate, IceError> {
        let txid = TransactionId::random();
        let request = Message::binding_request(txid).encode();
        sock.send_to(&request, server).await?;

        let deadline = tokio::time::Instant::now() + timeout;
        let base = sock.local_addr()?;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                warn!(server = %server, "ICE: STUN binding request timed out");
                return Err(IceError::GatherTimeout);
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Err(_) => return Err(IceError::GatherTimeout),
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                    return Err(IceError::GatherTimeout);
                }
                Ok(Ok((pkt, from))) => {
                    if let Some(c) = self.try_complete_reflexive(&pkt, from, server, txid, base) {
                        return Ok(c);
                    }
                }
            }
        }
    }

    fn try_complete_reflexive(
        &mut self,
        pkt: &[u8],
        from: SocketAddr,
        server: SocketAddr,
        txid: TransactionId,
        base: SocketAddr,
    ) -> Option<Candidate> {
        if from != server {
            return None;
        }
        let msg = Message::parse(pkt).ok()?;
        if msg.txid != txid
            || msg.typ.method() != Method::BINDING
            || msg.typ.class() != Class::SuccessResponse
        {
            return None;
        }
        match stun::verify_fingerprint(pkt) {
            Ok(()) | Err(stun::StunError::MissingFingerprint) => {}
            Err(_) => {
                debug!(from = %from, "ICE: STUN response failed FINGERPRINT");
                return None;
            }
        }
        let mapped = msg.xor_mapped_address()?;
        let c = self.add_server_reflexive_candidate(base, mapped, Some(server));
        info!(public = %mapped, "ICE: server-reflexive candidate discovered");
        Some(c)
    }

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

    pub fn add_remote_candidate(&mut self, c: Candidate) {
        self.remote_candidates.push(c);
    }

    pub fn add_remote_candidate_attribute(&mut self, value: &str) -> Result<Candidate, IceError> {
        let c = Candidate::from_attribute(value)?;
        self.remote_candidates.push(c.clone());
        Ok(c)
    }

    pub fn pairs(&self) -> &[CandidatePair] {
        &self.pairs
    }

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
        pairs.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.remote.addr.cmp(&b.remote.addr))
        });

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
        self.checks_sent.clear();
        self.check_order.clear();
    }

    pub fn next_check(&mut self) -> Option<usize> {
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
        self.pairs[idx].attempts = self.pairs[idx].attempts.saturating_add(1);
        Some(idx)
    }

    pub fn fail_pair(&mut self, idx: usize) {
        if let Some(p) = self.pairs.get_mut(idx) {
            p.state = PairState::Failed;
        }
    }

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

    pub fn selected_pair(&self) -> Option<&CandidatePair> {
        let idx = self.nominated?;
        let p = self.pairs.get(idx)?;
        if p.state == PairState::Succeeded {
            Some(p)
        } else {
            None
        }
    }

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

    fn track_check(&mut self, txid: TransactionId, idx: usize, base: SocketAddr) {
        self.checks_sent.insert(txid, (idx, base, Instant::now()));
        self.check_order.push_back(txid);
        while self.check_order.len() > MAX_TRACKED_CHECKS {
            if let Some(old) = self.check_order.pop_front() {
                self.checks_sent.remove(&old);
            }
        }
    }

    pub fn selected_pair_rtt(&self) -> Option<Duration> {
        self.selected_pair().and_then(|p| p.rtt)
    }

    pub fn build_triggered_check(&mut self, idx: usize) -> Result<Vec<u8>, IceError> {
        self.build_check(idx, false)
    }

    pub fn can_retransmit(&self, idx: usize) -> bool {
        self.pairs
            .get(idx)
            .map(|p| p.attempts < self.retransmit_attempts)
            .unwrap_or(false)
    }

    pub fn retransmit(&mut self, idx: usize) -> bool {
        if !self.can_retransmit(idx) {
            return false;
        }
        if let Some(p) = self.pairs.get_mut(idx) {
            p.attempts = p.attempts.saturating_add(1);
        }
        true
    }

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
            Class::Request => {
                if let (Some(Attribute::Username(u)), Some(expected)) =
                    (msg.get(0x0006), self.expected_incoming_username())
                {
                    if u.as_slice() != expected.as_bytes() {
                        return Ok(None);
                    }
                }
                self.handle_request(raw, &msg, from).map(Some)
            }
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
        if stun::verify_integrity(raw, self.local_credentials.password.as_bytes()).is_err() {
            warn!(from = %from, "ICE: dropping unauthenticated check");
            return Err(IceError::Stun(stun::StunError::BadIntegrity));
        }

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
            self.form_pairs();
        }

        let nominated_by_peer = msg.get(0x0025).is_some();

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
                self.discovered_prflx = self.discovered_prflx.saturating_add(1);
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
                self.pairs.len().saturating_sub(1)
            }
        };

        if let Some(p) = self.pairs.get_mut(pair_idx) {
            p.state = PairState::Succeeded;
        }
        if nominated_by_peer {
            let _ = self.nominate(pair_idx);
        }

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
        let measured = self
            .checks_sent
            .remove(&msg.txid)
            .map(|(sent_idx, base, at)| (sent_idx, base, at.elapsed()));
        let idx = match measured {
            Some((sent_idx, _, _)) if sent_idx < self.pairs.len() => Some(sent_idx),
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

    pub fn expected_incoming_username(&self) -> Option<String> {
        let remote = self.remote_credentials.as_ref()?;
        Some(format!("{}:{}", self.local_credentials.ufrag, remote.ufrag))
    }
}

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
        let host = candidate_priority(CandidateType::Host, 65535, 1);
        assert_eq!(host, (126 << 24) + (65535 << 8) + 255);
        let srflx = candidate_priority(CandidateType::ServerReflexive, 65535, 1);
        let relay = candidate_priority(CandidateType::Relay, 65535, 1);
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
        let b = Candidate::new(
            CandidateType::ServerReflexive,
            sock("192.168.1.10:5000"),
            sock("198.51.100.1:40001"),
            DEFAULT_COMPONENT,
            Some(stun),
        );
        assert_eq!(a.foundation, b.foundation);

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
        assert_eq!(pair_priority_minmax(100, 200), (1u64 << 32) * 100 + 400);
        assert_eq!(pair_priority_minmax(200, 100), (1u64 << 32) * 100 + 400 + 1);
    }

    #[test]
    fn controlling_and_controlled_agree_on_pair_priority() {
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
        assert!(a.pairs()[0].priority >= a.pairs()[1].priority);
        assert_eq!(a.pairs()[0].state, PairState::Waiting);
        assert_eq!(a.pairs()[1].state, PairState::Frozen);
    }

    #[test]
    fn next_check_promotes_frozen_siblings_only_after_failure() {
        let mut a = agent_with_pairs(IceRole::Controlling);
        let first = a.next_check().expect("a waiting pair");
        assert_eq!(a.pairs()[first].state, PairState::InProgress);
        assert_eq!(a.pairs()[first].attempts, 1);

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

        let idx = alice.next_check().unwrap();
        let check = alice.build_check(idx, true).unwrap();

        let outcome = bob
            .handle_check(&check, alice_addr)
            .unwrap()
            .expect("bob must treat this as a check");
        assert!(outcome.nominated, "USE-CANDIDATE must propagate");
        assert!(bob.selected_pair().is_some(), "bob must nominate the pair");
        let response = outcome.response.expect("a request is answered");

        let reply = alice
            .handle_check(&response, bob_addr)
            .unwrap()
            .expect("alice must match the response to her check");
        assert_eq!(reply.pair, idx);
        assert!(alice.selected_pair().is_some());
        assert_eq!(alice.state(), IceState::Connected);
        assert_eq!(bob.state(), IceState::Connected);

        let rtt = alice
            .selected_pair_rtt()
            .expect("a completed check must yield a measured RTT");
        assert!(rtt < Duration::from_secs(5), "implausible RTT {rtt:?}");
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
        assert!(text.contains("raddr 192.168.1.10 rport 5000"), "{text}");
        let parsed = Candidate::from_attribute(&text).unwrap();
        assert_eq!(
            parsed, c,
            "a candidate must survive the text form unchanged"
        );

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
        assert!(Candidate::from_attribute("candidate:x 1 bogus 1 1.2.3.4 5").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 tcp 1 1.2.3.4 5 typ host").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 UDP no 1.2.3.4 5 typ host").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 UDP 1 nope 5 typ host").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 UDP 1 1.2.3.4 99999 typ host").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 UDP 1 1.2.3.4 5").is_err());
        assert!(Candidate::from_attribute("candidate:x 1 UDP 1 1.2.3.4 5 typ bogus").is_err());
        assert!(
            Candidate::from_attribute("candidate:x 1 UDP 1 1.2.3.4 5 typ host tcptype x").is_err()
        );
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

        let short_pwd = format!(
            "ice-ufrag:abcd\nice-pwd:tooshort\nrole:controlling\ncandidate:{} 1 UDP 1 10.0.0.1 5 typ host",
            good.candidates[0].foundation
        );
        assert!(IceOffer::decode(&short_pwd).is_err());

        let bad_role = good.encode().replace("role:controlled", "role:emperor");
        assert!(IceOffer::decode(&bad_role).is_err());

        assert!(IceOffer::decode("hello world").is_err());

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
        let dest = sock("192.0.2.1:3478");
        if let Ok(a) = probe_local_addr(dest) {
            assert!(!a.ip().is_unspecified());
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
        assert!(!a.can_retransmit(idx));
        assert!(!a.retransmit(idx));
        assert_eq!(a.pairs()[idx].attempts, 3);
    }

    #[test]
    fn mismatched_username_request_is_ignored_on_shared_mux() {
        let mut bob = agent_with_pairs(IceRole::Controlled);
        let other_addr = sock("203.0.113.88:5555");
        let mut msg = Message::binding_request(TransactionId::random());
        msg.push(Attribute::Username(
            format!("{}:charlieufrag", bob.local_credentials().ufrag).into_bytes(),
        ));
        let check = msg
            .encode_with_integrity(bob.local_credentials().password.as_bytes())
            .unwrap();
        assert!(bob.handle_check(&check, other_addr).unwrap().is_none());
        assert_eq!(bob.discovered_prflx(), 0);
    }

    #[tokio::test]
    async fn gather_reflexive_mux_receives_stun_response_via_channel() {
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let server_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();

        let (tx, mut rx) = tokio::sync::broadcast::channel::<(Vec<u8>, SocketAddr)>(16);
        let mapped: SocketAddr = "198.51.100.42:51234".parse().unwrap();

        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = server_sock.recv_from(&mut buf).await.unwrap();
            let req = Message::parse(&buf[..n]).unwrap();
            let resp = Message::binding_success(req.txid, mapped).encode();
            let _ = tx.send((resp, server_addr));
            assert_eq!(from, client_addr);
        });

        let mut agent = IceAgent::new(IceRole::Controlling);
        let cand = agent
            .gather_reflexive_mux(&client_sock, server_addr, Duration::from_secs(2), &mut rx)
            .await
            .expect("muxed STUN reflexive response should succeed");
        assert_eq!(cand.addr, mapped);
        assert_eq!(cand.ctype, CandidateType::ServerReflexive);
        srv.await.unwrap();
    }
}
