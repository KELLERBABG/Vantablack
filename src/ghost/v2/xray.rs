//! Adversary Goggles — the truth ledger.
//!
//! A privacy product that says "anonymous" in a badge has made a claim it cannot
//! check. This module builds the opposite: a per-view description of what each
//! observer can actually see, plus invariants that are **evaluated** against the
//! live node rather than asserted in a marketing page.
//!
//! The rules are deliberately unflattering:
//!
//! * no anonymity claim below 200 live public relays (roadmap item 8), and never
//!   from a regime that is not [`Regime::Vantablack`];
//! * a strict circuit with fewer hops than configured is a failure, not a
//!   footnote;
//! * anything the node cannot measure is `Unknown`, never `Verified`. A ledger
//!   that treats "we didn't look" as a pass is worse than no ledger.
//!
//! [`TruthLedger::headline`] is what the dashboard shows at the top. It is
//! derived from the invariants, so a failing check necessarily changes the
//! headline.

use crate::ghost::net::discovery::CAP_RELAY;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use super::regime::{effective_population, Plane, Regime, MIN_ANONYMITY_RELAYS};

/// A peer whose signed descriptor verified, kept only for the ledger.
#[derive(Debug, Clone)]
pub struct PeerWitness {
    pub fingerprint: String,
    pub capabilities: u8,
    /// Routing-domain cluster the endpoint falls in (`/24` v4, `/48` v6).
    pub domain: String,
    pub seen_at: u64,
}

/// Descriptors older than this are not evidence of a live relay.
const PEER_WITNESS_TTL_SECS: u64 = 7 * 86_400;

fn witnesses() -> &'static RwLock<HashMap<String, PeerWitness>> {
    static W: OnceLock<RwLock<HashMap<String, PeerWitness>>> = OnceLock::new();
    W.get_or_init(|| RwLock::new(HashMap::new()))
}

/// The routing-domain cluster of an endpoint: `/24` for IPv4, `/48` for IPv6.
///
/// This is a *proxy* for an administrative domain, not an ASN: the descriptor
/// does not carry one. It still defeats the concrete Sybil shape the ledger is
/// guarding against — many addresses on one host or one small allocation — and
/// the field is labelled as a subnet cluster wherever it is reported.
pub fn domain_cluster(endpoint: &str) -> String {
    use std::net::IpAddr;
    let host = endpoint
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(['[', ']']))
        .unwrap_or(endpoint);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let o = ip.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(IpAddr::V6(ip)) => {
            let s = ip.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        Err(_) => format!("unparsed:{endpoint}"),
    }
}

/// Record (or refresh) a peer whose signed descriptor verified.
///
/// Called from the descriptor install path, so a peer only enters this registry
/// after its signature and freshness checked out.
pub fn note_verified_peer(fingerprint: &str, capabilities: u8, endpoint: &str) {
    let mut reg = witnesses().write().unwrap_or_else(|e| e.into_inner());
    reg.insert(
        fingerprint.to_string(),
        PeerWitness {
            fingerprint: fingerprint.to_string(),
            capabilities,
            domain: domain_cluster(endpoint),
            seen_at: super::now_secs(),
        },
    );
}

/// Drop a peer that disconnected or withdrew its descriptor.
pub fn forget_verified_peer(fingerprint: &str) {
    witnesses()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(fingerprint);
}

#[derive(Default)]
struct NonceEchoState {
    pending: std::collections::HashMap<[u8; 16], u64>,
    last_verified: Option<(u8, u64)>,
}

fn nonce_echo_state() -> &'static std::sync::Mutex<NonceEchoState> {
    static STATE: std::sync::OnceLock<std::sync::Mutex<NonceEchoState>> =
        std::sync::OnceLock::new();
    STATE.get_or_init(|| std::sync::Mutex::new(NonceEchoState::default()))
}

/// Canonical domain-separated signing input for a signed nonce-echo witness.
pub fn nonce_echo_signing_input(nonce: &[u8; 16], hops: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 16 + 1);
    out.extend_from_slice(b"VB-NONCE-ECHO-V1");
    out.extend_from_slice(nonce);
    out.push(hops);
    out
}

/// Issue a fresh 16-byte nonce challenge for an active circuit/session.
pub fn issue_nonce_challenge() -> [u8; 16] {
    let nonce: [u8; 16] = rand::random();
    let now = super::now_secs();
    let mut st = nonce_echo_state().lock().unwrap_or_else(|e| e.into_inner());
    st.pending.retain(|_, ts| now.saturating_sub(*ts) <= 120);
    if st.pending.len() >= 64 {
        st.pending.clear();
    }
    st.pending.insert(nonce, now);
    nonce
}

/// Verify a peer's Ed25519 signature over an outstanding nonce challenge and record the hop count.
pub fn verify_nonce_echo(
    nonce: &[u8; 16],
    signer_pk: &[u8; 32],
    sig_bytes: &[u8; 64],
    hops: u8,
) -> bool {
    let now = super::now_secs();
    {
        let mut st = nonce_echo_state().lock().unwrap_or_else(|e| e.into_inner());
        let Some(issued_at) = st.pending.remove(nonce) else {
            return false;
        };
        if now.saturating_sub(issued_at) > 120 {
            return false;
        }
    }
    let msg = nonce_echo_signing_input(nonce, hops);
    if !crate::ghost::layers::l0_identity::verify_peer_signature(signer_pk, &msg, sig_bytes) {
        return false;
    }
    let mut st = nonce_echo_state().lock().unwrap_or_else(|e| e.into_inner());
    st.last_verified = Some((hops, now));
    true
}

/// Hop count of the latest verified signed nonce-echo witness (stale after 300s -> `None`).
pub fn last_nonce_echo_hops() -> Option<u8> {
    let now = super::now_secs();
    let st = nonce_echo_state().lock().unwrap_or_else(|e| e.into_inner());
    st.last_verified
        .and_then(|(hops, ts)| (now.saturating_sub(ts) <= 300).then_some(hops))
}

fn live_witnesses() -> Vec<PeerWitness> {
    let now = super::now_secs();
    let reg = witnesses().read().unwrap_or_else(|e| e.into_inner());
    reg.values()
        .filter(|w| now.saturating_sub(w.seen_at) <= PEER_WITNESS_TTL_SECS)
        .cloned()
        .collect()
}

/// Every unexpired verified peer, for tests and diagnostics.
pub fn verified_peers() -> Vec<PeerWitness> {
    live_witnesses()
}

/// Verified peers advertising `CAP_RELAY`.
pub fn cap_relay_verified() -> usize {
    live_witnesses()
        .iter()
        .filter(|w| w.capabilities & CAP_RELAY != 0)
        .count()
}

/// One consistent snapshot of the verified `CAP_RELAY` population and its
/// routing-domain groups.
///
/// Both numbers are taken from the same read of the registry, so the ledger can
/// never report a population and a grouping that describe different sets.
pub fn relay_population() -> (usize, Vec<usize>) {
    let peers: Vec<PeerWitness> = live_witnesses()
        .into_iter()
        .filter(|w| w.capabilities & CAP_RELAY != 0)
        .collect();
    let mut groups: HashMap<String, usize> = HashMap::new();
    for peer in &peers {
        *groups.entry(peer.domain.clone()).or_default() += 1;
    }
    (peers.len(), groups.into_values().collect())
}

/// Verified `CAP_RELAY` peers, grouped by routing-domain cluster.
pub fn relay_domains() -> Vec<usize> {
    relay_population().1
}

/// State of one invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Verified,
    Failed,
    Unknown,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Verified => "verified",
            State::Failed => "failed",
            State::Unknown => "unknown",
        }
    }
}

/// One checkable property of the running node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Invariant {
    pub id: &'static str,
    pub state: State,
    /// What was checked, in plain language.
    pub detail: String,
}

/// Everything the ledger needs from the running node. Fields are `Option` so a
/// headless build can say "not measured" instead of inventing a value.
#[derive(Debug, Clone, Default)]
pub struct LedgerInput {
    pub regime: Option<Regime>,
    /// Live public relays the node can see. `None` means the node has not looked.
    pub public_relays: Option<usize>,
    /// Hops actually in the circuit in use.
    pub circuit_hops: Option<u8>,
    /// Distinct autonomous systems among the circuit's hops.
    pub circuit_asns: Option<usize>,
    pub transport: Option<String>,
    /// The SNI an observer of the outer connection would read.
    pub outer_sni: Option<String>,
    /// The address a website sees, if the node is exiting.
    pub exit_ip: Option<String>,
    /// Cover frames actually emitted by this process, from the RACS counters.
    /// `None` means the emitter has not reported; `Some(0)` is a real failure.
    pub cover_tx: Option<u64>,
    /// Whether DNS queries are known to bypass the mesh.
    pub dns_leak: Option<bool>,
    /// `true` when the handshake used the hybrid PQ suite.
    pub pq_hybrid: Option<bool>,
    /// Active ACK pacing state, from [`super::chronos`].
    pub clock_consistent: Option<bool>,
    /// Peers whose `CAP_RELAY` bit was verified against their signed descriptor.
    /// Raw connected-peer counts do not count: a peer that advertises nothing
    /// may simply be dropping every circuit we hand it.
    pub cap_relay_verified: Option<usize>,
    /// Hop count of the last completed signed nonce echo. `None` when no
    /// circuit has answered the witness, which is the common case and is
    /// reported as unmeasured rather than assumed.
    pub nonce_echo_hops: Option<u8>,
    /// Relay counts grouped by administrative domain (ASN / subnet cluster).
    /// Without this, a raw relay count is not an effective population.
    pub relay_domains: Option<Vec<usize>>,
}

/// One observer's view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observation {
    /// "Your ISP", "The guard", "The website".
    pub observer: String,
    pub sees: Vec<String>,
    pub does_not_see: Vec<String>,
}

/// The full ledger, ready for JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TruthLedger {
    pub headline: String,
    /// The strongest sentence this node is allowed to say about itself.
    pub claim: String,
    pub regime: String,
    pub plane: String,
    pub observations: Vec<Observation>,
    pub invariants: Vec<Invariant>,
    pub generated_at: u64,
}

impl TruthLedger {
    pub fn headline(&self) -> &str {
        &self.headline
    }

    pub fn failed(&self) -> impl Iterator<Item = &Invariant> {
        self.invariants.iter().filter(|i| i.state == State::Failed)
    }

    pub fn all_verified(&self) -> bool {
        !self.invariants.is_empty() && self.invariants.iter().all(|i| i.state == State::Verified)
    }
}

fn inv(id: &'static str, state: State, detail: impl Into<String>) -> Invariant {
    Invariant {
        id,
        state,
        detail: detail.into(),
    }
}

/// Build the ledger from live measurements.
pub fn build(input: &LedgerInput) -> TruthLedger {
    let regime = input.regime.unwrap_or(Regime::Ghost);
    let plane = regime.plane();
    let relays = input.public_relays;
    // Rényi-2 collision entropy over administrative domains: N_eff is what
    // decides whether "200 relays" means 200 independent operators or one VPS
    // with 200 addresses.
    let neff = input
        .relay_domains
        .as_deref()
        .filter(|groups| !groups.is_empty())
        .map(effective_population)
        .map(|n| n.round() as usize);

    // ── Invariants ──────────────────────────────────────────────────────
    let mut invariants = Vec::with_capacity(12);

    invariants.push(match input.pq_hybrid {
        Some(true) => inv(
            "pq_hybrid_handshake",
            State::Verified,
            "handshake used X25519 + ML-KEM-768 (hybrid)",
        ),
        Some(false) => inv(
            "pq_hybrid_handshake",
            State::Failed,
            "handshake fell back to a classical-only suite",
        ),
        None => inv(
            "pq_hybrid_handshake",
            State::Unknown,
            "no session handshake has completed in this process",
        ),
    });

    let required_hops = regime.hops().hops();
    invariants.push(match input.circuit_hops {
        Some(n) if n >= required_hops => inv(
            "circuit_length",
            State::Verified,
            format!("{n} hops, {required_hops} required by {}", regime.as_str()),
        ),
        Some(n) => inv(
            "circuit_length",
            State::Failed,
            format!(
                "{n} hops in use but {} requires {required_hops}",
                regime.as_str()
            ),
        ),
        None => inv(
            "circuit_length",
            State::Unknown,
            "no circuit is established",
        ),
    });

    // The witnesses below are the difference between "the regime asked for
    // cover and three hops" and "the node measured cover and three hops".
    if plane == Plane::Umbra {
        invariants.push(match input.cap_relay_verified {
            Some(n) if n >= required_hops as usize => inv(
                "relay_capability",
                State::Verified,
                format!("{n} peers verified CAP_RELAY, {required_hops} required"),
            ),
            Some(n) => inv(
                "relay_capability",
                State::Failed,
                format!(
                    "only {n} peers verified CAP_RELAY; {} needs {required_hops}",
                    regime.as_str()
                ),
            ),
            None => inv(
                "relay_capability",
                State::Unknown,
                "CAP_RELAY not verified against signed peer descriptors",
            ),
        });
        invariants.push(match input.nonce_echo_hops {
            Some(n) if n >= required_hops => inv(
                "nonce_echo",
                State::Verified,
                format!("{n}-hop signed nonce echo returned within the horizon"),
            ),
            Some(n) => inv(
                "nonce_echo",
                State::Failed,
                format!("signed nonce echo reached {n} of {required_hops} hops"),
            ),
            None => inv(
                "nonce_echo",
                State::Unknown,
                "no signed nonce echo witness for a live circuit",
            ),
        });
    }

    if regime.requires_asn_diversity() {
        invariants.push(match input.circuit_asns {
            Some(n) if n >= required_hops as usize => inv(
                "asn_diversity",
                State::Verified,
                format!("{n} distinct networks across {required_hops} hops"),
            ),
            Some(n) => inv(
                "asn_diversity",
                State::Failed,
                format!("{n} distinct networks across {required_hops} hops — not independent"),
            ),
            None => inv(
                "asn_diversity",
                State::Unknown,
                "network diversity not measured",
            ),
        });
    }

    // The population check applies to a public anonymity plane whether or not
    // the regime is allowed to claim anonymity: it is the difference between
    // "hidden among users" and "alone in a bucket".
    if plane == Plane::Umbra {
        invariants.push(match (relays, neff) {
            (Some(n), Some(e)) if e >= MIN_ANONYMITY_RELAYS => inv(
                "relay_population",
                State::Verified,
                format!(
                    "{e} independent relays (N_eff) among {n} reachable (floor {MIN_ANONYMITY_RELAYS})"
                ),
            ),
            (Some(n), Some(e)) => inv(
                "relay_population",
                State::Failed,
                format!(
                    "{e} independent relays (N_eff) among {n} reachable; anonymity needs at least {MIN_ANONYMITY_RELAYS}"
                ),
            ),
            (Some(n), None) => inv(
                "relay_population",
                State::Unknown,
                format!(
                    "{n} relays reachable, but their administrative domains are unmeasured, so N_eff is unknown"
                ),
            ),
            (None, _) => inv(
                "relay_population",
                State::Unknown,
                "public relay count not measured",
            ),
        });
    }

    invariants.push(match input.dns_leak {
        Some(false) => inv(
            "dns_path",
            State::Verified,
            "DNS resolution goes through the mesh",
        ),
        Some(true) => inv(
            "dns_path",
            State::Failed,
            "DNS queries leave directly — the resolver sees every name",
        ),
        None => inv("dns_path", State::Unknown, "DNS path not measured"),
    });

    if regime.cover_traffic() {
        invariants.push(match input.cover_tx {
            Some(n) if n > 0 => inv(
                "cover_traffic",
                State::Verified,
                format!("{n} cover frames emitted by this process"),
            ),
            Some(_) => inv(
                "cover_traffic",
                State::Failed,
                format!(
                    "{} requires cover traffic but the emitter reports none",
                    regime.as_str()
                ),
            ),
            None => inv(
                "cover_traffic",
                State::Unknown,
                "cover traffic emission not measured",
            ),
        });
    }

    if let Some(consistent) = input.clock_consistent {
        invariants.push(inv(
            "layer_clocks",
            if consistent {
                State::Verified
            } else {
                State::Failed
            },
            if consistent {
                "outer transport RTT matches the inner circuit".to_string()
            } else {
                "outer RTT and circuit RTT diverge — a cross-layer classifier can see the relay"
                    .to_string()
            },
        ));
    }

    // ── Claim ───────────────────────────────────────────────────────────
    let failed = invariants
        .iter()
        .filter(|i| i.state == State::Failed)
        .count();
    let unknown = invariants
        .iter()
        .filter(|i| i.state == State::Unknown)
        .count();

    let claim = if !regime.anonymity_claim_allowed() {
        format!(
            "{} ({}) — no anonymity claim",
            regime.as_str(),
            plane.as_str()
        )
    } else if failed > 0 || unknown > 0 {
        "Vantablack — anonymity claim withheld while a check fails or is unmeasured".to_string()
    } else {
        format!(
            "anonymous among {} independent public relays",
            neff.unwrap_or(0)
        )
    };

    let headline = if failed > 0 {
        format!(
            "{} {} check{} failing — {}",
            failed,
            "invariant",
            if failed == 1 { " is" } else { "s are" },
            claim
        )
    } else if unknown > 0 {
        format!(
            "{} check{} unmeasured — {claim}",
            unknown,
            if unknown == 1 { " is" } else { "s are" }
        )
    } else {
        claim.clone()
    };

    // ── Observer views ──────────────────────────────────────────────────
    let mut isp_sees = vec![
        match input.transport.as_deref() {
            Some("quic") => "one QUIC/HTTP-3 flow to a single address".to_string(),
            Some("webrtc") => "a WebRTC media session (DTLS-SRTP)".to_string(),
            Some("tls") => "a TLS 1.3 connection to one host".to_string(),
            Some(other) => format!("one UDP flow ({other}) to a single address"),
            None => "one encrypted flow".to_string(),
        },
        if input.clock_consistent == Some(true) {
            "an outer RTT that matches the circuit's"
        } else {
            "an outer RTT that may not match the circuit's"
        }
        .to_string(),
    ];
    if let Some(sni) = &input.outer_sni {
        isp_sees.push(format!("the server name indicator: {sni}"));
    }
    let mut isp_not = vec![
        "which sites you visit inside the circuit".to_string(),
        "the contents of any frame".to_string(),
    ];
    if plane == Plane::Umbra {
        isp_not.push("your exit address or the sites it reaches".to_string());
    }
    if input.dns_leak == Some(false) {
        isp_not.push("the names you resolve".to_string());
    }

    let mut guard_sees = vec![format!(
        "{} hop{}",
        input.circuit_hops.unwrap_or(0),
        if input.circuit_hops == Some(1) {
            ""
        } else {
            "s"
        }
    )];
    if input.public_relays.is_some() {
        guard_sees.push(format!(
            "a relay population of {}",
            input.public_relays.unwrap_or(0)
        ));
    }
    let guard_not = vec![
        "the destination, unless it is the exit".to_string(),
        "plaintext or long-term keys".to_string(),
    ];

    let website = match (&input.exit_ip, plane) {
        (Some(ip), _) => vec![
            format!("the exit address {ip}"),
            "your normal TLS fingerprint".to_string(),
        ],
        (None, Plane::Umbra) => vec!["the exit node's address, not yours".to_string()],
        (None, Plane::Phantom) => {
            vec!["your own address — this plane does not hide it".to_string()]
        }
    };

    TruthLedger {
        headline,
        claim,
        regime: regime.as_str().to_string(),
        plane: plane.as_str().to_string(),
        observations: vec![
            Observation {
                observer: "Your ISP".to_string(),
                sees: isp_sees,
                does_not_see: isp_not,
            },
            Observation {
                observer: "The guard relay".to_string(),
                sees: guard_sees,
                does_not_see: guard_not,
            },
            Observation {
                observer: "The website".to_string(),
                sees: website,
                does_not_see: vec!["your identity".to_string(), "where you are".to_string()],
            },
        ],
        invariants,
        generated_at: super::now_secs(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified_input() -> LedgerInput {
        LedgerInput {
            regime: Some(Regime::Vantablack),
            public_relays: Some(500),
            circuit_hops: Some(3),
            circuit_asns: Some(3),
            transport: Some("quic".into()),
            outer_sni: Some("cdn.example".into()),
            exit_ip: None,
            cover_tx: Some(1_024),
            dns_leak: Some(false),
            pq_hybrid: Some(true),
            clock_consistent: Some(true),
            cap_relay_verified: Some(3),
            nonce_echo_hops: Some(3),
            relay_domains: Some(vec![1; 500]),
        }
    }

    #[test]
    fn a_fully_measured_vantablack_node_may_claim_anonymity() {
        let ledger = build(&verified_input());
        assert!(ledger.all_verified(), "{:?}", ledger.invariants);
        assert_eq!(
            ledger.claim,
            "anonymous among 500 independent public relays"
        );
        assert!(!ledger.headline().contains("FAIL"));
    }

    #[test]
    fn too_few_relays_downgrades_the_headline() {
        let mut input = verified_input();
        input.public_relays = Some(12);
        input.relay_domains = Some(vec![1; 12]);
        let ledger = build(&input);
        assert!(ledger.claim.contains("withheld"));
        assert!(ledger.headline().contains("failing"));
        assert!(ledger
            .invariants
            .iter()
            .any(|i| i.id == "relay_population" && i.state == State::Failed));
    }

    #[test]
    fn ghost_never_claims_anonymity_even_with_a_huge_population() {
        let mut input = verified_input();
        input.regime = Some(Regime::Ghost);
        input.circuit_asns = None; // ghost does not require diversity
        let ledger = build(&input);
        assert_eq!(ledger.claim, "ghost (umbra) — no anonymity claim");
    }

    #[test]
    fn unmeasured_is_not_a_pass() {
        let ledger = build(&LedgerInput {
            regime: Some(Regime::Vantablack),
            ..Default::default()
        });
        assert!(ledger.invariants.iter().any(|i| i.state == State::Unknown));
        assert!(!ledger.all_verified());
        assert!(ledger.claim.contains("withheld"));
        assert!(ledger.headline().contains("unmeasured"));
    }

    #[test]
    fn dns_leak_and_missing_cover_are_failures() {
        let mut input = verified_input();
        input.dns_leak = Some(true);
        input.cover_tx = Some(0);
        let ledger = build(&input);
        let failed: Vec<&str> = ledger.failed().map(|i| i.id).collect();
        assert!(failed.contains(&"dns_path"));
        assert!(failed.contains(&"cover_traffic"));
    }

    #[test]
    fn a_domain_cluster_is_a_subnet_not_an_address() {
        assert_eq!(domain_cluster("192.0.2.10:2270"), "192.0.2.0/24");
        assert_eq!(domain_cluster("192.0.2.11:2270"), "192.0.2.0/24");
        assert_eq!(domain_cluster("198.51.100.7:2270"), "198.51.100.0/24");
        assert_eq!(domain_cluster("[2001:db8:1::5]:2270"), "2001:db8:1::/48");
    }

    #[test]
    fn the_verified_registry_is_the_source_of_the_population() {
        // Unique fingerprint: the registry is process-global and libtest runs
        // tests in parallel, so no test may assert on a global total.
        let fp = "xray-witness-test-9f3a";
        note_verified_peer(fp, CAP_RELAY, "192.0.2.200:2270");
        assert!(verified_peers().iter().any(|w| w.fingerprint == fp));
        let (population, groups) = relay_population();
        assert_eq!(groups.iter().sum::<usize>(), population);
        forget_verified_peer(fp);
        assert!(!verified_peers().iter().any(|w| w.fingerprint == fp));
    }

    #[test]
    fn one_host_with_many_addresses_is_not_a_population() {
        let mut input = verified_input();
        input.public_relays = Some(500);
        input.relay_domains = Some(vec![500]);
        let ledger = build(&input);
        assert!(
            ledger.failed().any(|i| i.id == "relay_population"),
            "N_eff of one domain is 1, not 500"
        );
        assert!(ledger.claim.contains("withheld"));
    }

    #[test]
    fn an_unmeasured_domain_grouping_is_unknown_rather_than_optimistic() {
        let mut input = verified_input();
        input.relay_domains = None;
        let ledger = build(&input);
        let population = ledger
            .invariants
            .iter()
            .find(|i| i.id == "relay_population")
            .unwrap();
        assert_eq!(population.state, State::Unknown);
        assert!(population.detail.contains("N_eff is unknown"));
    }

    #[test]
    fn isp_view_does_not_pretend_to_hide_a_phantom_exit() {
        let input = LedgerInput {
            regime: Some(Regime::Fast),
            exit_ip: Some("203.0.113.7".into()),
            ..Default::default()
        };
        let ledger = build(&input);
        let site = ledger
            .observations
            .iter()
            .find(|o| o.observer == "The website")
            .unwrap();
        assert!(site.sees.iter().any(|s| s.contains("203.0.113.7")));
        assert!(ledger.claim.contains("no anonymity claim"));
    }

    #[test]
    fn signed_nonce_echo_verifies_and_rejects_forgeries() {
        let id = crate::ghost::layers::l0_identity::GhostIdentity::generate_fresh();
        let pk = id.long_term_signing.verifying_key().to_bytes();
        let nonce = issue_nonce_challenge();
        let msg = nonce_echo_signing_input(&nonce, 3);
        let mut bad_sig = id.sign(&msg).to_bytes();
        bad_sig[0] ^= 0xff;
        assert!(!verify_nonce_echo(&nonce, &pk, &bad_sig, 3));

        let nonce2 = issue_nonce_challenge();
        let msg2 = nonce_echo_signing_input(&nonce2, 3);
        let sig2 = id.sign(&msg2).to_bytes();
        assert!(verify_nonce_echo(&nonce2, &pk, &sig2, 3));
        assert_eq!(last_nonce_echo_hops(), Some(3));
        // Replay of already-consumed nonce must fail.
        assert!(!verify_nonce_echo(&nonce2, &pk, &sig2, 3));
    }
}
