//! Boomerang home-exits — `Phone → Guard → Middle → Home PC → Internet`.
//!
//! Public exits are the most expensive and most legally exposed part of any
//! anonymity network, and the sites you actually use treat them accordingly: a
//! shared exit address is a CAPTCHA, a login challenge or a streaming block. The
//! obvious fix is to stop using someone else's exit.
//!
//! A **home exit** is your own always-on machine, registered as the last hop of a
//! three-relay circuit. The two public relays see an encrypted circuit that ends
//! at your home; your home decrypts the last layer and makes the outbound
//! connection from your own residential address. So:
//!
//! * no public exit carries your traffic or your liability;
//! * websites see a normal residential address, so banking and streaming work;
//! * a hostile Wi-Fi sees only the first hop.
//!
//! The planner is deliberately conservative, because a home exit that is chosen
//! badly is worse than a public one:
//!
//! * all three hops must be **distinct nodes**;
//! * the guard and middle must sit in **different networks** from each other and
//!   from the home exit (otherwise one ISP sees the whole circuit);
//! * descriptors **expire** — a stale address is an attacker's opportunity;
//! * selection is **seeded per epoch**, so two devices in one fleet pick the same
//!   circuit without a coordinator, and the choice is not a stable fingerprint.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use crate::ghost::net::discovery::CAP_HOME_EXIT;

/// How long a signed home-exit descriptor is accepted.
pub const DESCRIPTOR_MAX_AGE_SECS: u64 = 900;

/// One mesh node that can take part in a circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDescriptor {
    /// Node identifier, 16 bytes, hex on the wire.
    pub node_id: String,
    /// Ed25519 public key, hex.
    pub node_pk: String,
    /// Reachable `host:port`.
    pub endpoint: String,
    /// Autonomous system number, when known. `0` = unknown.
    pub asn: u32,
    /// The /16 (v4) or /32 (v6) prefix the node sits in, for coarse diversity.
    pub prefix: u16,
    /// True when this node offers exit service from a residential address.
    pub home_exit: bool,
    /// Unix seconds when the descriptor was published.
    pub seen_at: u64,
}

impl RelayDescriptor {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(b"VB-HOME-EXIT-V1");
        for field in [
            self.node_id.as_str(),
            self.node_pk.as_str(),
            self.endpoint.as_str(),
        ] {
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&self.asn.to_be_bytes());
        out.extend_from_slice(&self.prefix.to_be_bytes());
        out.push(u8::from(self.home_exit));
        out.extend_from_slice(&self.seen_at.to_be_bytes());
        out
    }

    /// Coarse network identity. Nodes in the same ASN *or* the same prefix are
    /// treated as one network for diversity purposes: either alone is enough to
    /// put two hops behind one operator.
    fn network_key(&self) -> (u32, u16) {
        (self.asn, self.prefix)
    }

    pub fn same_network(&self, other: &RelayDescriptor) -> bool {
        self.network_key() == other.network_key()
    }
}

/// A home exit is a descriptor plus the home node's signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeExit {
    pub descriptor: RelayDescriptor,
    pub signature: String,
}

impl HomeExit {
    /// Sign a descriptor. Only the node that holds the private key matching
    /// `descriptor.node_pk` can publish itself as a home exit.
    pub fn sign(descriptor: RelayDescriptor, signing: &SigningKey) -> Self {
        let sig = signing.sign(&descriptor.canonical_bytes());
        Self {
            descriptor,
            signature: hex::encode(sig.to_bytes()),
        }
    }

    pub fn verify(&self) -> bool {
        let Ok(pk_bytes) = hex::decode(&self.descriptor.node_pk) else {
            return false;
        };
        let Ok(pk): Result<[u8; 32], _> = pk_bytes.try_into() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(&self.signature) else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return false;
        };
        vk.verify_strict(
            &self.descriptor.canonical_bytes(),
            &Signature::from_bytes(&sig_arr),
        )
        .is_ok()
    }

    pub fn is_fresh(&self, now: u64, max_age: u64) -> bool {
        self.descriptor.seen_at <= now && now.saturating_sub(self.descriptor.seen_at) <= max_age
    }
}

/// Why a circuit could not be planned. Each variant is a real deployment
/// condition, not a generic error: the caller can tell the operator what to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// Fewer usable home exits than needed (at least one, plus two relays).
    NotEnoughCandidates { have: usize, need: usize },
    /// Two selected hops are the same node.
    DuplicateHop,
    /// Two hops share a network, so one operator would see most of the circuit.
    InsufficientDiversity { a: String, b: String },
    /// No candidate passed signature or freshness checks.
    NoVerifiedHomeExit,
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::NotEnoughCandidates { have, need } => {
                write!(f, "need {need} distinct relays, {have} available")
            }
            PlanError::DuplicateHop => f.write_str("a relay was selected twice"),
            PlanError::InsufficientDiversity { a, b } => write!(
                f,
                "{a} and {b} share a network; the circuit is not split across operators"
            ),
            PlanError::NoVerifiedHomeExit => {
                f.write_str("no home exit with a valid, fresh signature")
            }
        }
    }
}

impl std::error::Error for PlanError {}

/// A built circuit: the two intermediate hops and the home exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CircuitPlan {
    pub guard: RelayDescriptor,
    pub middle: RelayDescriptor,
    pub home: RelayDescriptor,
    /// Always 3 for a home-exit circuit.
    pub hops: u8,
    /// Distinct networks actually covered.
    pub distinct_networks: usize,
    /// The epoch the choice was seeded from, exposed so two devices can agree.
    pub epoch: u64,
}

impl CircuitPlan {
    /// Render the path for the dashboard.
    pub fn path_label(&self) -> String {
        format!(
            "phone → guard {} → middle {} → home {} → internet",
            short(&self.guard.node_id),
            short(&self.middle.node_id),
            short(&self.home.node_id)
        )
    }
}

fn short(id: &str) -> &str {
    if id.len() > 8 {
        &id[..8]
    } else {
        id
    }
}

/// Deterministic per-epoch ordering. Uses SHA-256 of the epoch and node id, so
/// the shuffle is reproducible across devices without a shared RNG and changes
/// every epoch.
fn epoch_rank(epoch: u64, node_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"VB-BOOMERANG-SELECT-V1");
    h.update(epoch.to_be_bytes());
    h.update(node_id.as_bytes());
    h.finalize().into()
}

/// Plan `guard → middle → home` from the available signed descriptors.
///
/// `candidates` may include ordinary relays and home exits; only verified,
/// fresh descriptors are used, and exactly one must be a home exit.
pub fn plan(
    candidates: &[HomeExit],
    plain_relays: &[RelayDescriptor],
    epoch: u64,
    now: u64,
) -> Result<CircuitPlan, PlanError> {
    let mut homes: Vec<&HomeExit> = candidates
        .iter()
        .filter(|h| {
            h.descriptor.home_exit && h.verify() && h.is_fresh(now, DESCRIPTOR_MAX_AGE_SECS)
        })
        .collect();
    if homes.is_empty() {
        return Err(PlanError::NoVerifiedHomeExit);
    }
    homes.sort_by_key(|h| epoch_rank(epoch, &h.descriptor.node_id));

    // Intermediate hops: every fresh descriptor we know about, home exits
    // excluded — the exit is a destination, not a relay.
    let mut relays: Vec<RelayDescriptor> = plain_relays
        .iter()
        .filter(|r| {
            !r.home_exit
                && r.seen_at <= now
                && now.saturating_sub(r.seen_at) <= DESCRIPTOR_MAX_AGE_SECS
        })
        .cloned()
        .collect();
    relays.sort_by_key(|r| epoch_rank(epoch, &r.node_id));

    let home = homes[0].descriptor.clone();
    let mut chosen: Vec<RelayDescriptor> = Vec::with_capacity(2);

    'outer: for candidate in relays.iter().chain(homes.iter().map(|h| &h.descriptor)) {
        if candidate.node_id == home.node_id {
            continue;
        }
        if chosen.iter().any(|c| c.node_id == candidate.node_id) {
            continue;
        }
        if candidate.same_network(&home) {
            continue;
        }
        if let Some(prev) = chosen.first() {
            if prev.same_network(candidate) {
                continue;
            }
        }
        chosen.push(candidate.clone());
        if chosen.len() == 2 {
            break 'outer;
        }
    }

    if chosen.len() < 2 {
        let available = relays.len() + homes.len() - 1;
        return Err(PlanError::NotEnoughCandidates {
            have: available,
            need: 3,
        });
    }

    let guard = chosen[0].clone();
    let middle = chosen[1].clone();
    if guard.node_id == middle.node_id {
        return Err(PlanError::DuplicateHop);
    }
    if !guard_ok(&guard, &middle, &home) {
        return Err(PlanError::InsufficientDiversity {
            a: guard.node_id.clone(),
            b: middle.node_id.clone(),
        });
    }

    Ok(CircuitPlan {
        hops: 3,
        distinct_networks: 1 + count_new_networks(&[&middle, &home]),
        guard,
        middle,
        home,
        epoch,
    })
}

fn guard_ok(guard: &RelayDescriptor, middle: &RelayDescriptor, home: &RelayDescriptor) -> bool {
    !guard.same_network(middle) && !guard.same_network(home) && !middle.same_network(home)
}

fn count_new_networks(others: &[&RelayDescriptor]) -> usize {
    let mut count: usize = 0;
    for (i, a) in others.iter().enumerate() {
        if !others[..i].iter().any(|b| a.same_network(b)) {
            count = count.saturating_add(1);
        }
    }
    count
}

// ── Live advertisement, selection and routing ─────────────────────────────
//
// The planner above decides *which* circuit to build from signed descriptors.
// This half is what makes a home exit real on a running node: a peer that
// advertises `CAP_HOME_EXIT` in its signed [`crate::ghost::net::discovery::PeerDescriptorV2`]
// is remembered here, an operator (or the client itself) selects one, and the
// SOCKS5 initiator binds its exit to that fingerprint. Nothing here silently
// falls back: if the selected home exit has no session, the proxy refuses the
// connection rather than routing through an unrelated exit.

/// A peer that advertised home-exit service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerHomeExit {
    pub fingerprint: String,
    pub endpoint: String,
    /// Unix seconds when this node last saw the advertisement.
    pub seen_at: u64,
}

#[derive(Debug, Default)]
struct Runtime {
    peers: HashMap<String, PeerHomeExit>,
    selected: Option<String>,
    local_endpoint: Option<String>,
    local_active: bool,
    last_circuit: Option<LastCircuit>,
}

/// The last onion route the SOCKS5 proxy actually assembled, for live telemetry.
#[derive(Debug, Clone)]
pub struct LastCircuit {
    pub route: Vec<String>,
    pub policy: String,
    pub recorded_unix: u64,
}

/// Record the route a connection was just built on. Called by the SOCKS5 proxy
/// after hop selection, so `/api/v2/home-exit` reports observed circuit state
/// instead of a plan.
pub fn record_circuit(route: &[String], policy: &str) {
    let mut rt = runtime().write().unwrap_or_else(|e| e.into_inner());
    rt.last_circuit = Some(LastCircuit {
        route: route.to_vec(),
        policy: policy.to_string(),
        recorded_unix: super::now_secs(),
    });
}

/// Hop count of the last circuit the SOCKS5 proxy actually assembled.
///
/// This is a measured route, not the regime's requested hop count: `None` until
/// a circuit exists in this process.
pub fn last_circuit_hops() -> Option<u8> {
    last_circuit_measurement().map(|(hops, _)| hops)
}

/// `(hops, recorded_unix)` of the last assembled circuit. The ledger wraps this
/// in a decaying witness, so a route from hours ago cannot satisfy a live check.
pub fn last_circuit_measurement() -> Option<(u8, u64)> {
    let rt = runtime().read().unwrap_or_else(|e| e.into_inner());
    rt.last_circuit
        .as_ref()
        .map(|c| (c.route.len().min(u8::MAX as usize) as u8, c.recorded_unix))
}

fn runtime() -> &'static RwLock<Runtime> {
    static RUNTIME: OnceLock<RwLock<Runtime>> = OnceLock::new();
    RUNTIME.get_or_init(|| RwLock::new(Runtime::default()))
}

/// Record a verified peer descriptor's home-exit capability.
///
/// Called from the descriptor install path (beacons, PEX, `vb://2.` invites), so
/// the registry only ever holds peers whose signed descriptor actually claimed
/// the capability. A descriptor without `CAP_HOME_EXIT` also *removes* a stale
/// entry: an operator who turned the service off must stop being a candidate.
pub fn note_peer(fingerprint: &str, capabilities: u8, endpoint: &str) {
    // Every caller reaches this point only after a signed descriptor verified,
    // so this is also the one place a peer becomes a ledger witness for
    // CAP_RELAY and its routing-domain cluster.
    super::xray::note_verified_peer(fingerprint, capabilities, endpoint);
    let mut rt = runtime().write().unwrap_or_else(|e| e.into_inner());
    if capabilities & CAP_HOME_EXIT == 0 {
        rt.peers.remove(fingerprint);
        if rt.selected.as_deref() == Some(fingerprint) {
            rt.selected = None;
        }
        return;
    }
    rt.peers.insert(
        fingerprint.to_string(),
        PeerHomeExit {
            fingerprint: fingerprint.to_string(),
            endpoint: endpoint.to_string(),
            seen_at: super::now_secs(),
        },
    );
}

/// Drop a peer that disconnected or re-advertised without exit service.
pub fn forget_peer(fingerprint: &str) {
    super::xray::forget_verified_peer(fingerprint);
    let mut rt = runtime().write().unwrap_or_else(|e| e.into_inner());
    rt.peers.remove(fingerprint);
    if rt.selected.as_deref() == Some(fingerprint) {
        rt.selected = None;
    }
}

/// Home exits this node currently knows about, newest first.
pub fn candidates() -> Vec<PeerHomeExit> {
    let rt = runtime().read().unwrap_or_else(|e| e.into_inner());
    let mut out: Vec<PeerHomeExit> = rt.peers.values().cloned().collect();
    out.sort_by(|a, b| {
        b.seen_at
            .cmp(&a.seen_at)
            .then(a.fingerprint.cmp(&b.fingerprint))
    });
    out
}

/// Bind the exit path to `fingerprint`.
///
/// Refuses when the peer was never seen advertising `CAP_HOME_EXIT`: selecting
/// an arbitrary peer as a "home exit" would be exactly the silent downgrade this
/// feature exists to prevent.
pub fn select(fingerprint: &str) -> Result<PeerHomeExit, String> {
    let mut rt = runtime().write().unwrap_or_else(|e| e.into_inner());
    let peer = rt.peers.get(fingerprint).cloned().ok_or_else(|| {
        format!("{fingerprint} has not advertised a home exit; refusing to bind the exit path")
    })?;
    rt.selected = Some(fingerprint.to_string());
    Ok(peer)
}

pub fn selected() -> Option<String> {
    runtime()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .selected
        .clone()
}

/// Stop pinning the exit path. Returns the fingerprint that was pinned.
pub fn clear_selection() -> Option<String> {
    let mut rt = runtime().write().unwrap_or_else(|e| e.into_inner());
    rt.selected.take()
}

/// Record whether *this* node advertises home-exit service, for `/api/v2/home-exit`.
pub fn set_local_advertisement(endpoint: &str, active: bool) {
    let mut rt = runtime().write().unwrap_or_else(|e| e.into_inner());
    rt.local_endpoint = Some(endpoint.to_string());
    rt.local_active = active;
}

/// JSON view consumed by `/api/v2/home-exit` and the dashboard.
pub fn view(node_fingerprint: &str) -> serde_json::Value {
    let rt = runtime().read().unwrap_or_else(|e| e.into_inner());
    serde_json::json!({
        "node_fingerprint": node_fingerprint,
        "local": {
            "advertises_home_exit": rt.local_active,
            "endpoint": rt.local_endpoint,
            "capability_bit": CAP_HOME_EXIT,
        },
        "selected": rt.selected,
        "candidates": rt.peers.values().cloned().collect::<Vec<_>>(),
        // The route the proxy actually assembled for the last connection. `none`
        // means no onion route has been built since this daemon started; it does
        // not imply the capability is missing.
        "planned_circuit": match &rt.last_circuit {
            Some(c) => serde_json::json!({
                "state": "live",
                "hops": c.route.len(),
                "route": c.route,
                "policy": c.policy,
                "recorded_unix": c.recorded_unix,
            }),
            None => serde_json::json!({
                "state": "none",
                "reason": "no SOCKS5 onion route assembled since daemon start",
            }),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(id: &str, asn: u32, prefix: u16, home: bool) -> RelayDescriptor {
        RelayDescriptor {
            node_id: id.to_string(),
            node_pk: hex::encode([0u8; 32]),
            endpoint: "198.51.100.1:2270".to_string(),
            asn,
            prefix,
            home_exit: home,
            seen_at: 1_000,
        }
    }

    fn signed_home(desc: RelayDescriptor) -> HomeExit {
        // Sign with a key that matches the descriptor's public key so `verify`
        // exercises the real path.
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let mut desc = desc;
        desc.node_pk = hex::encode(sk.verifying_key().to_bytes());
        HomeExit::sign(desc, &sk)
    }

    #[test]
    fn plans_three_distinct_networks() {
        let home = signed_home(relay("home-1", 64500, 0xC0A8, true));
        let relays = vec![
            relay("guard-1", 64501, 0x0A00, false),
            relay("middle-1", 64502, 0x0B00, false),
        ];
        let plan = plan(&[home], &relays, 42, 1_100).expect("plan");
        assert_eq!(plan.hops, 3);
        assert_eq!(plan.distinct_networks, 3);
        assert_ne!(plan.guard.node_id, plan.middle.node_id);
        assert_ne!(plan.home.node_id, plan.guard.node_id);
        assert!(plan.path_label().contains("→ internet"));
    }

    #[test]
    fn refuses_when_every_relay_shares_the_home_network() {
        let home = signed_home(relay("home-1", 64500, 0xC0A8, true));
        let relays = vec![
            relay("guard-1", 64500, 0xC0A8, false),
            relay("middle-1", 64500, 0xC0A8, false),
        ];
        assert!(matches!(
            plan(&[home], &relays, 1, 1_100),
            Err(PlanError::NotEnoughCandidates { .. })
        ));
    }

    #[test]
    fn stale_descriptors_are_not_used() {
        let mut home = signed_home(relay("home-1", 64500, 1, true));
        let mut relays = vec![relay("guard-1", 64501, 2, false)];
        home.descriptor.seen_at = 0;
        relays[0].seen_at = 0;
        let err = plan(&[home], &relays, 7, 10_000).unwrap_err();
        assert_eq!(err, PlanError::NoVerifiedHomeExit);
    }

    #[test]
    fn an_unsigned_home_exit_is_refused() {
        let mut home = signed_home(relay("home-1", 64500, 1, true));
        home.descriptor.endpoint = "203.0.113.9:1".into(); // tamper after signing
        let relays = vec![relay("g", 2, 2, false), relay("m", 3, 3, false)];
        assert_eq!(
            plan(&[home], &relays, 1, 1_100).unwrap_err(),
            PlanError::NoVerifiedHomeExit
        );
    }

    #[test]
    fn selection_is_stable_within_an_epoch_and_changes_across_epochs() {
        let home = signed_home(relay("home-1", 64500, 0xC0A8, true));
        let relays = vec![
            relay("guard-a", 64501, 0x0A00, false),
            relay("guard-b", 64502, 0x0B00, false),
            relay("middle-a", 64503, 0x0C00, false),
            relay("middle-b", 64504, 0x0D00, false),
        ];
        let a = plan(std::slice::from_ref(&home), &relays, 5, 1_100).unwrap();
        let b = plan(std::slice::from_ref(&home), &relays, 5, 1_100).unwrap();
        assert_eq!(a, b, "same epoch, same circuit");

        let mut changed = false;
        for epoch in 6..40 {
            let p = plan(std::slice::from_ref(&home), &relays, epoch, 1_100).unwrap();
            if p.guard.node_id != a.guard.node_id {
                changed = true;
                break;
            }
        }
        assert!(changed, "selection rotates with the epoch");
    }

    #[test]
    fn runtime_registry_only_accepts_advertised_home_exits() {
        note_peer("fp-home", CAP_HOME_EXIT, "192.0.2.7:2270");
        note_peer("fp-plain", 1, "192.0.2.8:2270");
        let listed = candidates();
        assert!(listed.iter().any(|c| c.fingerprint == "fp-home"));
        assert!(!listed.iter().any(|c| c.fingerprint == "fp-plain"));
        assert!(
            select("fp-plain").is_err(),
            "never advertised, never selected"
        );
        assert!(select("fp-home").is_ok());
        assert_eq!(selected().as_deref(), Some("fp-home"));
        // A later descriptor without the bit withdraws the advertisement.
        note_peer("fp-home", 0, "192.0.2.7:2270");
        assert_eq!(selected(), None);
        assert!(candidates().is_empty());
    }

    #[test]
    fn a_plain_relay_can_never_be_the_home_exit() {
        let relays = vec![
            relay("a", 1, 1, false),
            relay("b", 2, 2, false),
            relay("c", 3, 3, false),
        ];
        assert_eq!(
            plan(&[], &relays, 1, 1_100).unwrap_err(),
            PlanError::NoVerifiedHomeExit
        );
    }
}
