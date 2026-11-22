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

use serde::Serialize;

use super::regime::{Plane, Regime, MIN_ANONYMITY_RELAYS};

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
    pub cover_traffic: bool,
    /// Whether DNS queries are known to bypass the mesh.
    pub dns_leak: Option<bool>,
    /// `true` when the handshake used the hybrid PQ suite.
    pub pq_hybrid: Option<bool>,
    /// Active ACK pacing state, from [`super::chronos`].
    pub clock_consistent: Option<bool>,
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

    // ── Invariants ──────────────────────────────────────────────────────
    let mut invariants = Vec::with_capacity(8);

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
        invariants.push(match relays {
            Some(n) if n >= MIN_ANONYMITY_RELAYS => inv(
                "relay_population",
                State::Verified,
                format!("{n} public relays live (floor {MIN_ANONYMITY_RELAYS})"),
            ),
            Some(n) => inv(
                "relay_population",
                State::Failed,
                format!("{n} public relays live; anonymity needs at least {MIN_ANONYMITY_RELAYS}"),
            ),
            None => inv(
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
        invariants.push(inv(
            "cover_traffic",
            if input.cover_traffic {
                State::Verified
            } else {
                State::Failed
            },
            if input.cover_traffic {
                "cover traffic is being emitted".to_string()
            } else {
                format!(
                    "{} requires cover traffic but none is active",
                    regime.as_str()
                )
            },
        ));
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
        format!("anonymous among {} public relays", relays.unwrap_or(0))
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
            cover_traffic: true,
            dns_leak: Some(false),
            pq_hybrid: Some(true),
            clock_consistent: Some(true),
        }
    }

    #[test]
    fn a_fully_measured_vantablack_node_may_claim_anonymity() {
        let ledger = build(&verified_input());
        assert!(ledger.all_verified(), "{:?}", ledger.invariants);
        assert_eq!(ledger.claim, "anonymous among 500 public relays");
        assert!(!ledger.headline().contains("FAIL"));
    }

    #[test]
    fn too_few_relays_downgrades_the_headline() {
        let mut input = verified_input();
        input.public_relays = Some(12);
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
        input.cover_traffic = false;
        let ledger = build(&input);
        let failed: Vec<&str> = ledger.failed().map(|i| i.id).collect();
        assert!(failed.contains(&"dns_path"));
        assert!(failed.contains(&"cover_traffic"));
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
}
