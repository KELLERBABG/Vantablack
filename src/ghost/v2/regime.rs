//! Four human regimes, two honest planes.
//!
//! v1 exposed four SOCKS5 ports (`:1080`–`:1083`) and roughly thirty
//! `GHOST_*` variables, and left the operator to work out which combination
//! meant what. That is not a UI problem — it is an honesty problem, because the
//! difference between "fast" and "anonymous" is a threat-model difference, not a
//! port number.
//!
//! This module names the four regimes the roadmap asks for and derives every
//! mechanical setting from the one word:
//!
//! | Regime | Plane | Hops | SOCKS | Cover traffic | Anonymous claim |
//! |---|---|---|---|---|---|
//! | `fast` | Phantom | 1 | `:1081` | no | never |
//! | `shielded` | Phantom | 2 | `:1082` | no | never |
//! | `ghost` | Umbra | 3 strict | `:1083` | yes | never (N is too small) |
//! | `vantablack` | Umbra | 3 strict + diversity | `:1083` | yes | only at N ≥ 200 |
//!
//! The last column is the point. `ghost` and `vantablack` are both anonymity
//! planes, but only `vantablack` is *allowed to claim* anonymity, and only while
//! the live relay count supports it — see [`RegimePolicy::refuse_reason`] and
//! [`super::xray`]. A regime that silently degrades is worse than one that
//! refuses.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const REGIME_ENV: &str = "GHOST_V2_REGIME";

pub const REGIME_FILE: &str = "ghost-regime.json";

pub fn effective_population(groups: &[usize]) -> f64 {
    let total: usize = groups.iter().copied().sum();
    if total == 0 {
        return 0.0;
    }
    let sum_sq: f64 = groups
        .iter()
        .map(|n| {
            let w = *n as f64 / total as f64;
            w * w
        })
        .sum();
    if sum_sq <= 0.0 {
        0.0
    } else {
        1.0 / sum_sq
    }
}

pub const MIN_ANONYMITY_RELAYS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plane {
    Phantom,
    Umbra,
}

impl Plane {
    pub fn as_str(self) -> &'static str {
        match self {
            Plane::Phantom => "phantom",
            Plane::Umbra => "umbra",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopClass {
    Direct,
    TwoHop,
    ThreeHopStrict,
}

impl HopClass {
    pub fn hops(self) -> u8 {
        match self {
            HopClass::Direct => 1,
            HopClass::TwoHop => 2,
            HopClass::ThreeHopStrict => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            HopClass::Direct => "direct",
            HopClass::TwoHop => "two_hop",
            HopClass::ThreeHopStrict => "three_hop_strict",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Regime {
    Fast,
    Shielded,
    Ghost,
    Vantablack,
}

impl Regime {
    pub const ALL: [Regime; 4] = [
        Regime::Fast,
        Regime::Shielded,
        Regime::Ghost,
        Regime::Vantablack,
    ];

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "fast" | "1" => Some(Regime::Fast),
            "shielded" | "shield" | "2" => Some(Regime::Shielded),
            "ghost" | "3" => Some(Regime::Ghost),
            "vantablack" | "vb" | "4" => Some(Regime::Vantablack),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Regime::Fast => "fast",
            Regime::Shielded => "shielded",
            Regime::Ghost => "ghost",
            Regime::Vantablack => "vantablack",
        }
    }

    pub fn plane(self) -> Plane {
        match self {
            Regime::Fast | Regime::Shielded => Plane::Phantom,
            Regime::Ghost | Regime::Vantablack => Plane::Umbra,
        }
    }

    pub fn hops(self) -> HopClass {
        match self {
            Regime::Fast => HopClass::Direct,
            Regime::Shielded => HopClass::TwoHop,
            Regime::Ghost | Regime::Vantablack => HopClass::ThreeHopStrict,
        }
    }

    pub fn socks_offset(self) -> u16 {
        match self {
            Regime::Fast => 1,
            Regime::Shielded => 2,
            Regime::Ghost | Regime::Vantablack => 3,
        }
    }

    pub fn cover_traffic(self) -> bool {
        matches!(self, Regime::Ghost | Regime::Vantablack)
    }

    pub fn timing_hardened(self) -> bool {
        matches!(self, Regime::Ghost | Regime::Vantablack)
    }

    pub fn shaping_required(self) -> bool {
        self.timing_hardened()
    }

    pub fn chronos_required(self) -> bool {
        self.timing_hardened()
    }

    pub fn requires_asn_diversity(self) -> bool {
        matches!(self, Regime::Vantablack)
    }

    pub fn anonymity_claim_allowed(self) -> bool {
        matches!(self, Regime::Vantablack)
    }

    pub fn describe(self) -> &'static str {
        match self {
            Regime::Fast => {
                "One hop, direct exit. Honest about being a fast tunnel, not an anonymity system."
            }
            Regime::Shielded => "Two hops, split across two operators.",
            Regime::Ghost => "Three strict hops. Refuses to connect if fewer than 3 peers are live.",
            Regime::Vantablack => {
                "Three strict hops across independent networks, with cover traffic and a live truth ledger."
            }
        }
    }
}

impl std::fmt::Display for Regime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimePolicy {
    pub regime: Regime,
    pub plane: Plane,
    pub hops: HopClass,
    pub socks_port: u16,
    pub cover_traffic: bool,
    pub asn_diversity: bool,
    pub refuse_reason: Option<String>,
    pub claim: String,
}

impl RegimePolicy {
    pub fn is_refused(&self) -> bool {
        self.refuse_reason.is_some()
    }
}

pub fn effective_policy(regime: Regime, relays: usize, base_socks_port: u16) -> RegimePolicy {
    let hops = regime.hops();
    let mut refuse = None;

    let needed = match hops {
        HopClass::Direct => 1usize,
        HopClass::TwoHop => 2,
        HopClass::ThreeHopStrict => 3,
    };
    if relays < needed {
        refuse = Some(format!(
            "{} needs {needed} live relays, {relays} present",
            regime.as_str()
        ));
    }

    let claim = if regime.anonymity_claim_allowed() {
        if relays >= MIN_ANONYMITY_RELAYS {
            format!("anonymous among {relays} public relays")
        } else {
            format!("not anonymous — {relays} public relays live, {MIN_ANONYMITY_RELAYS} required")
        }
    } else if regime.plane() == Plane::Umbra {
        format!("unlinkable from a guard's view; not an anonymity claim ({relays} relays)")
    } else {
        "private mesh; no anonymity claim".to_string()
    };

    RegimePolicy {
        regime,
        plane: regime.plane(),
        hops,
        socks_port: base_socks_port.saturating_add(regime.socks_offset()),
        cover_traffic: regime.cover_traffic(),
        asn_diversity: regime.requires_asn_diversity(),
        refuse_reason: refuse,
        claim,
    }
}

pub fn from_env() -> Result<Option<Regime>, String> {
    match std::env::var(REGIME_ENV) {
        Ok(raw) if !raw.trim().is_empty() => Regime::parse(&raw)
            .map(Some)
            .ok_or_else(|| format!("{REGIME_ENV}={raw:?} is not fast|shielded|ghost|vantablack")),
        _ => Ok(None),
    }
}

pub fn config_path() -> PathBuf {
    crate::ghost::paths::data_dir().join(REGIME_FILE)
}

pub fn load_persisted(path: &Path) -> Result<Option<Regime>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    #[derive(Deserialize)]
    struct Persisted {
        regime: String,
    }
    match serde_json::from_str::<Persisted>(&raw) {
        Ok(p) => Regime::parse(&p.regime)
            .map(Some)
            .ok_or_else(|| format!("{}: unknown regime {:?}", path.display(), p.regime)),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub fn save_persisted(path: &Path, regime: Regime) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::json!({
        "regime": regime.as_str(),
        "plane": regime.plane().as_str(),
        "hops": regime.hops().hops(),
        "updated_at": crate::ghost::v2::now_secs(),
    });
    std::fs::write(path, serde_json::to_vec_pretty(&body).unwrap_or_default())
}

pub fn active() -> Result<Regime, String> {
    if let Some(r) = from_env()? {
        return Ok(r);
    }
    match load_persisted(&config_path())? {
        Some(r) => Ok(r),
        None => Ok(Regime::Ghost),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regimes_map_to_distinct_ports_and_planes() {
        assert_eq!(effective_policy(Regime::Fast, 1, 1080).socks_port, 1081);
        assert_eq!(effective_policy(Regime::Shielded, 2, 1080).socks_port, 1082);
        assert_eq!(effective_policy(Regime::Ghost, 3, 1080).socks_port, 1083);
        assert_eq!(
            effective_policy(Regime::Vantablack, 200, 1080).socks_port,
            1083
        );
        assert_eq!(Regime::Fast.plane(), Plane::Phantom);
        assert_eq!(Regime::Vantablack.plane(), Plane::Umbra);
    }

    #[test]
    fn strict_regimes_refuse_rather_than_degrade() {
        let p = effective_policy(Regime::Ghost, 2, 1080);
        assert!(p.is_refused());
        assert!(p.refuse_reason.unwrap().contains("3 live relays"));

        let p = effective_policy(Regime::Fast, 1, 1080);
        assert!(!p.is_refused());
    }

    #[test]
    fn anonymity_is_claimed_only_above_the_relay_floor() {
        let small = effective_policy(Regime::Vantablack, 12, 1080);
        assert!(small.claim.starts_with("not anonymous"));
        assert!(!small.is_refused(), "12 relays can still build 3 hops");

        let large = effective_policy(Regime::Vantablack, MIN_ANONYMITY_RELAYS, 1080);
        assert!(large.claim.starts_with("anonymous among"));

        for r in [Regime::Fast, Regime::Shielded, Regime::Ghost] {
            assert!(!effective_policy(r, 10_000, 1080)
                .claim
                .starts_with("anonymous"));
        }
    }

    #[test]
    fn effective_population_rejects_sybil_inflation() {
        assert!((effective_population(&[200]) - 1.0).abs() < 1e-9);
        let independent: Vec<usize> = std::iter::repeat_n(1, 200).collect();
        assert!((effective_population(&independent) - 200.0).abs() < 1e-6);
        assert!((effective_population(&[50, 50, 50, 50]) - 4.0).abs() < 1e-9);
        assert_eq!(effective_population(&[]), 0.0);
        assert_eq!(effective_population(&[0, 0]), 0.0);
    }

    #[test]
    fn parse_rejects_typos_instead_of_falling_back() {
        assert_eq!(Regime::parse(" Fast "), Some(Regime::Fast));
        assert_eq!(Regime::parse("VANTABLACK"), Some(Regime::Vantablack));
        assert_eq!(Regime::parse("anon"), None);
        assert_eq!(Regime::parse(""), None);
    }

    #[test]
    fn persisted_regime_round_trips() {
        let dir = std::env::temp_dir().join(format!(
            "vb-regime-test-{}-{}",
            std::process::id(),
            crate::ghost::v2::now_secs()
        ));
        let path = dir.join(REGIME_FILE);
        save_persisted(&path, Regime::Shielded).expect("save");
        assert_eq!(load_persisted(&path), Ok(Some(Regime::Shielded)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_default() {
        let path = std::env::temp_dir().join(format!(
            "vb-regime-corrupt-{}-{}.json",
            std::process::id(),
            crate::ghost::v2::now_secs()
        ));
        std::fs::write(&path, b"{not json").unwrap();
        assert!(load_persisted(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn timing_hardening_is_strictly_the_umbra_planes() {
        for r in [Regime::Fast, Regime::Shielded] {
            assert!(!r.timing_hardened(), "{r:?}");
            assert!(!r.shaping_required(), "{r:?}");
            assert!(!r.chronos_required(), "{r:?}");
            assert!(!r.cover_traffic(), "{r:?}");
        }
        for r in [Regime::Ghost, Regime::Vantablack] {
            assert!(r.timing_hardened(), "{r:?}");
            assert!(r.shaping_required(), "{r:?}");
            assert!(r.chronos_required(), "{r:?}");
            assert!(r.cover_traffic(), "{r:?}");
        }
    }

    #[test]
    fn effective_fast_policy_is_unchanged_by_timing_hardening() {
        let fast = effective_policy(Regime::Fast, 10, 1080);
        assert_eq!(fast.socks_port, 1081);
        assert!(!fast.cover_traffic);
        assert!(!fast.asn_diversity);
        assert!(!fast.regime.timing_hardened());
        assert_eq!(fast.hops, HopClass::Direct);
    }
}
