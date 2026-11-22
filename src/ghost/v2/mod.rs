//! Vantablack v2 — the user-facing product surface.
//!
//! The v1 stack is a strong transport with a hard first-run problem: a single
//! user gets nothing useful until a second device joins. Everything in this
//! module exists to make the node worth running at `N = 1` and to make its
//! privacy claims legible rather than implied.
//!
//! | Roadmap item | Module |
//! |---|---|
//! | `ggn drop` / GhostPortal | [`portal`] |
//! | `ggn expose` | [`expose`] |
//! | `ggn party` | [`party`] |
//! | P2P-REALITY / MASQUE / SRTP shaping | [`reality`] |
//! | Chronos-Splice ACK pacing | [`chronos`] |
//! | Boomerang home-exits | [`boomerang`] |
//! | HPEB heterogeneous bonding | [`hpeb`] |
//! | Four regimes + `.vb` DNS | [`regime`], [`vbdns`] |
//! | Adversary Goggles / truth ledger | [`xray`] |
//! | Fleet subkeys + revocation | [`fleet`] |
//! | BTCr blind-signed transit tickets | [`btcr`] |
//! | Continuum ladder + GhostCell-Nano | [`continuum`] |
//! | RACS cover shaping + LEDBAT++ | [`racs`] |
//!
//! Everything here is compiled into the default build: there is no entitlement
//! gate anywhere in this product, so a capability is either implemented or it is
//! absent, never merely switched off.

pub mod api;
pub mod boomerang;
pub mod btcr;
pub mod chronos;
pub mod expose;
pub mod fleet;
pub mod hpeb;
pub mod party;
pub mod continuum;
pub mod portal;
pub mod racs;
pub mod reality;
pub mod regime;
pub mod vbdns;
pub mod xray;

/// The v2 surfaces this build actually contains.
///
/// Used by `ggn --help`, the control center and the status document so that a
/// build can state its capabilities without a hand-maintained list drifting from
/// the code. Each entry is a module that is compiled in and unit-tested.
/// Wall-clock seconds since the Unix epoch.
///
/// v2 state is timestamped rather than counter-based because it is shared
/// between processes (CLI, daemon, dashboard) and survives restarts. `0` on a
/// clock that predates the epoch, which keeps a broken clock from panicking the
/// daemon over a display field.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub const V2_SURFACES: &[(&str, &str)] = &[
    ("drop", "GhostPortal encrypted browser file drop"),
    ("expose", "token-gated local server tunnel"),
    ("party", "UDP LAN-bridge for games"),
    ("regime", "Fast / Shielded / Ghost / Vantablack regimes"),
    ("vbdns", ".vb mesh DNS stub"),
    ("chronos", "RTT-matching ACK pacing"),
    ("reality", "probe splicing, MASQUE and SRTP shaping"),
    (
        "boomerang",
        "home-exit advertisement and selection (runtime tri-hop assembly deferred)",
    ),
    ("hpeb", "multi-PHY erasure bonding"),
    ("xray", "truth ledger with live invariants"),
    ("fleet", "fleet subkeys and device revocation"),
    ("btcr", "Ristretto255 blind-signed transit tickets"),
    ("ladder", "six-rung Continuum ladder and GhostCell-Nano DTN"),
    ("racs", "burst-shaped cover with measured preemption and LEDBAT++"),
];
