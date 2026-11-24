//! Signed threat-feed snapshots for the local Threat Shield (`docs/anti_abuse.md` §3-4).
//!
//! This is the half of the shield that turns a file on disk into rules. It parses a
//! **snapshot**, verifies it against a pinned Ed25519 key, and installs it into
//! [`super::threat_shield`]. Nothing here touches the network: an operator (or a
//! refresh task) supplies the file, which is what keeps the shield 100% local.
//!
//! ## Format
//!
//! Line-oriented UTF-8, `#` comments and blank lines ignored:
//!
//! ```text
//! vantablack-threat-feed 1
//! issued 1764000000
//! expires 1766592000
//! domain phishing evil.example.com
//! domain malware bad.example.net
//! cidr c2 203.0.113.0/24
//! cidr hijacked 198.51.100.0/24
//! signature 9f8a...   # 128 hex chars, Ed25519 over the canonical body
//! ```
//!
//! Kinds: `phishing`, `malware`, `c2` (command-and-control), `hijacked` (a hijacked
//! or criminal-controlled netblock).
//!
//! The signature covers a **canonical body** — the header and every entry, in file
//! order, rebuilt by [`Snapshot::canonical_body`] — not the raw file bytes. That way
//! an operator's signer and this loader cannot disagree about whitespace, comments or
//! line endings, and a comment can never be part of what was signed.
//!
//! ## Failing closed
//!
//! A snapshot is installed **only** if it carries a valid signature from the pinned
//! key. There is no unsigned path:
//!
//! * no pinned key (`GHOST_THREAT_FEED_KEY`, hex 32-byte Ed25519 public key) →
//!   [`FeedError::Unpinned`];
//! * no `signature` line → [`FeedError::Unsigned`];
//! * a key mismatch or tampering → [`FeedError::BadSignature`];
//! * `expires` at or before the reference time → [`FeedError::Expired`].
//!
//! A refused snapshot installs nothing and leaves whatever was already loaded in
//! place, so a failed refresh degrades to the previous rules rather than to none.
//!
//! ## Expiry
//!
//! Every `cidr` entry installed from a snapshot expires when the *snapshot* does.
//! Botnet C2 addresses rotate quickly, and a refresh that silently stops happening
//! must not keep blocking an address that has since been reassigned to someone
//! innocent. Domain rules do not carry that TTL: a malicious domain is far more
//! stable than the address behind it, so a stale domain list errs toward blocking.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signature, VerifyingKey};

use super::threat_shield::{self, Shield, ThreatKind, Verdict};

/// Domain-separation label mixed into every signed canonical body.
const FEED_LABEL: &str = "vantablack-threat-feed";
/// The only snapshot format this loader understands.
const FEED_VERSION: &str = "1";

/// The pinned key's environment variable: hex-encoded 32-byte Ed25519 public key.
pub const PINNED_KEY_ENV: &str = "GHOST_THREAT_FEED_KEY";

/// Most recent unix second a snapshot was installed at, for observability.
static LAST_INSTALL: AtomicU64 = AtomicU64::new(0);

/// Why a snapshot could not be parsed, verified or installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedError {
    /// The file does not start with the expected format marker.
    Unsupported(String),
    /// A header or entry line is malformed.
    Parse(String),
    /// A required header is missing.
    Missing(&'static str),
    /// No pinned key is configured, so nothing can be verified yet.
    Unpinned,
    /// The snapshot carries no signature.
    Unsigned,
    /// The pinned key is not a valid Ed25519 public key.
    BadKey(String),
    /// The signature does not verify against the canonical body.
    BadSignature,
    /// The snapshot's own `expires` has already passed.
    Expired {
        /// The moment the snapshot stopped being valid.
        expires: u64,
        /// The moment the install was attempted.
        now: u64,
    },
    /// The file could not be read.
    Io(String),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "unsupported feed: {what}"),
            Self::Parse(what) => write!(f, "malformed feed: {what}"),
            Self::Missing(field) => write!(f, "feed is missing `{field}`"),
            Self::Unpinned => write!(
                f,
                "no pinned feed key: set {PINNED_KEY_ENV} to a hex Ed25519 public key"
            ),
            Self::Unsigned => f.write_str("feed carries no signature"),
            Self::BadKey(what) => write!(f, "pinned key is invalid: {what}"),
            Self::BadSignature => f.write_str("feed signature does not verify"),
            Self::Expired { expires, now } => {
                write!(f, "feed expired at {expires} (now {now})")
            }
            Self::Io(what) => write!(f, "feed could not be read: {what}"),
        }
    }
}

impl std::error::Error for FeedError {}

/// A parsed snapshot, verified or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// When the feed was published (unix seconds).
    pub issued: u64,
    /// When the feed stops being valid — and when its CIDR rules stop applying.
    pub expires: u64,
    /// Domain rules, in file order.
    pub domains: Vec<(String, ThreatKind)>,
    /// Netblock rules, in file order.
    pub cidrs: Vec<(IpAddr, u8, ThreatKind)>,
    /// Decoded Ed25519 signature over [`Self::canonical_body`], if present.
    pub signature: Option<[u8; 64]>,
}

/// What an install changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    pub domains: usize,
    pub cidrs: usize,
    /// Unix second the rules stop applying (`cidr` entries only).
    pub expires: u64,
}

impl Snapshot {
    /// Parse a snapshot. Signature verification is a separate step: parsing must be
    /// possible so a *broken* signature can be reported as such instead of as a
    /// syntax error.
    pub fn parse(text: &str) -> Result<Self, FeedError> {
        let mut first_line = true;
        let mut issued: Option<u64> = None;
        let mut expires: Option<u64> = None;
        let mut domains = Vec::new();
        let mut cidrs = Vec::new();
        let mut signature: Option<[u8; 64]> = None;

        for (index, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let directive = parts.next().unwrap_or_default();

            if first_line {
                first_line = false;
                let version = parts.next();
                if directive != FEED_LABEL || version != Some(FEED_VERSION) {
                    return Err(FeedError::Unsupported(format!(
                        "line {}: expected `{FEED_LABEL} {FEED_VERSION}`",
                        index + 1
                    )));
                }
                continue;
            }

            match directive {
                "issued" => {
                    issued = Some(parse_secs(parts.next(), index)?);
                }
                "expires" => {
                    expires = Some(parse_secs(parts.next(), index)?);
                }
                "domain" => {
                    let kind = parse_kind(parts.next(), index)?;
                    let name = parts.next().ok_or_else(|| {
                        FeedError::Parse(format!("line {}: no domain", index + 1))
                    })?;
                    if parts.next().is_some() {
                        return Err(FeedError::Parse(format!(
                            "line {}: trailing fields after the domain",
                            index + 1
                        )));
                    }
                    let name = name.trim_end_matches('.').to_ascii_lowercase();
                    if name.is_empty() || !name.contains('.') {
                        return Err(FeedError::Parse(format!(
                            "line {}: `{name}` is not a domain",
                            index + 1
                        )));
                    }
                    domains.push((name, kind));
                }
                "cidr" => {
                    let kind = parse_kind(parts.next(), index)?;
                    let net = parts.next().ok_or_else(|| {
                        FeedError::Parse(format!("line {}: no netblock", index + 1))
                    })?;
                    let (network, prefix) = parse_cidr(net, index)?;
                    cidrs.push((network, prefix, kind));
                }
                "signature" => {
                    let hex_sig = parts.next().ok_or_else(|| {
                        FeedError::Parse(format!("line {}: no signature bytes", index + 1))
                    })?;
                    let bytes = hex::decode(hex_sig).map_err(|_| {
                        FeedError::Parse(format!("line {}: signature is not hex", index + 1))
                    })?;
                    let decoded: [u8; 64] = bytes.try_into().map_err(|_| {
                        FeedError::Parse(format!("line {}: signature must be 64 bytes", index + 1))
                    })?;
                    signature = Some(decoded);
                }
                other => {
                    return Err(FeedError::Parse(format!(
                        "line {}: unknown directive `{other}`",
                        index + 1
                    )));
                }
            }
        }

        if first_line {
            return Err(FeedError::Unsupported("the file is empty".to_string()));
        }
        let issued = issued.ok_or(FeedError::Missing("issued"))?;
        let expires = expires.ok_or(FeedError::Missing("expires"))?;
        if expires <= issued {
            return Err(FeedError::Parse(format!(
                "expires ({expires}) must be after issued ({issued})"
            )));
        }
        if domains.is_empty() && cidrs.is_empty() {
            return Err(FeedError::Parse("the snapshot has no entries".into()));
        }
        Ok(Self {
            issued,
            expires,
            domains,
            cidrs,
            signature,
        })
    }

    /// The bytes the signature covers: header plus entries, in file order.
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut body = String::new();
        body.push_str(&format!("{FEED_LABEL} {FEED_VERSION}\n"));
        body.push_str(&format!("issued {}\n", self.issued));
        body.push_str(&format!("expires {}\n", self.expires));
        for (domain, kind) in &self.domains {
            body.push_str(&format!("domain {} {domain}\n", kind_token(*kind)));
        }
        for (network, prefix, kind) in &self.cidrs {
            body.push_str(&format!("cidr {} {network}/{prefix}\n", kind_token(*kind)));
        }
        body.into_bytes()
    }

    /// Verify the signature against `key`. Fails closed: no signature is an error.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), FeedError> {
        let Some(bytes) = self.signature else {
            return Err(FeedError::Unsigned);
        };
        let signature = Signature::from_bytes(&bytes);
        key.verify_strict(&self.canonical_body(), &signature)
            .map_err(|_| FeedError::BadSignature)
    }

    /// Whether the snapshot is still valid at `now`.
    pub fn is_live_at(&self, now: u64) -> bool {
        now < self.expires
    }
}

/// Parse a pinned key from a hex string.
pub fn pinned_key(hex_key: &str) -> Result<VerifyingKey, FeedError> {
    let bytes = hex::decode(hex_key.trim()).map_err(|_| FeedError::BadKey("not hex".into()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| FeedError::BadKey("must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| FeedError::BadKey(e.to_string()))
}

/// The pinned key from the environment, if this node has one.
pub fn pinned_key_from_env() -> Result<VerifyingKey, FeedError> {
    let raw = std::env::var(PINNED_KEY_ENV).map_err(|_| FeedError::Unpinned)?;
    if raw.trim().is_empty() {
        return Err(FeedError::Unpinned);
    }
    pinned_key(&raw)
}

/// Verify a parsed snapshot against the pinned key and install it.
///
/// On any error nothing is installed: the previously loaded rules stay in force.
pub fn install_verified(snapshot: &Snapshot, now: u64) -> Result<Installed, FeedError> {
    let key = pinned_key_from_env()?;
    install_with_key(snapshot, &key, now)
}

/// Verify against an explicit key and install. The seam the tests use, and what a
/// refresh task with its own key handling would call.
pub fn install_with_key(
    snapshot: &Snapshot,
    key: &VerifyingKey,
    now: u64,
) -> Result<Installed, FeedError> {
    snapshot.verify(key)?;
    if !snapshot.is_live_at(now) {
        return Err(FeedError::Expired {
            expires: snapshot.expires,
            now,
        });
    }
    Ok(install(snapshot, now))
}

/// Install an already-verified snapshot, replacing whatever was loaded before.
///
/// Domains and netblocks both come from this snapshot: a refresh must not leave a
/// rule from the previous snapshot in force, or a de-listed host would stay blocked
/// forever. CIDR entries expire with the snapshot.
pub fn install(snapshot: &Snapshot, now: u64) -> Installed {
    let installed = threat_shield::with_shield(|shield| {
        shield.clear_domains();
        shield.clear_cidrs();
        for (domain, kind) in &snapshot.domains {
            shield.insert_domain(domain, *kind);
        }
        for (network, prefix, kind) in &snapshot.cidrs {
            shield
                .cidrs_mut()
                .insert_expiring(*network, *prefix, *kind, Some(snapshot.expires));
        }
        shield.prune_expired(now);
        Installed {
            domains: shield.domain_count(),
            cidrs: shield.cidr_count(),
            expires: snapshot.expires,
        }
    });
    LAST_INSTALL.store(now, Ordering::Relaxed);
    tracing::info!(
        domains = installed.domains,
        cidrs = installed.cidrs,
        expires = installed.expires,
        "Threat shield: signed snapshot installed"
    );
    installed
}

/// Parse `text`, verify against the pinned key, and install.
pub fn load_and_install(text: &str, now: u64) -> Result<Installed, FeedError> {
    let key = pinned_key_from_env()?;
    load_and_install_with_key(text, &key, now)
}

/// Parse `text`, verify against `key`, and install.
pub fn load_and_install_with_key(
    text: &str,
    key: &VerifyingKey,
    now: u64,
) -> Result<Installed, FeedError> {
    let snapshot = Snapshot::parse(text)?;
    install_with_key(&snapshot, key, now)
}

/// Read, verify and install a snapshot from disk — a refresh.
///
/// Safe to call repeatedly: each successful call replaces the previous rules, and a
/// failed one leaves them untouched.
pub fn refresh_from_path(path: &Path, now: u64) -> Result<Installed, FeedError> {
    let key = pinned_key_from_env()?;
    refresh_from_path_with_key(path, &key, now)
}

/// Read and install with an explicit key.
pub fn refresh_from_path_with_key(
    path: &Path,
    key: &VerifyingKey,
    now: u64,
) -> Result<Installed, FeedError> {
    let text = std::fs::read_to_string(path).map_err(|e| FeedError::Io(e.to_string()))?;
    load_and_install_with_key(&text, key, now)
}

/// Drop netblock rules whose expiry has passed. Called by the refresh path, and
/// exposed so a long-lived process can prune without a new snapshot.
pub fn prune_expired(now: u64) -> usize {
    threat_shield::with_shield(|shield| shield.prune_expired(now))
}

/// The unix second of the last successful install, if any.
pub fn last_install_at() -> Option<u64> {
    match LAST_INSTALL.load(Ordering::Relaxed) {
        0 => None,
        at => Some(at),
    }
}

/// Classify a domain or literal address exactly as the shield will, without
/// recording a block — the read-only view a UI or a test wants.
pub fn classify(host: &str, now: u64) -> Option<Verdict> {
    threat_shield::with_shield_read(|shield: &Shield| {
        if let Ok(ip) = host.trim().parse::<IpAddr>() {
            return shield.classify_ip_at(ip, now);
        }
        shield.classify_domain(host)
    })
}

/// Classify a SOCKS-style `host:port` destination.
pub fn classify_host_port(target: &str, now: u64) -> Option<Verdict> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return classify(&addr.ip().to_string(), now);
    }
    // A hostname with a port: the index is keyed on the name alone.
    let host = if let Some(rest) = target.strip_prefix('[') {
        rest.split_once(']').map(|(host, _)| host).unwrap_or(target)
    } else {
        target
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(target)
    };
    classify(host, now)
}

fn parse_secs(value: Option<&str>, index: usize) -> Result<u64, FeedError> {
    value
        .ok_or_else(|| FeedError::Parse(format!("line {}: no timestamp", index + 1)))?
        .parse()
        .map_err(|_| FeedError::Parse(format!("line {}: timestamp is not a number", index + 1)))
}

fn parse_kind(value: Option<&str>, index: usize) -> Result<ThreatKind, FeedError> {
    match value.unwrap_or_default() {
        "phishing" => Ok(ThreatKind::Phishing),
        "malware" => Ok(ThreatKind::Malware),
        "c2" | "command-and-control" => Ok(ThreatKind::CommandAndControl),
        "hijacked" | "hijacked-netblock" => Ok(ThreatKind::HijackedNetblock),
        other => Err(FeedError::Parse(format!(
            "line {}: unknown kind `{other}`",
            index + 1
        ))),
    }
}

fn kind_token(kind: ThreatKind) -> &'static str {
    match kind {
        ThreatKind::Phishing => "phishing",
        ThreatKind::Malware => "malware",
        ThreatKind::CommandAndControl => "c2",
        ThreatKind::HijackedNetblock => "hijacked",
    }
}

fn parse_cidr(net: &str, index: usize) -> Result<(IpAddr, u8), FeedError> {
    let (addr, prefix) = net.split_once('/').ok_or_else(|| {
        FeedError::Parse(format!(
            "line {}: `{net}` is not `address/prefix`",
            index + 1
        ))
    })?;
    let addr: IpAddr = addr
        .parse()
        .map_err(|_| FeedError::Parse(format!("line {}: `{addr}` is not an address", index + 1)))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| FeedError::Parse(format!("line {}: `{prefix}` is not a prefix", index + 1)))?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(FeedError::Parse(format!(
            "line {}: prefix /{prefix} is too long",
            index + 1
        )));
    }
    Ok((addr, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::net::threat_shield::Indicator;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Mutex;

    /// The shield is process-global; these tests must not interleave.
    static LOCK: Mutex<()> = Mutex::new(());

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        threat_shield::reset();
        threat_shield::set_enabled(true);
        guard
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sign(snapshot_text: &str, seed: u8) -> String {
        let unsigned = Snapshot::parse(snapshot_text).expect("the body parses");
        let signature = key(seed).sign(&unsigned.canonical_body());
        format!(
            "{snapshot_text}signature {}\n",
            hex::encode(signature.to_bytes())
        )
    }

    const BODY: &str = "vantablack-threat-feed 1\nissued 1000\nexpires 5000\n\
         domain phishing login.evil.example\ndomain malware bad.example.net\n\
         cidr c2 203.0.113.0/24\ncidr hijacked 198.51.100.0/24\n";

    #[test]
    fn parses_domains_and_cidrs_with_their_kinds() {
        let snapshot = Snapshot::parse(BODY).expect("parses");
        assert_eq!(snapshot.issued, 1000);
        assert_eq!(snapshot.expires, 5000);
        assert_eq!(
            snapshot.domains,
            vec![
                ("login.evil.example".to_string(), ThreatKind::Phishing),
                ("bad.example.net".to_string(), ThreatKind::Malware),
            ]
        );
        assert_eq!(snapshot.cidrs.len(), 2);
        assert_eq!(snapshot.cidrs[0].2, ThreatKind::CommandAndControl);
        assert_eq!(snapshot.cidrs[1].2, ThreatKind::HijackedNetblock);
        assert!(snapshot.signature.is_none());
    }

    #[test]
    fn parsing_is_strict_and_names_what_it_rejected() {
        let cases = [
            ("nonsense 1\nissued 1\nexpires 2\ndomain malware a.example\n", "unsupported"),
            ("vantablack-threat-feed 2\nissued 1\nexpires 2\ndomain malware a.example\n", "unsupported"),
            ("", "unsupported"),
            ("vantablack-threat-feed 1\nexpires 2\ndomain malware a.example\n", "missing"),
            ("vantablack-threat-feed 1\nissued 3\nexpires 2\ndomain malware a.example\n", "malformed"),
            ("vantablack-threat-feed 1\nissued 1\nexpires 2\n", "malformed"),
            ("vantablack-threat-feed 1\nissued 1\nexpires 2\ndomain nonsense a.example\n", "malformed"),
            ("vantablack-threat-feed 1\nissued 1\nexpires 2\ndomain malware\n", "malformed"),
            ("vantablack-threat-feed 1\nissued 1\nexpires 2\ndomain malware a.example extra\n", "malformed"),
            ("vantablack-threat-feed 1\nissued 1\nexpires 2\ncidr c2 203.0.113.1\n", "malformed"),
            ("vantablack-threat-feed 1\nissued 1\nexpires 2\ncidr c2 203.0.113.0/40\n", "malformed"),
            ("vantablack-threat-feed 1\nissued 1\nexpires 2\ncmd c2 203.0.113.0/24\n", "malformed"),
            ("vantablack-threat-feed 1\nissued 1\nexpires 2\ndomain malware a.example\nsignature zz\n", "malformed"),
        ];
        for (text, expected) in cases {
            let error = Snapshot::parse(text).expect_err(&format!("{text:?} must be refused"));
            let rendered = match expected {
                "unsupported" => matches!(error, FeedError::Unsupported(_)),
                "missing" => matches!(error, FeedError::Missing(_)),
                _ => matches!(error, FeedError::Parse(_)),
            };
            assert!(rendered, "{text:?} produced {error:?}");
        }
    }

    #[test]
    fn an_unsigned_snapshot_installs_nothing() {
        let _guard = guard();
        let snapshot = Snapshot::parse(BODY).expect("parses");
        assert_eq!(
            install_with_key(&snapshot, &key(1).verifying_key(), 2000).unwrap_err(),
            FeedError::Unsigned
        );
        assert_eq!(threat_shield::with_shield(|s| s.domain_count()), 0);
        assert_eq!(threat_shield::with_shield(|s| s.cidr_count()), 0);
    }

    #[test]
    fn a_forged_or_tampered_snapshot_is_refused() {
        let _guard = guard();
        let signed = sign(BODY, 1);

        // Signed by a key this node does not pin.
        assert_eq!(
            load_and_install_with_key(&signed, &key(2).verifying_key(), 2000).unwrap_err(),
            FeedError::BadSignature
        );

        // Tampered after signing: one rule swapped for a broader block.
        let tampered = signed.replace("203.0.113.0/24", "203.0.0.0/16");
        assert_eq!(
            load_and_install_with_key(&tampered, &key(1).verifying_key(), 2000).unwrap_err(),
            FeedError::BadSignature
        );

        // Nothing from either attempt was installed.
        assert_eq!(threat_shield::with_shield(|s| s.cidr_count()), 0);
    }

    #[test]
    fn no_pinned_key_means_nothing_installs() {
        let _guard = guard();
        std::env::remove_var(PINNED_KEY_ENV);
        let signed = sign(BODY, 1);
        assert_eq!(
            load_and_install(&signed, 2000).unwrap_err(),
            FeedError::Unpinned
        );
        std::env::set_var(PINNED_KEY_ENV, "not-hex");
        assert!(matches!(
            load_and_install(&signed, 2000),
            Err(FeedError::BadKey(_))
        ));
        std::env::set_var(
            PINNED_KEY_ENV,
            hex::encode(key(1).verifying_key().to_bytes()),
        );
        assert!(load_and_install(&signed, 2000).is_ok());
        std::env::remove_var(PINNED_KEY_ENV);
    }

    #[test]
    fn a_signed_snapshot_installs_and_blocks_through_the_shield() {
        let _guard = guard();
        let signed = sign(BODY, 7);
        let installed = load_and_install_with_key(&signed, &key(7).verifying_key(), 2000)
            .expect("verified snapshot installs");
        assert_eq!(installed.domains, 2);
        assert_eq!(installed.cidrs, 2);
        assert_eq!(installed.expires, 5000);

        let phish = classify("CDN.Login.Evil.Example.", 2000).expect("blocked");
        assert_eq!(phish.matched, "login.evil.example");
        assert_eq!(phish.kind, ThreatKind::Phishing);
        assert_eq!(phish.indicator, Indicator::Domain);
        assert!(classify("innocent.example", 2000).is_none());

        let c2 = classify("203.0.113.9", 2000).expect("blocked");
        assert_eq!(c2.matched, "203.0.113.0/24");
        assert_eq!(c2.kind, ThreatKind::CommandAndControl);
        assert!(classify("203.0.114.9", 2000).is_none());
        assert_eq!(last_install_at(), Some(2000));
    }

    #[test]
    fn a_refresh_replaces_the_previous_rules_entirely() {
        let _guard = guard();
        let first = sign(BODY, 1);
        load_and_install_with_key(&first, &key(1).verifying_key(), 2000).expect("first install");
        assert!(classify("bad.example.net", 2000).is_some());
        assert!(classify("203.0.113.9", 2000).is_some());

        // A newer snapshot that de-lists the old host and netblock.
        let newer = "vantablack-threat-feed 1\nissued 3000\nexpires 8000\n\
             domain malware new.example.org\ncidr c2 192.0.2.0/24\n";
        let installed = load_and_install_with_key(&sign(newer, 1), &key(1).verifying_key(), 3000)
            .expect("refresh installs");
        assert_eq!(installed.domains, 1, "the old domains are gone");
        assert_eq!(installed.cidrs, 1, "the old netblocks are gone");
        assert!(
            classify("bad.example.net", 3000).is_none(),
            "a de-listed host must stop being blocked"
        );
        assert!(classify("203.0.113.9", 3000).is_none());
        assert!(classify("new.example.org", 3000).is_some());
        assert!(classify("192.0.2.5", 3000).is_some());
    }

    #[test]
    fn cidr_rules_stop_applying_when_the_snapshot_expires() {
        let _guard = guard();
        let signed = sign(BODY, 1);
        load_and_install_with_key(&signed, &key(1).verifying_key(), 2000).expect("install");

        // Live just before expiry...
        assert!(classify("203.0.113.9", 4999).is_some());
        // ...and not one second later, so a snapshot that stops refreshing stops
        // blocking addresses that may since have been reassigned.
        assert!(classify("203.0.113.9", 5000).is_none());
        assert!(classify("203.0.113.9", 99_999).is_none());

        // Domain rules are deliberately not on the C2 TTL.
        assert!(
            classify("bad.example.net", 5000).is_some(),
            "a malicious domain is stable; only the address behind it rotates"
        );

        // The expired netblocks are pruned rather than kept around forever.
        assert_eq!(prune_expired(5000), 2);
        assert_eq!(threat_shield::with_shield(|s| s.cidr_count()), 0);
        assert_eq!(threat_shield::with_shield(|s| s.domain_count()), 2);
    }

    #[test]
    fn an_expired_snapshot_is_refused_without_disturbing_loaded_rules() {
        let _guard = guard();
        let signed = sign(BODY, 1);
        load_and_install_with_key(&signed, &key(1).verifying_key(), 2000).expect("install");

        assert_eq!(
            load_and_install_with_key(&signed, &key(1).verifying_key(), 5000).unwrap_err(),
            FeedError::Expired {
                expires: 5000,
                now: 5000
            }
        );
        // The previous rules are still in force.
        assert!(classify("203.0.113.9", 4000).is_some());
    }

    #[test]
    fn the_loader_reads_a_snapshot_file_and_refreshes_it() {
        let _guard = guard();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("vb-threat-feed-{}-{stamp}.txt", std::process::id()));
        let vk = key(9).verifying_key();

        std::fs::write(&path, sign(BODY, 9)).expect("write the snapshot");
        let installed = refresh_from_path_with_key(&path, &vk, 2000).expect("first load");
        assert_eq!(installed.domains, 2);
        assert!(classify("bad.example.net", 2000).is_some());

        let newer = "vantablack-threat-feed 1\nissued 3000\nexpires 9000\n\
             domain phishing only.example\n";
        std::fs::write(&path, sign(newer, 9)).expect("rewrite the snapshot");
        let refreshed = refresh_from_path_with_key(&path, &vk, 3000).expect("refresh");
        assert_eq!(refreshed.domains, 1);
        assert!(classify("bad.example.net", 3000).is_none());
        assert!(classify("only.example", 3000).is_some());

        // A corrupt file must leave the working rules alone.
        std::fs::write(&path, "vantablack-threat-feed 1\nissued 1\n").expect("write junk");
        assert!(refresh_from_path_with_key(&path, &vk, 3000).is_err());
        assert!(classify("only.example", 3000).is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn canonical_body_is_stable_and_ignores_comments_and_whitespace() {
        let plain = Snapshot::parse(BODY).expect("parses");
        let decorated = Snapshot::parse(
            "# operator note\n\n\
             vantablack-threat-feed 1   # format\n\
             issued 1000\n\
             expires 5000\n\
             domain phishing login.evil.example.\n\
             \x20 domain malware bad.example.net\n\
             cidr c2 203.0.113.0/24\n\
             cidr hijacked 198.51.100.0/24\n",
        )
        .expect("parses");
        assert_eq!(plain.canonical_body(), decorated.canonical_body());
    }

    #[test]
    fn classify_host_port_accepts_a_socks_destination() {
        let _guard = guard();
        let signed = sign(BODY, 1);
        load_and_install_with_key(&signed, &key(1).verifying_key(), 2000).expect("install");
        assert!(classify_host_port("203.0.113.9:443", 2000).is_some());
        assert!(classify_host_port("login.evil.example:443", 2000).is_some());
        assert!(classify_host_port("93.184.216.34:443", 2000).is_none());
    }
}
