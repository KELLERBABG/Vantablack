//! Local Threat / Malware Shield (`docs/anti_abuse.md` §3).
//!
//! Blocks known malicious infrastructure — phishing, malware distribution, botnet
//! command-and-control — with the same local pipeline Ad & Tracker Blocking uses.
//! The two are **separate toggles**: this shield starts *off*, because it is only
//! meaningful once an operator has loaded a feed, and turning on ad blocking must
//! not silently start blocking whole netblocks.
//!
//! Four pieces, matching the design in the doc:
//!
//! * [`HostIndex`] — a suffix index for domains. Lookup walks label boundaries
//!   (`a.b.example.com` → `a.b.example.com`, `b.example.com`, `example.com`, `com`),
//!   so it costs O(labels) hash probes and never a linear scan over a 100k-entry
//!   feed.
//! * [`CidrIndex`] — a sorted prefix table for netblocks. Lookup walks prefix
//!   lengths from the longest down and binary-searches each, so a /32 rule is not
//!   shadowed by a /8 covering the same address... or rather, the more specific
//!   rule is the one reported.
//! * [`Shield`] — the loaded state plus the operator's **local allowlist**, which
//!   wins over every block rule (the false-positive escape hatch).
//! * [`recent_blocks`] — a bounded, in-memory ring buffer of what was blocked. It
//!   is never persisted: in amnesia mode it must not survive the process.
//!
//! ## What loading is *not*
//!
//! Feed snapshots are meant to be Ed25519-signed against a pinned Vantablack key
//! before they are trusted (`docs/anti_abuse.md` §4). Signature verification is not
//! wired yet, so nothing here fetches or verifies a feed: an operator (or a test)
//! hands the indexes entries, and this module never contacts the network on its own.
//! That is also why the toggle defaults off — an empty shield that claims to be on
//! would be a silent stub.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{OnceLock, RwLock};

static SHIELD_ENABLED: AtomicBool = AtomicBool::new(false);
static BLOCKED_TOTAL: AtomicU64 = AtomicU64::new(0);

pub const RECENT_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indicator {
    Domain,
    Ip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatKind {
    Phishing,
    Malware,
    CommandAndControl,
    HijackedNetblock,
}

impl ThreatKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Phishing => "phishing",
            Self::Malware => "malware",
            Self::CommandAndControl => "command-and-control",
            Self::HijackedNetblock => "hijacked-netblock",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub indicator: Indicator,
    pub matched: String,
    pub kind: ThreatKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEvent {
    pub value: String,
    pub indicator: Indicator,
    pub kind: ThreatKind,
    pub at: u64,
}

#[derive(Debug, Default)]
pub struct HostIndex {
    exact: HashMap<String, ThreatKind>,
}

impl HostIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }

    pub fn insert(&mut self, domain: &str, kind: ThreatKind) {
        let domain = normalize_domain(domain);
        if !domain.is_empty() {
            self.exact.insert(domain, kind);
        }
    }

    pub fn extend<I, S>(&mut self, domains: I, kind: ThreatKind)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for domain in domains {
            self.insert(domain.as_ref(), kind);
        }
    }

    pub fn lookup(&self, domain: &str) -> Option<(String, ThreatKind)> {
        let domain = normalize_domain(domain);
        if domain.is_empty() || self.exact.is_empty() {
            return None;
        }
        let mut rest = domain.as_str();
        loop {
            if let Some(&kind) = self.exact.get(rest) {
                return Some((rest.to_string(), kind));
            }
            match rest.split_once('.') {
                Some((_, tail)) if !tail.is_empty() => rest = tail,
                _ => return None,
            }
        }
    }

    pub fn clear(&mut self) {
        self.exact.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CidrEntry {
    network: IpAddr,
    prefix: u8,
    kind: ThreatKind,
    expires_at: Option<u64>,
}

#[derive(Debug, Default)]
pub struct CidrIndex {
    entries: Vec<CidrEntry>,
}

impl CidrIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn insert(&mut self, network: IpAddr, prefix: u8, kind: ThreatKind) {
        self.insert_expiring(network, prefix, kind, None);
    }

    pub fn insert_expiring(
        &mut self,
        network: IpAddr,
        prefix: u8,
        kind: ThreatKind,
        expires_at: Option<u64>,
    ) {
        let Some(network) = masked(network, prefix) else {
            return;
        };
        let key = (network, prefix);
        let entry = CidrEntry {
            network,
            prefix,
            kind,
            expires_at,
        };
        match self
            .entries
            .binary_search_by(|entry| (entry.network, entry.prefix).cmp(&key))
        {
            Ok(index) => self.entries[index] = entry,
            Err(index) => self.entries.insert(index, entry),
        }
    }

    pub fn extend<I>(&mut self, nets: I, kind: ThreatKind)
    where
        I: IntoIterator<Item = (IpAddr, u8)>,
    {
        for (network, prefix) in nets {
            self.insert(network, prefix, kind);
        }
    }

    pub fn extend_expiring<I>(&mut self, nets: I, kind: ThreatKind, expires_at: Option<u64>)
    where
        I: IntoIterator<Item = (IpAddr, u8)>,
    {
        for (network, prefix) in nets {
            self.insert_expiring(network, prefix, kind, expires_at);
        }
    }

    pub fn prune_expired(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|entry| !entry.expires_at.is_some_and(|at| at <= now));
        before - self.entries.len()
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<(String, ThreatKind)> {
        self.lookup_at(ip, now_secs())
    }

    pub fn lookup_at(&self, ip: IpAddr, now: u64) -> Option<(String, ThreatKind)> {
        if self.entries.is_empty() {
            return None;
        }
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        for prefix in (0..=max_prefix).rev() {
            let Some(network) = masked(ip, prefix) else {
                continue;
            };
            let key = (network, prefix);
            if let Ok(index) = self
                .entries
                .binary_search_by(|entry| (entry.network, entry.prefix).cmp(&key))
            {
                let entry = &self.entries[index];
                if entry.expires_at.is_some_and(|at| at <= now) {
                    continue;
                }
                return Some((format!("{}/{}", entry.network, entry.prefix), entry.kind));
            }
        }
        None
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[derive(Debug, Default)]
pub struct Shield {
    hosts: HostIndex,
    cidrs: CidrIndex,
    allow: HashSet<String>,
    recent: VecDeque<BlockEvent>,
}

impl Shield {
    pub fn is_loaded(&self) -> bool {
        !self.hosts.is_empty() || !self.cidrs.is_empty()
    }

    pub fn load_domains<I, S>(&mut self, domains: I, kind: ThreatKind)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.hosts.extend(domains, kind);
    }

    pub fn load_cidrs<I>(&mut self, nets: I, kind: ThreatKind)
    where
        I: IntoIterator<Item = (IpAddr, u8)>,
    {
        self.cidrs.extend(nets, kind);
    }

    pub fn insert_domain(&mut self, domain: &str, kind: ThreatKind) {
        self.hosts.insert(domain, kind);
    }

    pub fn clear_domains(&mut self) {
        self.hosts.clear();
    }

    pub fn clear_cidrs(&mut self) {
        self.cidrs.clear();
    }

    pub fn cidrs_mut(&mut self) -> &mut CidrIndex {
        &mut self.cidrs
    }

    pub fn domain_count(&self) -> usize {
        self.hosts.len()
    }

    pub fn cidr_count(&self) -> usize {
        self.cidrs.len()
    }

    pub fn prune_expired(&mut self, now: u64) -> usize {
        self.cidrs.prune_expired(now)
    }

    pub fn replace_domains<I, S>(&mut self, domains: I, kind: ThreatKind)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.hosts.clear();
        self.load_domains(domains, kind);
    }

    pub fn replace_cidrs<I>(&mut self, nets: I, kind: ThreatKind)
    where
        I: IntoIterator<Item = (IpAddr, u8)>,
    {
        self.cidrs.clear();
        self.load_cidrs(nets, kind);
    }

    pub fn replace_cidrs_expiring<I>(&mut self, nets: I, kind: ThreatKind, expires_at: Option<u64>)
    where
        I: IntoIterator<Item = (IpAddr, u8)>,
    {
        self.cidrs.clear();
        self.cidrs.extend_expiring(nets, kind, expires_at);
    }

    pub fn allow_domain(&mut self, domain: &str) {
        let domain = normalize_domain(domain);
        if !domain.is_empty() {
            self.allow.insert(domain);
        }
    }

    pub fn allow_ip(&mut self, ip: IpAddr) {
        self.allow.insert(ip.to_string());
    }

    pub fn clear_allowlist(&mut self) {
        self.allow.clear();
    }

    pub fn allowlist_len(&self) -> usize {
        self.allow.len()
    }

    pub fn is_allowed_domain(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return false;
        }
        let mut rest = domain.as_str();
        loop {
            if self.allow.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, tail)) if !tail.is_empty() => rest = tail,
                _ => return false,
            }
        }
    }

    pub fn is_allowed_ip(&self, ip: IpAddr) -> bool {
        self.allow.contains(&ip.to_string())
    }

    pub fn classify_domain(&self, domain: &str) -> Option<Verdict> {
        if self.is_allowed_domain(domain) {
            return None;
        }
        self.hosts.lookup(domain).map(|(matched, kind)| Verdict {
            indicator: Indicator::Domain,
            matched,
            kind,
        })
    }

    pub fn classify_ip(&self, ip: IpAddr) -> Option<Verdict> {
        self.classify_ip_at(ip, now_secs())
    }

    pub fn classify_ip_at(&self, ip: IpAddr, now: u64) -> Option<Verdict> {
        if self.is_allowed_ip(ip) {
            return None;
        }
        self.cidrs
            .lookup_at(ip, now)
            .map(|(matched, kind)| Verdict {
                indicator: Indicator::Ip,
                matched,
                kind,
            })
    }

    fn record(&mut self, value: &str, verdict: &Verdict) {
        if self.recent.len() == RECENT_CAPACITY {
            self.recent.pop_front();
        }
        self.recent.push_back(BlockEvent {
            value: value.to_string(),
            indicator: verdict.indicator,
            kind: verdict.kind,
            at: now_secs(),
        });
    }

    pub fn recent(&self, limit: usize) -> Vec<BlockEvent> {
        let skip = self.recent.len().saturating_sub(limit);
        self.recent.iter().skip(skip).cloned().collect()
    }
}

fn shield() -> &'static RwLock<Shield> {
    static SHIELD: OnceLock<RwLock<Shield>> = OnceLock::new();
    SHIELD.get_or_init(|| RwLock::new(Shield::default()))
}

#[cfg(test)]
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn is_enabled() -> bool {
    SHIELD_ENABLED.load(Ordering::Relaxed)
}

pub fn set_enabled(enabled: bool) {
    SHIELD_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn blocked_total() -> u64 {
    BLOCKED_TOTAL.load(Ordering::Relaxed)
}

pub fn with_shield<R>(f: impl FnOnce(&mut Shield) -> R) -> R {
    let mut guard = shield().write().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

pub fn with_shield_read<R>(f: impl FnOnce(&Shield) -> R) -> R {
    let guard = shield().read().unwrap_or_else(|e| e.into_inner());
    f(&guard)
}

pub fn load_domains<I, S>(domains: I, kind: ThreatKind)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    with_shield(|shield| shield.load_domains(domains, kind));
}

pub fn load_cidrs<I>(nets: I, kind: ThreatKind)
where
    I: IntoIterator<Item = (IpAddr, u8)>,
{
    with_shield(|shield| shield.load_cidrs(nets, kind));
}

pub fn allow_domain(domain: &str) {
    with_shield(|shield| shield.allow_domain(domain));
}

pub fn reset() {
    with_shield(|shield| {
        shield.replace_domains(Vec::<String>::new(), ThreatKind::Malware);
        shield.replace_cidrs(Vec::<(IpAddr, u8)>::new(), ThreatKind::Malware);
        shield.clear_allowlist();
    });
}

pub fn blocks_domain(domain: &str) -> bool {
    if !is_enabled() {
        return false;
    }
    let verdict = with_shield_read(|shield| shield.classify_domain(domain));
    if let Some(verdict) = &verdict {
        record_block(domain, verdict);
    }
    match verdict {
        Some(verdict) => {
            BLOCKED_TOTAL.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                domain = %domain,
                matched = %verdict.matched,
                kind = verdict.kind.as_str(),
                "Threat shield: domain blocked"
            );
            true
        }
        None => false,
    }
}

pub fn blocks_ip(ip: IpAddr) -> bool {
    if !is_enabled() {
        return false;
    }
    let verdict = with_shield_read(|shield| shield.classify_ip(ip));
    if let Some(verdict) = &verdict {
        record_block(&ip.to_string(), verdict);
    }
    match verdict {
        Some(verdict) => {
            BLOCKED_TOTAL.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                ip = %ip,
                matched = %verdict.matched,
                kind = verdict.kind.as_str(),
                "Threat shield: address blocked"
            );
            true
        }
        None => false,
    }
}

fn record_block(value: &str, verdict: &Verdict) {
    with_shield(|shield| shield.record(value, verdict));
}

pub fn recent_blocks(limit: usize) -> Vec<BlockEvent> {
    with_shield_read(|shield| shield.recent(limit))
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn masked(ip: IpAddr, prefix: u8) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(ip) => {
            if prefix > 32 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask)))
        }
        IpAddr::V6(ip) => {
            if prefix > 128 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            Some(IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask)))
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("an address")
    }

    #[test]
    fn host_index_matches_by_label_boundary_only() {
        let mut index = HostIndex::new();
        index.insert("malware.example.com", ThreatKind::Malware);
        assert_eq!(
            index.lookup("malware.example.com"),
            Some(("malware.example.com".to_string(), ThreatKind::Malware))
        );
        assert_eq!(
            index.lookup("cdn.malware.example.com."),
            Some(("malware.example.com".to_string(), ThreatKind::Malware))
        );
        assert_eq!(index.lookup("notmalware.example.com"), None);
        assert_eq!(index.lookup("example.com"), None);
        assert_eq!(index.lookup(""), None);
    }

    #[test]
    fn host_index_returns_the_most_specific_entry() {
        let mut index = HostIndex::new();
        index.insert("example.com", ThreatKind::Phishing);
        index.insert("cdn.bad.example.com", ThreatKind::Malware);
        assert_eq!(
            index.lookup("x.cdn.bad.example.com").unwrap().1,
            ThreatKind::Malware
        );
        assert_eq!(
            index.lookup("other.example.com").unwrap().1,
            ThreatKind::Phishing
        );
    }

    #[test]
    fn cidr_index_prefers_the_most_specific_block() {
        let mut index = CidrIndex::new();
        index.insert(ip("203.0.113.0"), 24, ThreatKind::HijackedNetblock);
        index.insert(ip("203.0.113.66"), 32, ThreatKind::CommandAndControl);
        assert_eq!(
            index.lookup(ip("203.0.113.66")),
            Some(("203.0.113.66/32".to_string(), ThreatKind::CommandAndControl))
        );
        assert_eq!(
            index.lookup(ip("203.0.113.10")),
            Some(("203.0.113.0/24".to_string(), ThreatKind::HijackedNetblock))
        );
        assert_eq!(index.lookup(ip("203.0.114.10")), None);
    }

    #[test]
    fn cidr_index_masks_misaligned_networks_and_handles_v6() {
        let mut index = CidrIndex::new();
        index.insert(ip("10.1.2.3"), 8, ThreatKind::HijackedNetblock);
        assert_eq!(index.lookup(ip("10.200.0.1")).unwrap().0, "10.0.0.0/8");
        index.insert(ip("2001:db8::1"), 32, ThreatKind::Malware);
        assert!(index.lookup(ip("2001:db8:1::1")).is_some());
        assert!(index.lookup(ip("2001:db9::1")).is_none());
        index.insert(ip("192.0.2.0"), 33, ThreatKind::Malware);
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn allowlist_wins_over_a_block_and_covers_subdomains() {
        let mut shield = Shield::default();
        shield.load_domains(["example.com"], ThreatKind::Malware);
        assert!(shield.classify_domain("cdn.example.com").is_some());
        shield.allow_domain("example.com");
        assert!(shield.classify_domain("cdn.example.com").is_none());
        assert!(shield.classify_domain("example.org").is_none());
        shield.clear_allowlist();
        assert!(shield.classify_domain("cdn.example.com").is_some());
    }

    #[test]
    fn allowlist_exempts_a_single_address_only() {
        let mut shield = Shield::default();
        shield.load_cidrs([(ip("198.51.100.0"), 24)], ThreatKind::CommandAndControl);
        shield.allow_ip(ip("198.51.100.7"));
        assert!(shield.classify_ip(ip("198.51.100.7")).is_none());
        assert!(shield.classify_ip(ip("198.51.100.8")).is_some());
    }

    #[test]
    fn recording_blocks_keeps_a_bounded_ring_buffer() {
        let mut shield = Shield::default();
        shield.load_domains(
            (0..RECENT_CAPACITY + 10).map(|i| format!("host{i}.bad.example")),
            ThreatKind::Malware,
        );
        for i in 0..RECENT_CAPACITY + 10 {
            let verdict = shield
                .classify_domain(&format!("host{i}.bad.example"))
                .expect("blocked");
            shield.record(&format!("host{i}.bad.example"), &verdict);
        }
        let recent = shield.recent(usize::MAX);
        assert_eq!(recent.len(), RECENT_CAPACITY, "the buffer is bounded");
        assert_eq!(
            recent.last().unwrap().value,
            format!("host{}.bad.example", RECENT_CAPACITY + 9),
            "the newest block is last"
        );
        assert_eq!(
            recent.first().unwrap().value,
            "host10.bad.example",
            "the oldest entries are the ones dropped"
        );
        assert_eq!(shield.recent(3).len(), 3);
    }

    #[test]
    fn the_toggle_gates_blocking_and_recording() {
        let _guard = test_guard();
        reset();
        set_enabled(false);
        load_domains(["c2.example"], ThreatKind::CommandAndControl);
        assert!(!blocks_domain("c2.example"), "off means no blocking");
        assert!(recent_blocks(usize::MAX).is_empty(), "and nothing recorded");

        set_enabled(true);
        assert!(blocks_domain("c2.example"));
        assert!(!blocks_domain("innocent.example"));
        let recent = recent_blocks(usize::MAX);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].kind, ThreatKind::CommandAndControl);
        assert_eq!(recent[0].indicator, Indicator::Domain);

        assert!(blocked_total() >= 1);
        set_enabled(false);
        reset();
    }

    #[test]
    fn an_empty_shield_blocks_nothing() {
        let _guard = test_guard();
        reset();
        set_enabled(true);
        assert!(!blocks_domain("anything.example"));
        assert!(!blocks_ip(ip("203.0.113.5")));
        assert!(recent_blocks(10).is_empty());
        set_enabled(false);
    }
}
