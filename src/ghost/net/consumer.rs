//! Consumer control-plane state for the Web Control Center.
//!
//! Everything a normal person can change from the dashboard — device names,
//! the system-VPN vs. SOCKS5 egress choice, and the split-tunnel bypass list —
//! lives in [`ConsumerSettings`]. The struct is plain serde so the node can
//! persist it to `ghost-consumer.json` next to `peers.cache` and reload it on
//! start.
//!
//! Two pieces are deliberately dependency-free because they run on the hot
//! path: [`ConsumerSettings::should_bypass`] (consulted per SOCKS5 CONNECT) and
//! [`derive_default_name`] (consulted per peer render).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Egress mode: bind a TUN adapter and route everything (the default a
/// consumer expects from a VPN).
pub const ROUTE_MODE_SYSTEM_VPN: &str = "system_vpn";
/// Egress mode: leave the OS routing table alone; only apps pointed at the
/// local SOCKS5 listener use the mesh.
pub const ROUTE_MODE_APP_SOCKS: &str = "app_socks";
/// Default egress mode — never hijacks the system routing table implicitly.
pub const DEFAULT_ROUTE_MODE: &str = ROUTE_MODE_APP_SOCKS;

/// Maximum number of user-entered bypass rules we will store.
pub const MAX_BYPASS_ENTRIES: usize = 500;
/// Maximum length of a single bypass rule or device name.
pub const MAX_RULE_LEN: usize = 253;

const ADJECTIVES: [&str; 16] = [
    "amber", "brisk", "calm", "dusk", "ember", "frosty", "gentle", "hazel", "ivory", "lunar",
    "misty", "noble", "quiet", "rapid", "silver", "warm",
];
const NOUNS: [&str; 16] = [
    "falcon", "heron", "otter", "panda", "raven", "sparrow", "tapir", "urchin", "vireo", "walrus",
    "yak", "zebra", "finch", "lark", "marten", "tern",
];

/// Map a free-form mode string (env, API, config file) onto a known mode.
pub fn normalize_route_mode(mode: &str) -> Option<&'static str> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "system_vpn" | "system" | "vpn" | "tun" | "full" => Some(ROUTE_MODE_SYSTEM_VPN),
        "app_socks" | "app" | "socks" | "socks5" | "proxy" | "local" => Some(ROUTE_MODE_APP_SOCKS),
        _ => None,
    }
}

/// Normalise a self-reported platform string onto a stable OS key.
///
/// Peers that never reported a platform return `"unknown"` — we never guess a
/// device's OS from its fingerprint.
pub fn normalize_os(reported: Option<&str>) -> String {
    let Some(raw) = reported else {
        return "unknown".to_string();
    };
    let v = raw.trim().to_ascii_lowercase();
    let key = match v.as_str() {
        "" => return "unknown".to_string(),
        "win" | "windows" | "win32" | "win64" | "windows-nt" => "windows",
        "mac" | "macos" | "darwin" | "osx" | "apple" | "mac-os-x" => "macos",
        "linux" | "ubuntu" | "debian" | "fedora" | "arch" | "gnu-linux" => "linux",
        "android" => "android",
        "ios" | "ipados" => "ios",
        "freebsd" | "openbsd" | "netbsd" | "bsd" => "bsd",
        other => {
            // Unknown-but-specific strings are kept verbatim so the UI can show
            // the raw platform rather than pretending it is "unknown".
            return other.chars().take(32).collect();
        }
    };
    key.to_string()
}

/// The OS of the machine this node is running on.
pub fn local_os() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else {
        "unknown"
    }
}

/// Presence for a peer: an established session is `online`, a discovered
/// address with no session is `idle`.
pub fn peer_status(has_session: bool, discovered: bool) -> &'static str {
    if has_session {
        "online"
    } else if discovered {
        "idle"
    } else {
        "offline"
    }
}

/// Deterministic, friendly fallback name for a peer: `amber-otter-a7b0`.
///
/// The same fingerprint always yields the same name on every node, so two
/// people looking at the same peer see the same label before anyone renames it.
pub fn derive_default_name(fingerprint: &str) -> String {
    let fp = fingerprint.trim();
    if fp.is_empty() {
        return "unknown-device".to_string();
    }
    // FNV-1a: tiny, dependency-free, well-mixed for short hex strings.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in fp.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let adjective = ADJECTIVES[(hash % ADJECTIVES.len() as u64) as usize];
    let noun = NOUNS[((hash >> 16) % NOUNS.len() as u64) as usize];
    let tail: String = {
        let chars: Vec<char> = fp.chars().collect();
        chars[chars.len().saturating_sub(4)..].iter().collect()
    };
    format!("{adjective}-{noun}-{tail}")
}

/// True when `rule` looks like something that could actually resolve: a bare
/// hostname, a `*.wildcard`, or an exact IPv4 address. Rules that can never
/// match a real destination (spaces, punctuation, stray symbols) are rejected
/// rather than silently stored as dead weight.
fn looks_like_host(rule: &str) -> bool {
    if rule == "*" {
        return true;
    }
    let target = rule.strip_prefix("*.").unwrap_or(rule);
    if target.is_empty() || target.len() > MAX_RULE_LEN || target.starts_with('.') {
        return false;
    }
    if !target
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return false;
    }
    // No empty labels ("a..b"), and no label that starts or ends with a dash.
    target.split('.').all(|label| {
        !label.is_empty() && !label.starts_with('-') && !label.ends_with('-') && label.len() <= 63
    })
}

/// Strip a user-entered rule down to a comparable host/CIDR form.
fn normalize_rule(rule: &str) -> Option<String> {
    let mut v = rule.trim().to_ascii_lowercase();
    if v.is_empty() {
        return None;
    }
    // Accept pasted URLs ("https://netflix.com/browse") and be forgiving.
    for scheme in ["https://", "http://", "socks5://"] {
        if let Some(rest) = v.strip_prefix(scheme) {
            v = rest.to_string();
            break;
        }
    }
    v = v.split('/').next().unwrap_or("").to_string();
    // A pathless URL is indistinguishable from a plain host; re-split for CIDR.
    let raw = rule.trim().to_ascii_lowercase();
    if raw.contains('/') {
        let candidate = raw
            .strip_prefix("https://")
            .or_else(|| raw.strip_prefix("http://"))
            .unwrap_or(&raw);
        if candidate.parse::<Cidr>().is_ok() {
            return Some(candidate.trim().to_string());
        }
    }
    // Drop any port suffix.
    if let Some((host, port)) = v.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !host.contains(':') {
            v = host.to_string();
        }
    }
    let v = v.trim_end_matches('.').trim().to_string();
    if !looks_like_host(&v) {
        return None;
    }
    Some(v)
}

/// A parsed IPv4 CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    network: u32,
    prefix: u8,
}

impl std::str::FromStr for Cidr {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, p),
            None => (s, "32"),
        };
        let ip: Ipv4Addr = addr.trim().parse().map_err(|_| ())?;
        let prefix: u8 = prefix.trim().parse().map_err(|_| ())?;
        if prefix > 32 {
            return Err(());
        }
        Ok(Cidr {
            network: u32::from(ip),
            prefix,
        })
    }
}

impl Cidr {
    fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - u32::from(self.prefix));
        (u32::from(ip) & mask) == (self.network & mask)
    }
}

/// Split a `host` or `host:port` target into its host part.
fn host_part(host: &str) -> &str {
    let h = host.trim();
    if let Some((head, port)) = h.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !head.contains(':') {
            return head;
        }
    }
    h
}

/// True when `host` (or `host:port`) matches any rule in `rules`.
///
/// Supported rule shapes:
///   `*.netflix.com`  any subdomain of netflix.com (and netflix.com itself)
///   `netflix.com`    an exact host
///   `192.168.1.0/24` an IPv4 CIDR block
///   `10.0.0.5`       an exact IPv4 address
///   `*`              everything (an explicit full-tunnel bypass)
pub fn is_bypassed(rules: &[String], host: &str) -> bool {
    let target = host_part(host).trim_end_matches('.').to_ascii_lowercase();
    if target.is_empty() {
        return false;
    }
    let target_ip: Option<Ipv4Addr> = target.parse().ok();
    for rule in rules {
        if rule == "*" {
            return true;
        }
        if let Some(suffix) = rule.strip_prefix("*.") {
            if target == suffix || target.ends_with(&format!(".{suffix}")) {
                return true;
            }
            continue;
        }
        if let Some(suffix) = rule.strip_prefix('.') {
            if target == suffix || target.ends_with(&format!(".{suffix}")) {
                return true;
            }
            continue;
        }
        if rule.contains('/') {
            if let (Ok(cidr), Some(ip)) = (rule.parse::<Cidr>(), target_ip) {
                if cidr.contains(ip) {
                    return true;
                }
            }
            continue;
        }
        if let Ok(rule_ip) = rule.parse::<Ipv4Addr>() {
            if target_ip == Some(rule_ip) {
                return true;
            }
            continue;
        }
        // A bare hostname rule also covers its subdomains ("netflix.com").
        if target == *rule || (rule.contains('.') && target.ends_with(&format!(".{rule}"))) {
            return true;
        }
    }
    false
}

/// Everything the consumer control plane persists between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsumerSettings {
    /// One of [`ROUTE_MODE_SYSTEM_VPN`] / [`ROUTE_MODE_APP_SOCKS`].
    pub route_mode: String,
    /// Hosts/IPs/CIDRs that skip the mesh and use the local ISP directly.
    pub bypass: Vec<String>,
    /// fingerprint → user-chosen friendly name.
    pub device_names: HashMap<String, String>,
    /// fingerprint → self-reported platform key.
    pub device_os: HashMap<String, String>,
}

impl Default for ConsumerSettings {
    fn default() -> Self {
        Self {
            route_mode: DEFAULT_ROUTE_MODE.to_string(),
            bypass: Vec::new(),
            device_names: HashMap::new(),
            device_os: HashMap::new(),
        }
    }
}

impl ConsumerSettings {
    /// Build from an environment-provided default mode, ignoring junk values.
    pub fn with_mode(mode: Option<&str>) -> Self {
        let mut s = Self::default();
        if let Some(m) = mode {
            if let Some(valid) = normalize_route_mode(m) {
                s.route_mode = valid.to_string();
            }
        }
        s
    }

    /// Validate and set the egress mode. Returns false for unknown modes.
    pub fn set_route_mode(&mut self, mode: &str) -> bool {
        match normalize_route_mode(mode) {
            Some(valid) => {
                self.route_mode = valid.to_string();
                true
            }
            None => false,
        }
    }

    /// Add a bypass rule. Returns `Ok(true)` if it was newly added.
    pub fn add_bypass(&mut self, rule: &str) -> Result<bool, String> {
        let Some(normalized) = normalize_rule(rule) else {
            return Err(format!(
                "'{rule}' is not a usable host, wildcard or IP range"
            ));
        };
        if self.bypass.contains(&normalized) {
            return Ok(false);
        }
        if self.bypass.len() >= MAX_BYPASS_ENTRIES {
            return Err(format!(
                "bypass list is full ({MAX_BYPASS_ENTRIES} entries)"
            ));
        }
        self.bypass.push(normalized);
        Ok(true)
    }

    /// Remove a bypass rule, matching loosely so users need not type exactly.
    pub fn remove_bypass(&mut self, rule: &str) -> bool {
        let normalized = normalize_rule(rule).unwrap_or_else(|| rule.trim().to_ascii_lowercase());
        let before = self.bypass.len();
        self.bypass.retain(|r| *r != normalized && r != rule.trim());
        self.bypass.len() != before
    }

    /// True when traffic to `host` must leave through the local ISP.
    pub fn should_bypass(&self, host: &str) -> bool {
        is_bypassed(&self.bypass, host)
    }

    /// Set a device's friendly name, returning the stored value.
    pub fn set_device_name(&mut self, fingerprint: &str, name: &str) -> Result<String, String> {
        let fp = fingerprint.trim();
        if fp.is_empty() {
            return Err("missing fingerprint".to_string());
        }
        // Strip control characters so a name can never break the rendered UI.
        let cleaned: String = name
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_RULE_LEN)
            .collect();
        if cleaned.is_empty() {
            self.device_names.remove(fp);
            self.device_os.remove(fp);
            return Ok(self.device_name(fp));
        }
        self.device_names.insert(fp.to_string(), cleaned.clone());
        Ok(cleaned)
    }

    /// Rename back to the deterministic default.
    pub fn clear_device_name(&mut self, fingerprint: &str) -> String {
        self.device_names.remove(fingerprint);
        self.device_name(fingerprint)
    }

    /// Record a peer's self-reported platform.
    pub fn set_device_os(&mut self, fingerprint: &str, os: Option<&str>) -> String {
        let fp = fingerprint.trim();
        if fp.is_empty() {
            return "unknown".to_string();
        }
        let key = normalize_os(os);
        if key == "unknown" {
            self.device_os.remove(fp);
        } else {
            self.device_os.insert(fp.to_string(), key.clone());
        }
        key
    }

    /// The name to display for a peer: user choice, else the stable default.
    pub fn device_name(&self, fingerprint: &str) -> String {
        match self.device_names.get(fingerprint.trim()) {
            Some(name) if !name.trim().is_empty() => name.clone(),
            _ => derive_default_name(fingerprint),
        }
    }

    /// The platform to display for a peer; `"unknown"` when never reported.
    pub fn device_os(&self, fingerprint: &str) -> String {
        self.device_os
            .get(fingerprint.trim())
            .cloned()
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Whether the user has explicitly renamed this peer.
    pub fn has_custom_name(&self, fingerprint: &str) -> bool {
        self.device_names.contains_key(fingerprint.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_mode_normalization_accepts_synonyms_and_rejects_junk() {
        assert_eq!(normalize_route_mode("VPN"), Some(ROUTE_MODE_SYSTEM_VPN));
        assert_eq!(normalize_route_mode("tun"), Some(ROUTE_MODE_SYSTEM_VPN));
        assert_eq!(normalize_route_mode(" SOCKS5 "), Some(ROUTE_MODE_APP_SOCKS));
        assert_eq!(normalize_route_mode("open-relay"), None);
    }

    #[test]
    fn settings_default_to_socks_and_never_hijack_routing_implicitly() {
        let mut s = ConsumerSettings::default();
        assert_eq!(s.route_mode, ROUTE_MODE_APP_SOCKS);
        assert!(!s.set_route_mode("not-a-mode"));
        assert_eq!(s.route_mode, ROUTE_MODE_APP_SOCKS);
        assert!(s.set_route_mode("system_vpn"));
        assert_eq!(s.route_mode, ROUTE_MODE_SYSTEM_VPN);
    }

    #[test]
    fn bypass_exact_host_wildcard_ip_and_cidr() {
        let mut s = ConsumerSettings::default();
        assert!(s.add_bypass("banking.sparkasse.de").unwrap());
        assert!(s.add_bypass("*.netflix.com").unwrap());
        assert!(s.add_bypass("192.168.1.0/24").unwrap());
        assert!(s.add_bypass("10.0.0.5").unwrap());

        assert!(s.should_bypass("banking.sparkasse.de"));
        assert!(s.should_bypass("BANKING.SPARKASSE.DE:443"));
        assert!(!s.should_bypass("sparkasse.de"));

        assert!(s.should_bypass("www.netflix.com"));
        assert!(s.should_bypass("netflix.com"));
        assert!(!s.should_bypass("notnetflix.com"));

        assert!(s.should_bypass("192.168.1.42"));
        assert!(!s.should_bypass("192.168.2.42"));
        assert!(s.should_bypass("10.0.0.5"));
        assert!(!s.should_bypass("10.0.0.6"));
    }

    #[test]
    fn bypass_normalizes_pasted_urls_and_dedupes() {
        let mut s = ConsumerSettings::default();
        assert!(s.add_bypass("https://www.netflix.com/browse").unwrap());
        assert!(!s.add_bypass("www.netflix.com").unwrap(), "duplicate rule");
        assert_eq!(s.bypass, vec!["www.netflix.com".to_string()]);
        assert!(s.should_bypass("www.netflix.com"));
        assert!(s.remove_bypass("WWW.NETFLIX.COM"));
        assert!(!s.should_bypass("www.netflix.com"));
    }

    #[test]
    fn bypass_rejects_empty_and_absurd_rules() {
        let mut s = ConsumerSettings::default();
        assert!(s.add_bypass("   ").is_err());
        assert!(s.add_bypass(&"a".repeat(MAX_RULE_LEN + 1)).is_err());
        assert!(s.bypass.is_empty());
    }

    #[test]
    fn bypass_rejects_rules_that_could_never_match() {
        let mut s = ConsumerSettings::default();
        // A rule with spaces or punctuation can never match a host or an IP, so
        // storing it would just be a silent no-op the user could not explain.
        for junk in [
            "not a host!!",
            "has space.de",
            "http://",
            "exa mple.com",
            "a..b",
        ] {
            assert!(s.add_bypass(junk).is_err(), "should reject {junk:?}");
        }
        assert!(s.bypass.is_empty());
        // Real shapes still work.
        for good in [
            "banking.example.de",
            "*.netflix.com",
            "192.168.0.0/16",
            "10.0.0.5",
            "*",
        ] {
            assert!(s.add_bypass(good).is_ok(), "should accept {good:?}");
        }
    }

    #[test]
    fn bypass_wildcard_matches_everything() {
        let mut s = ConsumerSettings::default();
        s.add_bypass("*").unwrap();
        assert!(s.should_bypass("anything.example"));
    }

    #[test]
    fn device_names_are_stable_then_overridable() {
        let fp = "a7b0e681c4f20d93";
        let d1 = derive_default_name(fp);
        assert_eq!(d1, derive_default_name(fp), "must be deterministic");
        assert!(d1.ends_with("0d93"));
        assert_ne!(d1, derive_default_name("ffffffffffffffff"));

        let mut s = ConsumerSettings::default();
        assert_eq!(s.device_name(fp), d1);
        assert!(!s.has_custom_name(fp));
        assert_eq!(
            s.set_device_name(fp, "Lukas-MacBook").unwrap(),
            "Lukas-MacBook"
        );
        assert!(s.has_custom_name(fp));
        assert_eq!(s.device_name(fp), "Lukas-MacBook");
        assert_eq!(s.clear_device_name(fp), d1);
        assert!(!s.has_custom_name(fp));
    }

    #[test]
    fn device_names_strip_control_characters_and_bound_length() {
        let mut s = ConsumerSettings::default();
        let nasty = format!("Home{}Server{}", '\u{7}', "x".repeat(400));
        let stored = s.set_device_name("deadbeefdeadbeef", &nasty).unwrap();
        assert!(
            !stored.contains('\u{7}'),
            "control characters must be stripped"
        );
        assert!(stored.starts_with("HomeServer"));
        assert!(stored.len() <= MAX_RULE_LEN);
        // An all-whitespace name clears back to the default.
        let reset = s.set_device_name("deadbeefdeadbeef", "   ").unwrap();
        assert_eq!(reset, derive_default_name("deadbeefdeadbeef"));
    }

    #[test]
    fn os_reporting_is_normalized_and_never_guessed() {
        let mut s = ConsumerSettings::default();
        assert_eq!(s.device_os("aabbccddeeff0011"), "unknown");
        assert_eq!(s.set_device_os("aabbccddeeff0011", Some("Darwin")), "macos");
        assert_eq!(s.device_os("aabbccddeeff0011"), "macos");
        assert_eq!(s.set_device_os("aabbccddeeff0011", Some("")), "unknown");
        assert_eq!(s.device_os("aabbccddeeff0011"), "unknown");
        assert_eq!(normalize_os(Some("Win32")), "windows");
        assert_eq!(normalize_os(Some("Arch")), "linux");
    }

    #[test]
    fn presence_reflects_session_then_discovery() {
        assert_eq!(peer_status(true, true), "online");
        assert_eq!(peer_status(false, true), "idle");
        assert_eq!(peer_status(false, false), "offline");
    }

    #[test]
    fn settings_round_trip_through_json_and_tolerate_partial_documents() {
        let mut s = ConsumerSettings::default();
        s.set_route_mode(ROUTE_MODE_SYSTEM_VPN);
        s.add_bypass("*.netflix.com").unwrap();
        s.set_device_name("a7b0e681c4f20d93", "LivingRoom-PC")
            .unwrap();
        let json = serde_json::to_string(&s).unwrap();
        let back: ConsumerSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.route_mode, ROUTE_MODE_SYSTEM_VPN);
        assert_eq!(back.bypass, s.bypass);
        assert_eq!(back.device_name("a7b0e681c4f20d93"), "LivingRoom-PC");

        // An older/hand-edited file missing fields must still load.
        let partial: ConsumerSettings = serde_json::from_str("{\"bypass\":[\"x.de\"]}").unwrap();
        assert_eq!(partial.route_mode, DEFAULT_ROUTE_MODE);
        assert_eq!(partial.bypass, vec!["x.de".to_string()]);
    }
}
