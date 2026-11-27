//! Default exit egress policy (`docs/anti_abuse.md` §2).
//!
//! An exit node dials targets on behalf of a peer, so an over-broad allowlist turns
//! a volunteer relay into an open proxy. This module is the floor beneath the
//! operator's `GHOST_TUNNEL_ALLOW` list: even a target that list permits is refused
//! here unless it is ordinary, public, routable traffic.
//!
//! Blocked by default:
//!
//! * **TCP/25 (SMTP)** — the classic spam-relay abuse, and never what a user means
//!   when they ask for a port forward.
//! * **Loopback** (`127.0.0.0/8`, `::1`) — a target on the exit's own host.
//! * **Private / RFC1918** (`10/8`, `172.16/12`, `192.168/16`) and **IPv6 ULA**
//!   (`fc00::/7`) — the LAN behind the exit.
//! * **Link-local** (`169.254.0.0/16`, `fe80::/10`), which includes the cloud
//!   metadata endpoint `169.254.169.254` — the SSRF pivot that hands out
//!   credentials.
//! * **Carrier-grade NAT** (`100.64/10`), unspecified, multicast and reserved space.
//! * The **name** `localhost` and any `*.localhost`, so the rule cannot be spelled
//!   around.
//!
//! Two operator escape hatches, both opt-in and both narrow:
//!
//! * `GHOST_EXIT_EGRESS_LAN=1` — home-exit / LAN-over-WAN use. Permits loopback,
//!   RFC1918, ULA and CGNAT. It does **not** permit link-local: a metadata endpoint
//!   is never a legitimate home-exit target, so that stays shut.
//! * `GHOST_EXIT_EGRESS_SMTP=1` — permit TCP/25 deliberately.
//! * `GHOST_EXIT_EGRESS_ALLOW=10.0.0.5:5432,...` — exact `host:port` exceptions for
//!   one-off internal services, checked before any rule below.
//!
//! The check runs on **resolved addresses**, not just on the literal the peer sent:
//! [`Policy::resolve`] looks the target up and hands the caller an address that
//! already passed, so a name that resolves into a blocked range cannot slip through
//! a DNS answer the peer controls.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    pub reason: &'static str,
}

impl Denied {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    lan: bool,
    smtp: bool,
    allow: Vec<String>,
}

impl Policy {
    pub fn strict() -> Self {
        Self::default()
    }

    pub fn with_lan(mut self, yes: bool) -> Self {
        self.lan = yes;
        self
    }

    pub fn with_smtp(mut self, yes: bool) -> Self {
        self.smtp = yes;
        self
    }

    pub fn with_allow_entry(mut self, entry: &str) -> Self {
        let entry = normalize(entry);
        if !entry.is_empty() {
            self.allow.push(entry);
        }
        self
    }

    pub fn with_allow_entries(mut self, entries: impl IntoIterator<Item = String>) -> Self {
        for entry in entries {
            self = self.with_allow_entry(&entry);
        }
        self
    }

    fn is_named(&self, target: &str) -> bool {
        self.allow.contains(&normalize(target))
    }

    pub fn check(&self, target: &str) -> Result<(), Denied> {
        let target = normalize(target);
        if target.is_empty() {
            return Err(Denied::new("empty target"));
        }
        let (host, port) = split_host_port(&target).ok_or(Denied::new("malformed target"))?;
        self.check_port(port)?;
        if self.is_named(&target) {
            return Ok(());
        }
        match host.parse::<IpAddr>() {
            Ok(ip) => self.check_addr(SocketAddr::new(ip, port)),
            Err(_) => {
                let host = host.trim_end_matches('.').to_ascii_lowercase();
                if host == "localhost" || host.ends_with(".localhost") {
                    return self.lan_ok("loopback target");
                }
                Ok(())
            }
        }
    }

    pub fn check_addr(&self, addr: SocketAddr) -> Result<(), Denied> {
        self.check_port(addr.port())?;
        if self.allow.contains(&normalize(&addr.to_string())) {
            return Ok(());
        }
        match addr.ip() {
            IpAddr::V4(ip) => self.check_v4(ip),
            IpAddr::V6(ip) => self.check_v6(ip),
        }
    }

    pub async fn resolve(&self, target: &str) -> Result<SocketAddr, Denied> {
        self.check(target)?;
        let named = self.is_named(target);
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target)
            .await
            .map_err(|_| Denied::new("target does not resolve"))?
            .collect();
        if addrs.is_empty() {
            return Err(Denied::new("target does not resolve"));
        }
        if named {
            return Ok(addrs[0]);
        }
        let mut first: Option<Denied> = None;
        for addr in addrs {
            match self.check_addr(addr) {
                Ok(()) => return Ok(addr),
                Err(denied) => {
                    first.get_or_insert(denied);
                }
            }
        }
        Err(first.unwrap_or(Denied::new("target does not resolve")))
    }

    fn check_port(&self, port: u16) -> Result<(), Denied> {
        if port == 25 && !self.smtp {
            return Err(Denied::new("smtp port 25 is blocked on exits"));
        }
        Ok(())
    }

    fn check_v4(&self, ip: Ipv4Addr) -> Result<(), Denied> {
        let in_net = |net: [u8; 4], prefix: u8| in_v4(ip, net, prefix);
        if ip.is_unspecified() {
            return Err(Denied::new("unspecified address"));
        }
        if in_net([169, 254, 0, 0], 16) {
            return Err(Denied::new("link-local target"));
        }
        if ip.is_loopback() {
            return self.lan_ok("loopback target");
        }
        if in_net([10, 0, 0, 0], 8) || in_net([172, 16, 0, 0], 12) || in_net([192, 168, 0, 0], 16) {
            return self.lan_ok("private address");
        }
        if in_net([100, 64, 0, 0], 10) {
            return self.lan_ok("carrier-grade NAT address");
        }
        if ip.is_multicast() || in_net([240, 0, 0, 0], 4) {
            return Err(Denied::new("reserved address"));
        }
        Ok(())
    }

    fn check_v6(&self, ip: Ipv6Addr) -> Result<(), Denied> {
        if ip.is_unspecified() {
            return Err(Denied::new("unspecified address"));
        }
        if let Some(v4) = ip.to_ipv4_mapped() {
            return self.check_v4(v4);
        }
        let segments = ip.segments();
        if (segments[0] & 0xffc0) == 0xfe80 {
            return Err(Denied::new("link-local target"));
        }
        if ip.is_loopback() {
            return self.lan_ok("loopback target");
        }
        if (segments[0] & 0xfe00) == 0xfc00 {
            return self.lan_ok("private address");
        }
        if (segments[0] & 0xff00) == 0xff00 {
            return Err(Denied::new("reserved address"));
        }
        Ok(())
    }

    fn lan_ok(&self, reason: &'static str) -> Result<(), Denied> {
        if self.lan {
            Ok(())
        } else {
            Err(Denied::new(reason))
        }
    }
}

pub fn policy() -> Policy {
    Policy {
        lan: env_flag("GHOST_EXIT_EGRESS_LAN"),
        smtp: env_flag("GHOST_EXIT_EGRESS_SMTP"),
        allow: std::env::var("GHOST_EXIT_EGRESS_ALLOW")
            .unwrap_or_default()
            .split(',')
            .map(normalize)
            .filter(|entry| !entry.is_empty())
            .collect(),
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn normalize(entry: &str) -> String {
    entry.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn split_host_port(target: &str) -> Option<(&str, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    let (host, port) = target.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    Some((host, port.parse().ok()?))
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_is_blocked_until_the_operator_opts_in() {
        assert_eq!(
            Policy::strict()
                .check("mail.example.com:25")
                .unwrap_err()
                .reason,
            "smtp port 25 is blocked on exits"
        );
        assert!(Policy::strict()
            .with_smtp(true)
            .check("mail.example.com:25")
            .is_ok());
        assert!(Policy::strict().check("mail.example.com:587").is_ok());
    }

    #[test]
    fn loopback_private_and_metadata_targets_are_blocked_by_default() {
        let policy = Policy::strict();
        for (target, reason) in [
            ("127.0.0.1:8080", "loopback target"),
            ("127.9.9.9:443", "loopback target"),
            ("10.0.0.5:5432", "private address"),
            ("172.20.1.1:22", "private address"),
            ("192.168.1.1:80", "private address"),
            ("100.64.0.1:80", "carrier-grade NAT address"),
            ("169.254.169.254:80", "link-local target"),
            ("[::1]:80", "loopback target"),
            ("[fd00::1]:80", "private address"),
            ("[fe80::1]:80", "link-local target"),
            ("0.0.0.0:80", "unspecified address"),
        ] {
            assert_eq!(
                policy.check(target).unwrap_err().reason,
                reason,
                "{target} must be refused"
            );
        }
    }

    #[test]
    fn public_targets_pass() {
        let policy = Policy::strict();
        for target in [
            "93.184.216.34:443",
            "example.com:443",
            "dns.google:853",
            "[2606:4700::1111]:443",
        ] {
            assert!(policy.check(target).is_ok(), "{target} must pass");
        }
    }

    #[test]
    fn lan_mode_permits_a_home_lan_but_never_the_metadata_endpoint() {
        let home = Policy::strict().with_lan(true);
        assert!(home.check("192.168.1.10:22").is_ok());
        assert!(home.check("127.0.0.1:8080").is_ok());
        assert!(home.check("[fd00::1]:80").is_ok());
        assert_eq!(
            home.check("169.254.169.254:80").unwrap_err().reason,
            "link-local target",
            "a metadata pivot is not a home-exit target"
        );
    }

    #[test]
    fn exact_allow_entries_beat_the_range_rules() {
        let policy = Policy::strict().with_allow_entry("10.0.0.5:5432");
        assert!(policy.check("10.0.0.5:5432").is_ok());
        assert!(policy.check("10.0.0.5:5433").is_err());
        assert!(policy.check("10.0.0.6:5432").is_err());
    }

    #[test]
    fn a_named_target_is_honoured_without_lan_mode() {
        let policy = Policy::strict().with_allow_entries(vec![
            "127.0.0.1:8080".to_string(),
            "192.168.1.10:445".to_string(),
        ]);
        assert!(policy.check("127.0.0.1:8080").is_ok());
        assert!(policy.check("192.168.1.10:445").is_ok());
        assert_eq!(
            policy.check("127.0.0.1:8081").unwrap_err().reason,
            "loopback target"
        );
        assert_eq!(
            policy.check("10.0.0.5:5432").unwrap_err().reason,
            "private address"
        );
        assert_eq!(
            policy.check("169.254.169.254:80").unwrap_err().reason,
            "link-local target"
        );
    }

    #[test]
    fn the_smtp_floor_applies_to_literal_addresses_too() {
        let policy = Policy::strict().with_allow_entry("192.0.2.10:25");
        let addr: SocketAddr = "192.0.2.10:25".parse().expect("an address");
        assert_eq!(
            policy.check_addr(addr).unwrap_err().reason,
            "smtp port 25 is blocked on exits"
        );
        assert_eq!(
            policy.check("192.0.2.10:25").unwrap_err().reason,
            "smtp port 25 is blocked on exits"
        );
        assert!(policy.check_addr("192.0.2.10:443".parse().unwrap()).is_ok());
    }

    #[test]
    fn naming_a_target_does_not_lift_the_smtp_floor() {
        let policy = Policy::strict().with_allow_entries(vec!["127.0.0.1:25".to_string()]);
        assert_eq!(
            policy.check("127.0.0.1:25").unwrap_err().reason,
            "smtp port 25 is blocked on exits"
        );
    }

    #[test]
    fn localhost_by_name_is_refused() {
        let policy = Policy::strict();
        assert_eq!(
            policy.check("localhost:8080").unwrap_err().reason,
            "loopback target"
        );
        assert!(policy.check("api.localhost:8080").is_err());
        assert!(Policy::strict()
            .with_lan(true)
            .check("localhost:8080")
            .is_ok());
    }

    #[test]
    fn malformed_targets_are_refused_rather_than_dialled() {
        let policy = Policy::strict();
        assert_eq!(policy.check("").unwrap_err().reason, "empty target");
        assert_eq!(
            policy.check("example.com").unwrap_err().reason,
            "malformed target"
        );
        assert_eq!(
            policy.check(":8080").unwrap_err().reason,
            "malformed target"
        );
    }
}
