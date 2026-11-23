//! `.vb` — a local DNS stub for mesh names.
//!
//! Names are the interface people actually use, and a mesh that only accepts
//! `fd7b::a1b2:…` addresses will never be used by anyone who is not debugging it.
//! This module answers `<name>.vb` on a loopback resolver (`127.0.0.53:53` by
//! default) with a deterministic ULA address derived from the device's node id:
//!
//! ```text
//!   fd7b : <NodeID[0..14]>
//!   └──/16      └── 112 bits of the node's own identifier
//! ```
//!
//! Two properties matter:
//!
//! * **Self-certifying.** The address is a pure function of the node id, so a
//!   name cannot be silently re-pointed at another device — there is no zone file
//!   to poison and no registrar to coerce. The name-to-node binding is the thing
//!   that gets gossiped, and it is signed there (see
//!   [`crate::ghost::net::discovery::PeerDescriptorV2`]).
//! * **Local only.** The stub binds loopback. It never forwards `<name>.vb`
//!   upstream, because leaking a private name to a public resolver would defeat
//!   the point; anything outside the zone is answered `REFUSED` so the OS
//!   resolver falls through to its next server instead of hanging.
//!
//! The responder implements enough of RFC 1035 for `AAAA` lookups and `PTR`
//! reverse lookups, with no compression on the way out (a stub this small gains
//! nothing from it, and uncompressed names are auditable).

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// The zone this stub is authoritative for.
pub const VB_ZONE: &str = "vb";

/// Default listener. `127.0.0.53` is the systemd-resolved stub address, chosen
/// because it is already reserved for a local resolver on Linux.
pub const VB_DNS_BIND: &str = "127.0.0.53:53";

/// ULA prefix bytes: `fd7b::/16`, the locally-assigned range this mesh uses.
pub const ULA_PREFIX: [u8; 2] = [0xfd, 0x7b];

/// DNS record type AAAA.
const QTYPE_AAAA: u16 = 28;
/// DNS record type PTR.
const QTYPE_PTR: u16 = 12;
/// IN class.
const QCLASS_IN: u16 = 1;

/// RCODE NOERROR.
const RCODE_OK: u8 = 0;
/// RCODE NXDOMAIN.
const RCODE_NXDOMAIN: u8 = 3;
/// RCODE REFUSED — used for names outside the zone so the OS resolver moves on.
const RCODE_REFUSED: u8 = 5;

/// A mesh name: one lowercase label, no dots, at most 63 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VbName(String);

impl VbName {
    /// Parse `name.vb` / `name.vb.` / `NAME.VB`. Returns `None` for anything that
    /// is not exactly one valid label in the zone.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim().trim_end_matches('.');
        let (label, zone) = trimmed.rsplit_once('.')?;
        if !zone.eq_ignore_ascii_case(VB_ZONE) {
            return None;
        }
        if label.is_empty() || label.len() > 63 || label.contains('.') {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        let mut out = String::with_capacity(label.len());
        for ch in label.chars() {
            let c = ch.to_ascii_lowercase();
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return None;
            }
            out.push(c);
        }
        Some(VbName(out))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The fully-qualified form used on the wire.
    pub fn fqdn(&self) -> String {
        format!("{}.{}", self.0, VB_ZONE)
    }

    /// A label that *is* the hex of a 14-byte node id resolves without any
    /// registry entry. This is the self-certifying case: the name is the key.
    pub fn embedded_node_id(&self) -> Option<[u8; 16]> {
        let label = self.0.as_str();
        if label.len() != 28 {
            return None;
        }
        let bytes = hex::decode(label).ok()?;
        if bytes.len() != 14 {
            return None;
        }
        let mut id = [0u8; 16];
        id[..14].copy_from_slice(&bytes);
        Some(id)
    }
}

impl std::fmt::Display for VbName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.fqdn())
    }
}

/// The ULA address for a node id: `fd7b:` followed by the first 14 bytes.
pub fn ula_for_node(node_id: &[u8; 16]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0..2].copy_from_slice(&ULA_PREFIX);
    octets[2..16].copy_from_slice(&node_id[0..14]);
    Ipv6Addr::from(octets)
}

/// Recover a node id from a ULA in this prefix. The last two bytes are not
/// carried by the address, so they come back as zero — enough to look a device
/// up by its mesh address, not enough to re-sign as it.
pub fn node_from_ula(addr: &Ipv6Addr) -> Option<[u8; 16]> {
    let o = addr.octets();
    if o[0..2] != ULA_PREFIX {
        return None;
    }
    let mut id = [0u8; 16];
    id[..14].copy_from_slice(&o[2..16]);
    Some(id)
}

/// A first-label name that is not the hex of a node id gets a stable,
/// collision-resistant node id derived from the name itself. These names are
/// only resolvable while the registry holds them; the derivation exists so the
/// address is reproducible across restarts rather than random.
pub fn synthetic_node_id(name: &VbName) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"VB-NAME-V1");
    h.update(name.as_str().as_bytes());
    let d = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    id
}

/// Name ↔ node bindings, with a reverse index for `PTR`.
#[derive(Debug, Default)]
pub struct NameRegistry {
    forward: DashMap<String, [u8; 16]>,
    reverse: DashMap<Ipv6Addr, String>,
}

impl NameRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a name to a node. Rebinding a name drops the old reverse entry so a
    /// stale PTR can never point at a device that no longer holds the name.
    pub fn bind(&self, name: VbName, node_id: [u8; 16]) {
        let addr = ula_for_node(&node_id);
        if let Some((_, old)) = self.forward.remove(name.as_str()) {
            let old_addr = ula_for_node(&old);
            self.reverse.remove(&old_addr);
        }
        self.reverse.insert(addr, name.as_str().to_string());
        self.forward.insert(name.0, node_id);
    }

    pub fn unbind(&self, name: &VbName) {
        if let Some((_, node)) = self.forward.remove(name.as_str()) {
            self.reverse.remove(&ula_for_node(&node));
        }
    }

    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Snapshot for `GET /api/v2/vbdns`.
    pub fn list(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .forward
            .iter()
            .map(|e| {
                (
                    format!("{}.{}", e.key(), VB_ZONE),
                    ula_for_node(e.value()).to_string(),
                )
            })
            .collect();
        out.sort();
        out
    }

    /// Resolve a name to an address. Forward entries win; the self-certifying
    /// hex form works without one.
    pub fn resolve(&self, name: &VbName) -> Option<Ipv6Addr> {
        if let Some(entry) = self.forward.get(name.as_str()) {
            return Some(ula_for_node(entry.value()));
        }
        name.embedded_node_id().map(|id| ula_for_node(&id))
    }

    pub fn reverse(&self, addr: &Ipv6Addr) -> Option<String> {
        self.reverse.get(addr).map(|e| e.value().clone())
    }
}

/// One parsed question out of a DNS request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Whether the request had the recursion-desired bit set.
    pub recursion_desired: bool,
}

/// Encode a domain name as uncompressed DNS labels.
fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    if out.len() > 255 {
        return None;
    }
    Some(out)
}

/// Decode a name at `offset`. Compression pointers are refused: a stub that
/// answers a handful of local names has no reason to follow a pointer into a
/// packet it did not author, and refusing removes a parsing hazard outright.
fn decode_name(msg: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut total = 0usize;
    loop {
        let len = *msg.get(offset)? as usize;
        offset = offset.checked_add(1)?;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let next_off = offset.checked_add(len)?;
        if len > 63 || next_off > msg.len() {
            return None;
        }
        total = total.saturating_add(len).saturating_add(1);
        if total > 255 {
            return None;
        }
        let label = std::str::from_utf8(msg.get(offset..next_off)?).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset = next_off;
    }
    Some((labels.join("."), offset))
}

/// Parse a DNS query. Answers `None` for anything that is not a single-question
/// standard query, which is all this stub serves.
pub fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    // QR must be 0 (query) and OPCODE 0 (standard query).
    if flags & 0x8000 != 0 || (flags >> 11) & 0x0F != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount != 1 {
        return None;
    }
    let (name, mut off) = decode_name(msg, 12)?;
    if off + 4 > msg.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
    let qclass = u16::from_be_bytes([msg[off + 2], msg[off + 3]]);
    off += 4;

    let mut end = off;
    if end < msg.len() && msg[end] == 0 {
        end += 1;
    }
    let _ = end;
    Some(Question {
        id,
        name,
        qtype,
        qclass,
        recursion_desired: flags & 0x0100 != 0,
    })
}

/// Build a standard response. `answers` is a list of (name, rdata) pairs; the
/// caller decides the type so the encoder stays dumb and testable.
fn build_response(
    q: &Question,
    rcode: u8,
    qtype: u16,
    answers: &[(String, Vec<u8>)],
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&q.id.to_be_bytes());
    let mut flags: u16 = 0x8000; // QR
    if q.recursion_desired {
        flags |= 0x0100; // RD copied
    }
    flags |= 0x0080; // RA: this stub is the resolver for the zone
    flags |= rcode as u16;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    out.extend_from_slice(&encode_name(&q.name)?);
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());

    for (name, rdata) in answers {
        out.extend_from_slice(&encode_name(name)?);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&QCLASS_IN.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes()); // TTL: short, names move
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    Some(out)
}

/// `fd7b::…` → `<reverse nibbles>.ip6.arpa`
pub fn ptr_name(addr: &Ipv6Addr) -> String {
    let hex = hex::encode(addr.octets());
    let mut labels: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
    labels.push("ip6".into());
    labels.push("arpa".into());
    labels.join(".")
}

/// Parse the IPv6 address out of a `PTR` question in `ip6.arpa`.
fn addr_from_ptr_name(name: &str) -> Option<Ipv6Addr> {
    let stripped = name
        .strip_suffix(".ip6.arpa")
        .or_else(|| name.strip_suffix("ip6.arpa"))?;
    let nibbles: Vec<&str> = stripped
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();
    if nibbles.len() != 32 {
        return None;
    }
    let mut hex = String::with_capacity(32);
    for n in nibbles.iter().rev() {
        if n.len() != 1 || !n.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        hex.push_str(n);
    }
    let bytes = hex::decode(hex).ok()?;
    let arr: [u8; 16] = bytes.try_into().ok()?;
    Some(Ipv6Addr::from(arr))
}

/// Answer one DNS message. Returns `None` when the message is not a query this
/// stub understands (the caller then stays silent, which is what a resolver
/// expects from a port that only serves one zone).
pub fn answer(registry: &NameRegistry, msg: &[u8]) -> Option<Vec<u8>> {
    let q = parse_question(msg)?;
    if q.qclass != QCLASS_IN {
        return build_response(&q, RCODE_REFUSED, q.qtype, &[]);
    }

    // Outside the zone: refuse rather than recurse. The OS resolver treats
    // REFUSED as "ask someone else", so ordinary browsing keeps working.
    // `ip6.arpa` is in scope because reverse lookups for our own ULA addresses
    // live there; everything else outside `.vb` is refused.
    let lower = q.name.trim_end_matches('.').to_ascii_lowercase();
    let in_zone = lower == VB_ZONE
        || lower.ends_with(&format!(".{VB_ZONE}"))
        || (q.qtype == QTYPE_PTR && lower.ends_with("ip6.arpa"));
    if !in_zone {
        return build_response(&q, RCODE_REFUSED, q.qtype, &[]);
    }

    match q.qtype {
        QTYPE_AAAA => {
            let Some(name) = VbName::parse(&q.name) else {
                return build_response(&q, RCODE_NXDOMAIN, q.qtype, &[]);
            };
            match registry.resolve(&name) {
                Some(addr) => build_response(
                    &q,
                    RCODE_OK,
                    QTYPE_AAAA,
                    &[(q.name.clone(), addr.octets().to_vec())],
                ),
                None => build_response(&q, RCODE_NXDOMAIN, q.qtype, &[]),
            }
        }
        QTYPE_PTR => {
            let addr = addr_from_ptr_name(&q.name)?;
            match registry.reverse(&addr) {
                Some(label) => {
                    let target = format!("{label}.{VB_ZONE}");
                    let rdata = encode_name(&target)?;
                    build_response(&q, RCODE_OK, QTYPE_PTR, &[(q.name.clone(), rdata)])
                }
                None => build_response(&q, RCODE_NXDOMAIN, q.qtype, &[]),
            }
        }
        // An A lookup on a `.vb` name is a real answer: there is no IPv4 in the
        // mesh, so NOERROR with no answers is more truthful than NXDOMAIN.
        _ => build_response(&q, RCODE_OK, q.qtype, &[]),
    }
}

/// Build a query, used by tests and by the CLI's `ggn vb-dns --check`.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&encode_name(name)?);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Some(out)
}

/// Pull the first AAAA rdata out of a response. Test/CLI helper.
pub fn first_aaaa(msg: &[u8]) -> Option<Ipv6Addr> {
    // Skip header + question without re-deriving offsets: walk from the answer
    // count instead.
    if msg.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    if ancount == 0 {
        return None;
    }
    let (_, mut off) = decode_name(msg, 12)?;
    off = off.checked_add(4)?;
    for _ in 0..ancount {
        let (_, next) = decode_name(msg, off)?;
        off = next;
        let hdr_end = off.checked_add(10)?;
        if hdr_end > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        off = hdr_end;
        let rdata_end = off.checked_add(rdlen)?;
        if rdata_end > msg.len() {
            return None;
        }
        if rtype == QTYPE_AAAA && rdlen == 16 {
            let mut o = [0u8; 16];
            o.copy_from_slice(msg.get(off..rdata_end)?);
            return Some(Ipv6Addr::from(o));
        }
        off = rdata_end;
    }
    None
}

/// Spawn the UDP responder. Returns the bound address so the caller can print
/// it (including the OS-assigned port when binding `:0`).
pub async fn spawn(
    registry: Arc<NameRegistry>,
    bind: SocketAddr,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let sock = Arc::new(UdpSocket::bind(bind).await?);
    let addr = sock.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            if let Some(resp) = answer(&registry, &buf[..n]) {
                let _ = sock.send_to(&resp, from).await;
            }
        }
    });
    Ok((addr, task))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> [u8; 16] {
        let mut id = [0u8; 16];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        id
    }

    #[test]
    fn names_are_strictly_normalised() {
        assert_eq!(VbName::parse("Laptop.VB").unwrap().as_str(), "laptop");
        assert_eq!(VbName::parse("laptop.vb.").unwrap().fqdn(), "laptop.vb");
        assert!(VbName::parse("two.labels.vb").is_none());
        assert!(VbName::parse("bad_name.vb").is_none());
        assert!(VbName::parse("-edge.vb").is_none());
        assert!(VbName::parse("laptop.com").is_none());
    }

    #[test]
    fn ula_is_deterministic_and_recoverable() {
        let id = node();
        let a = ula_for_node(&id);
        assert_eq!(a.octets()[0], 0xfd);
        assert_eq!(a.octets()[1], 0x7b);
        assert_eq!(a.octets()[2..], id[..14]);
        assert_eq!(ula_for_node(&id), a, "same node id, same address");
        assert_eq!(node_from_ula(&a).unwrap()[..14], id[..14]);
        // A v6 address outside the prefix is not ours.
        assert!(node_from_ula(&"2001:db8::1".parse().unwrap()).is_none());
    }

    #[test]
    fn aaaa_lookup_round_trips_on_the_wire() {
        let registry = NameRegistry::new();
        let id = node();
        registry.bind(VbName::parse("laptop.vb").unwrap(), id);

        let query = build_query(0x1234, "laptop.vb", QTYPE_AAAA).unwrap();
        let parsed = parse_question(&query).unwrap();
        assert_eq!(parsed.name, "laptop.vb");
        assert_eq!(parsed.qtype, QTYPE_AAAA);

        let resp = answer(&registry, &query).unwrap();
        assert_eq!(&resp[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(resp[3] & 0x0F, RCODE_OK);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert_eq!(first_aaaa(&resp).unwrap(), ula_for_node(&id));
    }

    #[test]
    fn unknown_name_is_nxdomain_and_foreign_zone_is_refused() {
        let registry = NameRegistry::new();
        let q = build_query(1, "nobody.vb", QTYPE_AAAA).unwrap();
        let resp = answer(&registry, &q).unwrap();
        assert_eq!(resp[3] & 0x0F, RCODE_NXDOMAIN);

        let q = build_query(2, "example.com", QTYPE_AAAA).unwrap();
        let resp = answer(&registry, &q).unwrap();
        assert_eq!(resp[3] & 0x0F, RCODE_REFUSED);
    }

    #[test]
    fn self_certifying_hex_label_needs_no_registry() {
        let id = node();
        let label = hex::encode(&id[..14]);
        let name = VbName::parse(&format!("{label}.vb")).unwrap();
        let registry = NameRegistry::new();
        assert_eq!(registry.resolve(&name), Some(ula_for_node(&id)));
    }

    #[test]
    fn ptr_lookup_returns_the_bound_name() {
        let registry = NameRegistry::new();
        let id = node();
        registry.bind(VbName::parse("desk.vb").unwrap(), id);
        let addr = ula_for_node(&id);
        let ptr = ptr_name(&addr);
        let q = build_query(7, &ptr, QTYPE_PTR).unwrap();
        let resp = answer(&registry, &q).unwrap();
        assert_eq!(resp[3] & 0x0F, RCODE_OK);
        // The rdata is the compressed-free name of the record.
        let tail = &resp[resp.len() - ("desk.vb".len() + 2)..];
        assert_eq!(tail, b"\x04desk\x02vb\x00");
    }

    #[test]
    fn rebinding_clears_the_old_reverse_entry() {
        let registry = NameRegistry::new();
        let name = VbName::parse("phone.vb").unwrap();
        let a = node();
        let mut b = node();
        b[0] = 0xEE;
        registry.bind(name.clone(), a);
        registry.bind(name, b);
        assert!(registry.reverse(&ula_for_node(&a)).is_none());
        assert_eq!(
            registry.reverse(&ula_for_node(&b)).as_deref(),
            Some("phone")
        );
        assert_eq!(registry.list().len(), 1);
    }

    #[tokio::test]
    async fn live_udp_stub_answers() {
        let registry = Arc::new(NameRegistry::new());
        let id = node();
        registry.bind(VbName::parse("mesh.vb").unwrap(), id);
        let (addr, task) = spawn(Arc::clone(&registry), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_query(99, "mesh.vb", QTYPE_AAAA).unwrap();
        client.send_to(&query, addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("stub answered within 2s")
        .unwrap();
        assert_eq!(first_aaaa(&buf[..n]).unwrap(), ula_for_node(&id));
        task.abort();
    }
}
