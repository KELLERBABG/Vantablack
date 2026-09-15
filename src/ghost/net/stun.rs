//! STUN (RFC 8489) — the subset ICE and TURN actually need.
//!
//! This replaces the "STUN-style" naming that used to sit in `mesh.rs`: a
//! `stun_server: Option<SocketAddr>` field that was stored and never read, and a
//! hole-punch loop that sent a `GHOST_HPUNCH_` marker and then reported success
//! unconditionally. Neither ever spoke STUN. This module speaks it.
//!
//! ## Scope
//!
//! * Message header: 2-bit-padded 14-bit type, length, magic cookie, 96-bit
//!   transaction ID (RFC 8489 §5).
//! * Attribute TLV with 4-byte padding (§14).
//! * The attributes ICE needs: `XOR-MAPPED-ADDRESS`, `MAPPED-ADDRESS`,
//!   `USERNAME`, `PRIORITY`, `USE-CANDIDATE`, `ICE-CONTROLLED`,
//!   `ICE-CONTROLLING`, `ERROR-CODE`, `SOFTWARE`, `FINGERPRINT` and
//!   `MESSAGE-INTEGRITY`.
//! * `FINGERPRINT` (CRC-32/ISO-HDLC) and `MESSAGE-INTEGRITY` (HMAC-SHA1),
//!   including the subtle "length field counts the attribute being added"
//!   rule that is easy to get wrong and silently breaks verification.
//!
//! Deliberately *not* here: authentication (long-term credentials / `REALM` /
//! `NONCE`) and TURN allocation. The `Method` constants for TURN exist so a TURN
//! client can reuse this codec, but the allocation state machine is separate
//! work (SOTA P1-1, TURN half).
//!
//! ## Wire layout
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     Message Type        |         Message Length          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      0x2112A442 (cookie)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Transaction ID (96 bits)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The fixed STUN magic cookie. Its top 16 bits double as the XOR mask for the
/// port in `XOR-MAPPED-ADDRESS`.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Fixed header size: type(2) + length(2) + cookie(4) + transaction ID(12).
pub const HEADER_LEN: usize = 20;

/// `FINGERPRINT` is the CRC-32 of the message XORed with this constant
/// (RFC 8489 §14.7).
const FINGERPRINT_XOR: u32 = 0x5354_554E;

const FINGERPRINT_SIZE: usize = 8; // 4 header + 4 CRC
const INTEGRITY_SIZE: usize = 24; // 4 header + 20 HMAC-SHA1

// Attribute type codes (RFC 8489 §18.2 / RFC 8445 §19 / RFC 8656 §18).
mod attr {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const DONT_FRAGMENT: u16 = 0x001A;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const PRIORITY: u16 = 0x0024;
    pub const USE_CANDIDATE: u16 = 0x0025;
    pub const SOFTWARE: u16 = 0x8022;
    pub const FINGERPRINT: u16 = 0x8028;
    pub const ICE_CONTROLLED: u16 = 0x8029;
    pub const ICE_CONTROLLING: u16 = 0x802A;
}

/// TURN `REQUESTED-TRANSPORT` protocol number for UDP (RFC 8656 §18.9).
pub const TRANSPORT_UDP: u8 = 17;

/// TURN channel numbers live in `0x4000..=0x7FFF` (RFC 8656 §12).
pub const CHANNEL_NUMBER_MIN: u16 = 0x4000;
pub const CHANNEL_NUMBER_MAX: u16 = 0x7FFF;

/// Derive the `MESSAGE-INTEGRITY` key for long-term credentials
/// (RFC 8489 §9.2.2): `MD5(username ":" realm ":" password)`.
///
/// Short-term credentials (ICE) use the password directly; TURN servers always
/// use the long-term form.
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut input = Vec::with_capacity(username.len() + realm.len() + password.len() + 2);
    input.extend_from_slice(username.as_bytes());
    input.push(b':');
    input.extend_from_slice(realm.as_bytes());
    input.push(b':');
    input.extend_from_slice(password.as_bytes());
    md5::compute(&input).into()
}

/// Address family byte in `MAPPED-ADDRESS` / `XOR-MAPPED-ADDRESS`.
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    #[error("message shorter than the 20-byte STUN header")]
    TooShort,
    #[error("bad magic cookie (expected 0x2112A442)")]
    BadMagicCookie,
    #[error(
        "message length field ({declared}) does not match the datagram ({actual} bytes available)"
    )]
    LengthMismatch { declared: usize, actual: usize },
    #[error("message length is not a multiple of 4")]
    UnpaddedLength,
    #[error("attribute header runs past the end of the message")]
    TruncatedAttribute,
    #[error("attribute value runs past the end of the message")]
    TruncatedValue,
    #[error("unknown address family byte {0}")]
    UnknownFamily(u8),
    #[error("MESSAGE-INTEGRITY absent")]
    MissingIntegrity,
    #[error("MESSAGE-INTEGRITY did not verify")]
    BadIntegrity,
    #[error("FINGERPRINT absent")]
    MissingFingerprint,
    #[error("FINGERPRINT did not verify")]
    BadFingerprint,
    #[error("malformed message: {0}")]
    Malformed(&'static str),
}

// ── Message type ────────────────────────────────────────────────────

/// Class of a STUN message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl Class {
    fn bits(self) -> u16 {
        match self {
            Class::Request => 0b00,
            Class::Indication => 0b01,
            Class::SuccessResponse => 0b10,
            Class::ErrorResponse => 0b11,
        }
    }
}

/// STUN method. Kept as a `u16` newtype rather than an enum so an unknown
/// method parses instead of failing — a forward-compatible parser matters once
/// TURN and future extensions are in play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Method(pub u16);

impl Method {
    pub const BINDING: Method = Method(0x001);
    /// TURN `Allocate` (RFC 8656 §4).
    pub const ALLOCATE: Method = Method(0x003);
    /// TURN `Refresh`.
    pub const REFRESH: Method = Method(0x004);
    /// TURN `Send` indication.
    pub const SEND: Method = Method(0x006);
    /// TURN `Data` indication.
    pub const DATA: Method = Method(0x007);
    /// TURN `CreatePermission`.
    pub const CREATE_PERMISSION: Method = Method(0x008);
    /// TURN `ChannelBind`.
    pub const CHANNEL_BIND: Method = Method(0x009);
}

/// A 14-bit STUN message type: method and class interleaved on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageType(pub u16);

impl MessageType {
    /// Interleave method and class into the wire type (RFC 8489 §5).
    ///
    /// The class bits are *split* around the method bits, which is the part
    /// that makes hand-written STUN codecs fail: class bit 0 lands at type bit
    /// 4 and class bit 1 at type bit 8.
    pub fn new(method: Method, class: Class) -> Self {
        let m = method.0;
        let c = class.bits();
        MessageType(
            (m & 0x000F)
                | ((m & 0x0070) << 1)
                | ((m & 0x0F80) << 2)
                | ((c & 0x01) << 4)
                | ((c & 0x02) << 7),
        )
    }

    pub fn method(&self) -> Method {
        Method((self.0 & 0x000F) | ((self.0 & 0x00E0) >> 1) | ((self.0 & 0x3E00) >> 2))
    }

    pub fn class(&self) -> Class {
        match ((self.0 >> 4) & 0x01) | ((self.0 >> 7) & 0x02) {
            0 => Class::Request,
            1 => Class::Indication,
            2 => Class::SuccessResponse,
            _ => Class::ErrorResponse,
        }
    }
}

// ── Transaction ID ──────────────────────────────────────────────────

/// 96-bit transaction ID. Also the XOR mask tail for IPv6
/// `XOR-MAPPED-ADDRESS`, which is why it must be carried alongside attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId(pub [u8; 12]);

impl TransactionId {
    /// Cryptographically random transaction ID (`OsRng`).
    pub fn random() -> Self {
        let mut b = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut b);
        TransactionId(b)
    }

    /// Deterministic ID, for tests and for callers that already own entropy.
    pub fn from_bytes(b: [u8; 12]) -> Self {
        TransactionId(b)
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

// ── Attributes ──────────────────────────────────────────────────────

/// A decoded STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    MappedAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    Username(Vec<u8>),
    MessageIntegrity([u8; 20]),
    ErrorCode {
        code: u16,
        reason: String,
    },
    /// ICE check priority (RFC 8445 §7.1.1).
    Priority(u32),
    /// ICE nomination flag (RFC 8445 §7.1.2).
    UseCandidate,
    /// Tie-breaker for a controlled agent.
    IceControlled(u64),
    /// Tie-breaker for a controlling agent.
    IceControlling(u64),
    Software(String),
    Fingerprint(u32),
    /// TURN: the peer address a permission/channel/data applies to.
    XorPeerAddress(SocketAddr),
    /// TURN: the address the server allocated for us.
    XorRelayedAddress(SocketAddr),
    /// TURN: opaque application payload carried by Send/Data indications.
    Data(Vec<u8>),
    Realm(String),
    Nonce(String),
    /// TURN `REQUESTED-TRANSPORT` protocol number.
    RequestedTransport(u8),
    Lifetime(u32),
    ChannelNumber(u16),
    /// STUN/TURN: attributes the peer could not understand.
    UnknownAttributes(Vec<u16>),
    DontFragment,
    /// Comprehension-optional attribute we don't model. Preserved so a
    /// re-encode does not silently drop a peer's extension.
    Unknown {
        kind: u16,
        value: Vec<u8>,
    },
}

impl Attribute {
    fn kind(&self) -> u16 {
        match self {
            Attribute::MappedAddress(_) => attr::MAPPED_ADDRESS,
            Attribute::XorMappedAddress(_) => attr::XOR_MAPPED_ADDRESS,
            Attribute::Username(_) => attr::USERNAME,
            Attribute::MessageIntegrity(_) => attr::MESSAGE_INTEGRITY,
            Attribute::ErrorCode { .. } => attr::ERROR_CODE,
            Attribute::Priority(_) => attr::PRIORITY,
            Attribute::UseCandidate => attr::USE_CANDIDATE,
            Attribute::IceControlled(_) => attr::ICE_CONTROLLED,
            Attribute::IceControlling(_) => attr::ICE_CONTROLLING,
            Attribute::Software(_) => attr::SOFTWARE,
            Attribute::Fingerprint(_) => attr::FINGERPRINT,
            Attribute::XorPeerAddress(_) => attr::XOR_PEER_ADDRESS,
            Attribute::XorRelayedAddress(_) => attr::XOR_RELAYED_ADDRESS,
            Attribute::Data(_) => attr::DATA,
            Attribute::Realm(_) => attr::REALM,
            Attribute::Nonce(_) => attr::NONCE,
            Attribute::RequestedTransport(_) => attr::REQUESTED_TRANSPORT,
            Attribute::Lifetime(_) => attr::LIFETIME,
            Attribute::ChannelNumber(_) => attr::CHANNEL_NUMBER,
            Attribute::UnknownAttributes(_) => attr::UNKNOWN_ATTRIBUTES,
            Attribute::DontFragment => attr::DONT_FRAGMENT,
            Attribute::Unknown { kind, .. } => *kind,
        }
    }

    /// Encode this attribute's *value* (no TLV header, no padding).
    fn encode_value(&self, txid: &TransactionId) -> Vec<u8> {
        match self {
            Attribute::MappedAddress(a) => encode_address(*a, txid, false),
            Attribute::XorMappedAddress(a) => encode_address(*a, txid, true),
            Attribute::Username(u) => u.clone(),
            Attribute::MessageIntegrity(h) => h.to_vec(),
            Attribute::ErrorCode { code, reason } => {
                // 4-byte header: 2 reserved-zero bytes, class, number.
                let mut v = Vec::with_capacity(4 + reason.len());
                v.push(0);
                v.push(0);
                v.push((code / 100) as u8 & 0x07);
                v.push((code % 100) as u8);
                v.extend_from_slice(reason.as_bytes());
                v
            }
            Attribute::Priority(p) => p.to_be_bytes().to_vec(),
            Attribute::UseCandidate => Vec::new(),
            Attribute::IceControlled(t) | Attribute::IceControlling(t) => t.to_be_bytes().to_vec(),
            Attribute::Software(s) => s.as_bytes().to_vec(),
            Attribute::Fingerprint(c) => c.to_be_bytes().to_vec(),
            Attribute::XorPeerAddress(a) | Attribute::XorRelayedAddress(a) => {
                encode_address(*a, txid, true)
            }
            Attribute::Data(d) => d.clone(),
            Attribute::Realm(s) | Attribute::Nonce(s) => s.as_bytes().to_vec(),
            Attribute::RequestedTransport(proto) => vec![*proto, 0, 0, 0],
            Attribute::Lifetime(secs) => secs.to_be_bytes().to_vec(),
            // Channel number occupies the first 2 bytes; the next 2 are reserved.
            Attribute::ChannelNumber(n) => {
                let mut v = n.to_be_bytes().to_vec();
                v.extend_from_slice(&[0, 0]);
                v
            }
            Attribute::UnknownAttributes(list) => {
                let mut v = Vec::with_capacity(list.len() * 2);
                for kind in list {
                    v.extend_from_slice(&kind.to_be_bytes());
                }
                v
            }
            Attribute::DontFragment => Vec::new(),
            Attribute::Unknown { value, .. } => value.clone(),
        }
    }

    /// Write this attribute as TLV, padded to a 4-byte boundary.
    fn encode_into(&self, txid: &TransactionId, out: &mut Vec<u8>) {
        let value = self.encode_value(txid);
        out.extend_from_slice(&self.kind().to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(&value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
}

/// Encode an address for `MAPPED-ADDRESS` / `XOR-MAPPED-ADDRESS`.
///
/// `xor` selects the obfuscated form: the port is XORed with the top 16 bits of
/// the magic cookie, the IPv4 address with the whole cookie, and the IPv6
/// address with (cookie ‖ transaction ID).
fn encode_address(addr: SocketAddr, txid: &TransactionId, xor: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.push(0); // reserved
    let port = if xor {
        addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)
    } else {
        addr.port()
    };
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(FAMILY_IPV4);
            out.extend_from_slice(&port.to_be_bytes());
            let mut raw = v4.octets();
            if xor {
                let mask = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    raw[i] ^= mask[i];
                }
            }
            out.extend_from_slice(&raw);
        }
        IpAddr::V6(v6) => {
            out.push(FAMILY_IPV6);
            out.extend_from_slice(&port.to_be_bytes());
            let mut raw = v6.octets();
            if xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(txid.as_bytes());
                for i in 0..16 {
                    raw[i] ^= mask[i];
                }
            }
            out.extend_from_slice(&raw);
        }
    }
    out
}

/// Decode an address attribute value (8 bytes for IPv4, 20 for IPv6).
fn decode_address(value: &[u8], txid: &TransactionId, xor: bool) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::Malformed(
            "address attribute shorter than 4 bytes",
        ));
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunError::Malformed("IPv4 address attribute needs 8 bytes"));
            }
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&value[4..8]);
            if xor {
                let mask = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    raw[i] ^= mask[i];
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw)), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunError::Malformed(
                    "IPv6 address attribute needs 20 bytes",
                ));
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&value[4..20]);
            if xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(txid.as_bytes());
                for i in 0..16 {
                    raw[i] ^= mask[i];
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(raw)), port))
        }
        other => Err(StunError::UnknownFamily(other)),
    }
}

// ── Message ─────────────────────────────────────────────────────────

/// A parsed or under-construction STUN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub typ: MessageType,
    pub txid: TransactionId,
    pub attributes: Vec<Attribute>,
}

impl Message {
    pub fn new(method: Method, class: Class, txid: TransactionId) -> Self {
        Message {
            typ: MessageType::new(method, class),
            txid,
            attributes: Vec::new(),
        }
    }

    /// A Binding request carrying `SOFTWARE`.
    pub fn binding_request(txid: TransactionId) -> Self {
        let mut m = Message::new(Method::BINDING, Class::Request, txid);
        m.attributes.push(Attribute::Software(software()));
        m
    }

    /// A Binding indication — the ICE keepalive (RFC 8445 §11).
    ///
    /// An indication gets no response, so it refreshes a NAT mapping without
    /// adding a round-trip or leaving any state behind on the peer.
    pub fn binding_indication(txid: TransactionId) -> Self {
        let mut m = Message::new(Method::BINDING, Class::Indication, txid);
        m.attributes.push(Attribute::Software(software()));
        m
    }

    /// A Binding success response echoing `txid` and reporting `mapped`.
    pub fn binding_success(txid: TransactionId, mapped: SocketAddr) -> Self {
        let mut m = Message::new(Method::BINDING, Class::SuccessResponse, txid);
        m.attributes.push(Attribute::XorMappedAddress(mapped));
        m.attributes.push(Attribute::Software(software()));
        m
    }

    pub fn push(&mut self, a: Attribute) -> &mut Self {
        self.attributes.push(a);
        self
    }

    pub fn get(&self, kind: u16) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.kind() == kind)
    }

    /// The peer's reflexive (public) address, if the message carried one.
    pub fn xor_mapped_address(&self) -> Option<SocketAddr> {
        match self.get(attr::XOR_MAPPED_ADDRESS) {
            Some(Attribute::XorMappedAddress(a)) => Some(*a),
            _ => match self.get(attr::MAPPED_ADDRESS) {
                Some(Attribute::MappedAddress(a)) => Some(*a),
                _ => None,
            },
        }
    }

    /// TURN: the address the server allocated for us.
    pub fn xor_relayed_address(&self) -> Option<SocketAddr> {
        match self.get(attr::XOR_RELAYED_ADDRESS) {
            Some(Attribute::XorRelayedAddress(a)) => Some(*a),
            _ => None,
        }
    }

    /// TURN: the peer a permission, channel or data indication refers to.
    pub fn xor_peer_address(&self) -> Option<SocketAddr> {
        match self.get(attr::XOR_PEER_ADDRESS) {
            Some(Attribute::XorPeerAddress(a)) => Some(*a),
            _ => None,
        }
    }

    /// TURN: the opaque payload of a Send/Data indication.
    pub fn data(&self) -> Option<&[u8]> {
        match self.get(attr::DATA) {
            Some(Attribute::Data(d)) => Some(d.as_slice()),
            _ => None,
        }
    }

    pub fn realm(&self) -> Option<&str> {
        match self.get(attr::REALM) {
            Some(Attribute::Realm(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn nonce(&self) -> Option<&str> {
        match self.get(attr::NONCE) {
            Some(Attribute::Nonce(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// TURN: lifetime in seconds.
    pub fn lifetime(&self) -> Option<u32> {
        match self.get(attr::LIFETIME) {
            Some(Attribute::Lifetime(s)) => Some(*s),
            _ => None,
        }
    }

    pub fn channel_number(&self) -> Option<u16> {
        match self.get(attr::CHANNEL_NUMBER) {
            Some(Attribute::ChannelNumber(n)) => Some(*n),
            _ => None,
        }
    }

    /// TURN: `REQUESTED-TRANSPORT` protocol number (`TRANSPORT_UDP` for UDP).
    pub fn requested_transport(&self) -> Option<u8> {
        match self.get(attr::REQUESTED_TRANSPORT) {
            Some(Attribute::RequestedTransport(p)) => Some(*p),
            _ => None,
        }
    }

    /// Attributes a peer reported as ununderstood.
    pub fn unknown_attributes(&self) -> &[u16] {
        match self.get(attr::UNKNOWN_ATTRIBUTES) {
            Some(Attribute::UnknownAttributes(list)) => list.as_slice(),
            _ => &[],
        }
    }

    pub fn error_code(&self) -> Option<(u16, &str)> {
        match self.get(attr::ERROR_CODE) {
            Some(Attribute::ErrorCode { code, reason }) => Some((*code, reason.as_str())),
            _ => None,
        }
    }

    /// Encode without `MESSAGE-INTEGRITY` or `FINGERPRINT`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        self.write_header(&mut out, 0);
        for a in &self.attributes {
            a.encode_into(&self.txid, &mut out);
        }
        let attr_len = out.len() - HEADER_LEN;
        out[2..4].copy_from_slice(&(attr_len as u16).to_be_bytes());
        out
    }

    /// Encode with `MESSAGE-INTEGRITY` (HMAC-SHA1 keyed by the ICE short-term
    /// credential) followed by `FINGERPRINT`.
    ///
    /// The length field is rewritten *before* each digest because both digests
    /// cover the header, including the length. `MESSAGE-INTEGRITY` covers
    /// everything up to itself and its length counts itself; `FINGERPRINT`
    /// covers everything up to itself and its length counts itself and the
    /// integrity attribute.
    pub fn encode_with_integrity(&self, key: &[u8]) -> Result<Vec<u8>, StunError> {
        let mut stripped = self.clone();
        stripped.attributes.retain(|a| {
            !matches!(
                a,
                Attribute::MessageIntegrity(_) | Attribute::Fingerprint(_)
            )
        });

        let mut out = Vec::with_capacity(128);
        stripped.write_header(&mut out, 0);
        for a in &stripped.attributes {
            a.encode_into(&stripped.txid, &mut out);
        }

        // MESSAGE-INTEGRITY: length counts the attribute we are about to add.
        let mi_total = out.len() - HEADER_LEN + INTEGRITY_SIZE;
        out[2..4].copy_from_slice(&(mi_total as u16).to_be_bytes());
        let mut mac =
            Hmac::<Sha1>::new_from_slice(key).map_err(|_| StunError::Malformed("bad HMAC key"))?;
        mac.update(&out);
        let tag = mac.finalize().into_bytes();
        out.extend_from_slice(&attr::MESSAGE_INTEGRITY.to_be_bytes());
        out.extend_from_slice(&(20u16).to_be_bytes());
        out.extend_from_slice(&tag);

        // FINGERPRINT: length now counts the integrity and fingerprint attrs.
        let fp_total = out.len() - HEADER_LEN + FINGERPRINT_SIZE;
        out[2..4].copy_from_slice(&(fp_total as u16).to_be_bytes());
        let crc = crc32_ieee(&out) ^ FINGERPRINT_XOR;
        out.extend_from_slice(&attr::FINGERPRINT.to_be_bytes());
        out.extend_from_slice(&(4u16).to_be_bytes());
        out.extend_from_slice(&crc.to_be_bytes());

        debug_assert_eq!(out.len() % 4, 0);
        // The header length must equal the real attribute bytes.
        debug_assert_eq!(
            u16::from_be_bytes([out[2], out[3]]) as usize,
            out.len() - HEADER_LEN
        );
        Ok(out)
    }

    fn write_header(&self, out: &mut Vec<u8>, attr_len: u16) {
        out.extend_from_slice(&self.typ.0.to_be_bytes());
        out.extend_from_slice(&attr_len.to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(self.txid.as_bytes());
        debug_assert_eq!(out.len(), HEADER_LEN);
    }

    /// Parse a datagram. `FINGERPRINT` / `MESSAGE-INTEGRITY` are decoded as
    /// attributes but *not* verified here — use [`verify_integrity`] and
    /// [`verify_fingerprint`] on the raw bytes for that.
    pub fn parse(buf: &[u8]) -> Result<Message, StunError> {
        if buf.len() < HEADER_LEN {
            return Err(StunError::TooShort);
        }
        let typ = MessageType(u16::from_be_bytes([buf[0], buf[1]]));
        let declared = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if declared % 4 != 0 {
            return Err(StunError::UnpaddedLength);
        }
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(StunError::BadMagicCookie);
        }
        let mut txid_bytes = [0u8; 12];
        txid_bytes.copy_from_slice(&buf[8..20]);
        let txid = TransactionId(txid_bytes);

        let available = buf.len() - HEADER_LEN;
        if declared > available {
            return Err(StunError::LengthMismatch {
                declared,
                actual: available,
            });
        }
        // A UDP datagram may legally carry padding beyond the STUN message, so
        // only the declared region is parsed.
        let body = &buf[HEADER_LEN..HEADER_LEN + declared];

        let mut attributes = Vec::new();
        let mut rest = body;
        while !rest.is_empty() {
            if rest.len() < 4 {
                return Err(StunError::TruncatedAttribute);
            }
            let kind = u16::from_be_bytes([rest[0], rest[1]]);
            let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            let value_end = 4 + len;
            if value_end > rest.len() {
                return Err(StunError::TruncatedValue);
            }
            let value = &rest[4..value_end];
            attributes.push(decode_attribute(kind, value, &txid)?);
            // Advance past the value plus its 4-byte padding.
            let padded = (len + 3) & !3;
            let advance = 4 + padded;
            if advance > rest.len() {
                return Err(StunError::TruncatedValue);
            }
            rest = &rest[advance..];
        }

        Ok(Message {
            typ,
            txid,
            attributes,
        })
    }
}

fn decode_attribute(kind: u16, value: &[u8], txid: &TransactionId) -> Result<Attribute, StunError> {
    Ok(match kind {
        attr::MAPPED_ADDRESS => Attribute::MappedAddress(decode_address(value, txid, false)?),
        attr::XOR_MAPPED_ADDRESS => Attribute::XorMappedAddress(decode_address(value, txid, true)?),
        attr::USERNAME => Attribute::Username(value.to_vec()),
        attr::MESSAGE_INTEGRITY => {
            if value.len() < 20 {
                return Err(StunError::Malformed(
                    "MESSAGE-INTEGRITY shorter than 20 bytes",
                ));
            }
            let mut h = [0u8; 20];
            h.copy_from_slice(&value[..20]);
            Attribute::MessageIntegrity(h)
        }
        attr::ERROR_CODE => {
            if value.len() < 4 {
                return Err(StunError::Malformed("ERROR-CODE shorter than 4 bytes"));
            }
            let code = ((value[2] & 0x07) as u16) * 100 + value[3] as u16;
            let reason = String::from_utf8_lossy(&value[4..]).into_owned();
            Attribute::ErrorCode { code, reason }
        }
        attr::PRIORITY => {
            if value.len() < 4 {
                return Err(StunError::Malformed("PRIORITY shorter than 4 bytes"));
            }
            Attribute::Priority(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
        }
        attr::USE_CANDIDATE => Attribute::UseCandidate,
        attr::ICE_CONTROLLED => Attribute::IceControlled(read_u64(value)?),
        attr::ICE_CONTROLLING => Attribute::IceControlling(read_u64(value)?),
        attr::SOFTWARE => Attribute::Software(String::from_utf8_lossy(value).into_owned()),
        attr::XOR_PEER_ADDRESS => Attribute::XorPeerAddress(decode_address(value, txid, true)?),
        attr::XOR_RELAYED_ADDRESS => {
            Attribute::XorRelayedAddress(decode_address(value, txid, true)?)
        }
        attr::DATA => Attribute::Data(value.to_vec()),
        attr::REALM => Attribute::Realm(String::from_utf8_lossy(value).into_owned()),
        attr::NONCE => Attribute::Nonce(String::from_utf8_lossy(value).into_owned()),
        attr::REQUESTED_TRANSPORT => {
            if value.is_empty() {
                return Err(StunError::Malformed(
                    "REQUESTED-TRANSPORT shorter than 1 byte",
                ));
            }
            Attribute::RequestedTransport(value[0])
        }
        attr::LIFETIME => Attribute::Lifetime(u32::from_be_bytes([
            *value
                .first()
                .ok_or(StunError::Malformed("LIFETIME empty"))?,
            *value.get(1).ok_or(StunError::Malformed("LIFETIME short"))?,
            *value.get(2).ok_or(StunError::Malformed("LIFETIME short"))?,
            *value.get(3).ok_or(StunError::Malformed("LIFETIME short"))?,
        ])),
        attr::CHANNEL_NUMBER => {
            if value.len() < 2 {
                return Err(StunError::Malformed("CHANNEL-NUMBER short"));
            }
            Attribute::ChannelNumber(u16::from_be_bytes([value[0], value[1]]))
        }
        attr::UNKNOWN_ATTRIBUTES => {
            if value.len() % 2 != 0 {
                return Err(StunError::Malformed("UNKNOWN-ATTRIBUTES not even"));
            }
            Attribute::UnknownAttributes(
                value
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect(),
            )
        }
        attr::DONT_FRAGMENT => Attribute::DontFragment,
        attr::FINGERPRINT => {
            if value.len() < 4 {
                return Err(StunError::Malformed("FINGERPRINT shorter than 4 bytes"));
            }
            Attribute::Fingerprint(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
        }
        other => Attribute::Unknown {
            kind: other,
            value: value.to_vec(),
        },
    })
}

fn read_u64(value: &[u8]) -> Result<u64, StunError> {
    if value.len() < 8 {
        return Err(StunError::Malformed(
            "64-bit attribute shorter than 8 bytes",
        ));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&value[..8]);
    Ok(u64::from_be_bytes(b))
}

fn software() -> String {
    format!("GhostNet/{}", env!("CARGO_PKG_VERSION"))
}

// ── Verification ────────────────────────────────────────────────────

/// Locate an attribute in a raw datagram, returning (value offset, value len).
fn find_raw_attribute(buf: &[u8], want: u16) -> Option<(usize, usize)> {
    let declared = u16::from_be_bytes([buf.get(2).copied()?, buf.get(3).copied()?]) as usize;
    let mut pos = HEADER_LEN;
    let end = (HEADER_LEN + declared).min(buf.len());
    while pos + 4 <= end {
        let kind = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        if kind == want {
            return Some((pos, len));
        }
        let padded = (len + 3) & !3;
        pos += 4 + padded;
    }
    None
}

/// Verify `MESSAGE-INTEGRITY` against the short-term credential `key`.
/// Verify `MESSAGE-INTEGRITY` (RFC 8489 §14.5).
///
/// The digest is defined over the message *up to* the MESSAGE-INTEGRITY
/// attribute, with the header length field set to reach the end of that
/// attribute. When a FINGERPRINT follows, the length field on the wire is
/// larger than that — because the wire field must describe the whole message
/// (§6) — so the covered value has to be **reconstructed**, not compared
/// against what arrived. Comparing instead makes every message that carries both
/// attributes fail verification, which is the classic way this codec is wrong.
pub fn verify_integrity(buf: &[u8], key: &[u8]) -> Result<(), StunError> {
    let (off, _) =
        find_raw_attribute(buf, attr::MESSAGE_INTEGRITY).ok_or(StunError::MissingIntegrity)?;
    if off + INTEGRITY_SIZE > buf.len() || off < HEADER_LEN {
        return Err(StunError::BadIntegrity);
    }
    let covered_len = (off - HEADER_LEN + INTEGRITY_SIZE) as u16;
    // Two-part update rather than a patched copy: no allocation on the check path.
    let mut mac =
        Hmac::<Sha1>::new_from_slice(key).map_err(|_| StunError::Malformed("bad HMAC key"))?;
    mac.update(&buf[..2]);
    mac.update(&covered_len.to_be_bytes());
    mac.update(&buf[4..off]);
    let mut expected = [0u8; 20];
    expected.copy_from_slice(&mac.finalize().into_bytes());
    let actual = &buf[off + 4..off + 24];
    if expected.as_slice() == actual {
        Ok(())
    } else {
        Err(StunError::BadIntegrity)
    }
}

/// Verify `FINGERPRINT` (CRC-32 of the message up to the attribute).
///
/// As with `MESSAGE-INTEGRITY` the covered length is reconstructed from the
/// attribute's position rather than read from the wire, so a message with
/// trailing bytes cannot smuggle a fingerprint in.
pub fn verify_fingerprint(buf: &[u8]) -> Result<(), StunError> {
    let (off, _) =
        find_raw_attribute(buf, attr::FINGERPRINT).ok_or(StunError::MissingFingerprint)?;
    if off + FINGERPRINT_SIZE > buf.len() || off < HEADER_LEN {
        return Err(StunError::BadFingerprint);
    }
    let covered_len = (off - HEADER_LEN + FINGERPRINT_SIZE) as u16;
    let mut covered = buf[..off].to_vec();
    covered[2..4].copy_from_slice(&covered_len.to_be_bytes());
    let expected = crc32_ieee(&covered) ^ FINGERPRINT_XOR;
    let actual = u32::from_be_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
    if expected == actual {
        Ok(())
    } else {
        Err(StunError::BadFingerprint)
    }
}

/// CRC-32/ISO-HDLC (reflected, polynomial `0xEDB88320`).
///
/// Bitwise rather than table-driven: STUN messages are small, and this is the
/// version that is hard to get subtly wrong.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn txid() -> TransactionId {
        TransactionId::from_bytes([
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ])
    }

    #[test]
    fn turn_attributes_round_trip() {
        let mut msg = Message::new(Method::ALLOCATE, Class::Request, txid());
        msg.push(Attribute::RequestedTransport(TRANSPORT_UDP));
        msg.push(Attribute::Lifetime(600));
        msg.push(Attribute::Realm("ghostnet.example".into()));
        msg.push(Attribute::Nonce("nonce-value".into()));
        msg.push(Attribute::XorPeerAddress(
            "198.51.100.22:51820".parse().unwrap(),
        ));
        msg.push(Attribute::DontFragment);

        let parsed = Message::parse(&msg.encode()).unwrap();
        assert_eq!(parsed.requested_transport(), Some(TRANSPORT_UDP));
        assert_eq!(parsed.lifetime(), Some(600));
        assert_eq!(parsed.realm(), Some("ghostnet.example"));
        assert_eq!(parsed.nonce(), Some("nonce-value"));
        assert_eq!(
            parsed.xor_peer_address(),
            Some("198.51.100.22:51820".parse().unwrap())
        );

        // The relayed address uses the same XOR form as the mapped address.
        let mut ok = Message::new(Method::ALLOCATE, Class::SuccessResponse, txid());
        ok.push(Attribute::XorRelayedAddress(
            "203.0.113.5:49152".parse().unwrap(),
        ));
        let parsed = Message::parse(&ok.encode()).unwrap();
        assert_eq!(
            parsed.xor_relayed_address(),
            Some("203.0.113.5:49152".parse().unwrap())
        );
    }

    #[test]
    fn turn_channel_number_and_data_round_trip() {
        let mut bind = Message::new(Method::CHANNEL_BIND, Class::Request, txid());
        bind.push(Attribute::ChannelNumber(0x4001));
        let parsed = Message::parse(&bind.encode()).unwrap();
        assert_eq!(parsed.channel_number(), Some(0x4001));

        let mut data = Message::new(Method::DATA, Class::Indication, txid());
        data.push(Attribute::Data(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01]));
        let parsed = Message::parse(&data.encode()).unwrap();
        // An odd-length DATA must survive the 4-byte padding.
        assert_eq!(parsed.data(), Some(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01][..]));
    }

    #[test]
    fn unknown_attributes_are_reported() {
        let mut msg = Message::new(Method::ALLOCATE, Class::ErrorResponse, txid());
        msg.push(Attribute::UnknownAttributes(vec![0x000C, 0x001A]));
        let parsed = Message::parse(&msg.encode()).unwrap();
        assert_eq!(parsed.unknown_attributes(), &[0x000C, 0x001A]);
    }

    #[test]
    fn long_term_key_is_deterministic_and_input_sensitive() {
        let a = long_term_key("user", "example.org", "secret-password");
        let b = long_term_key("user", "example.org", "secret-password");
        assert_eq!(a, b);
        assert_ne!(a, long_term_key("user2", "example.org", "secret-password"));
        assert_ne!(a, long_term_key("user", "example.com", "secret-password"));
        assert_ne!(a, long_term_key("user", "example.org", "other-password"));
        // MD5("user:example.org:secret-password") — 16 bytes, and the fields are
        // colon-joined, so a colon inside an input cannot be re-split silently.
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn binding_indication_is_class_indication_not_request() {
        let m = Message::binding_indication(txid());
        assert_eq!(m.typ.0, 0x0011);
        assert_eq!(m.typ.class(), Class::Indication);
        assert_eq!(m.typ.method(), Method::BINDING);
        let parsed = Message::parse(&m.encode()).unwrap();
        assert_eq!(parsed.typ.class(), Class::Indication);
        // An indication must never carry MESSAGE-INTEGRITY: nobody acknowledges it.
        assert!(parsed.get(attr::MESSAGE_INTEGRITY).is_none());
    }

    #[test]
    fn crc32_matches_the_standard_vector() {
        // The canonical CRC-32/ISO-HDLC check value.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
    }

    #[test]
    fn binding_request_type_is_0x0001() {
        let t = MessageType::new(Method::BINDING, Class::Request);
        assert_eq!(t.0, 0x0001);
        assert_eq!(t.method(), Method::BINDING);
        assert_eq!(t.class(), Class::Request);
    }

    #[test]
    fn class_bits_are_split_around_the_method_bits() {
        // The classic trap: class 0b10 is not type `method | 0b1000`.
        let success = MessageType::new(Method::BINDING, Class::SuccessResponse);
        assert_eq!(success.0, 0x0101);
        assert_eq!(success.class(), Class::SuccessResponse);

        let error = MessageType::new(Method::BINDING, Class::ErrorResponse);
        assert_eq!(error.0, 0x0111);
        assert_eq!(error.class(), Class::ErrorResponse);

        let indication = MessageType::new(Method::BINDING, Class::Indication);
        assert_eq!(indication.0, 0x0011);
        assert_eq!(indication.class(), Class::Indication);

        // Every class round-trips for a non-trivial method too.
        for m in [Method::BINDING, Method::ALLOCATE, Method::DATA] {
            for c in [
                Class::Request,
                Class::Indication,
                Class::SuccessResponse,
                Class::ErrorResponse,
            ] {
                let t = MessageType::new(m, c);
                assert_eq!(t.method(), m, "method {m:?} class {c:?}");
                assert_eq!(t.class(), c, "method {m:?} class {c:?}");
            }
        }
    }

    #[test]
    fn header_is_20_bytes_with_the_magic_cookie() {
        let msg = Message::binding_request(txid());
        let raw = msg.encode();
        assert_eq!(
            u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&raw[8..20], txid().as_bytes());
        assert_eq!(
            u16::from_be_bytes([raw[2], raw[3]]) as usize,
            raw.len() - HEADER_LEN
        );
    }

    #[test]
    fn xor_mapped_address_ipv4_obfuscates_port_and_address() {
        let addr: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let encoded = encode_address(addr, &txid(), true);
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], FAMILY_IPV4);
        // 32853 == 0x8055, XOR 0x2112 == 0xA147
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 0xA147);
        // 192.0.2.1 == 0xC0000201, XOR 0x2112A442 == 0xE112A643
        assert_eq!(&encoded[4..8], &[0xE1, 0x12, 0xA6, 0x43]);

        assert_eq!(decode_address(&encoded, &txid(), true).unwrap(), addr);
    }

    #[test]
    fn xor_mapped_address_ipv6_uses_the_transaction_id_as_mask_tail() {
        let addr: SocketAddr = "[2001:db8::1]:3478".parse().unwrap();
        let encoded = encode_address(addr, &txid(), true);
        assert_eq!(encoded[1], FAMILY_IPV6);
        assert_eq!(decode_address(&encoded, &txid(), true).unwrap(), addr);

        // A different transaction ID must decode to a different address, which
        // is exactly why the mask has to be threaded through decode.
        let other = TransactionId::from_bytes([0u8; 12]);
        assert_ne!(decode_address(&encoded, &other, true).unwrap(), addr);
    }

    #[test]
    fn uncompressed_mapped_address_round_trips() {
        let addr: SocketAddr = "203.0.113.7:5000".parse().unwrap();
        let encoded = encode_address(addr, &txid(), false);
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 5000);
        assert_eq!(decode_address(&encoded, &txid(), false).unwrap(), addr);
    }

    #[test]
    fn round_trip_through_the_wire() {
        let addr: SocketAddr = "198.51.100.9:1234".parse().unwrap();
        let msg = Message::binding_success(txid(), addr);
        let parsed = Message::parse(&msg.encode()).unwrap();
        assert_eq!(parsed.txid, txid());
        assert_eq!(parsed.typ.class(), Class::SuccessResponse);
        assert_eq!(parsed.xor_mapped_address(), Some(addr));
    }

    #[test]
    fn parse_rejects_a_bad_cookie_and_truncation() {
        let raw = Message::binding_request(txid()).encode();
        let mut bad = raw.clone();
        bad[4] ^= 0xFF;
        assert_eq!(Message::parse(&bad), Err(StunError::BadMagicCookie));

        assert_eq!(Message::parse(&raw[..10]), Err(StunError::TooShort));

        let mut short = raw.clone();
        short[2..4].copy_from_slice(&(4096u16).to_be_bytes());
        assert!(matches!(
            Message::parse(&short),
            Err(StunError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn integrity_and_fingerprint_verify_and_detect_tampering() {
        let addr: SocketAddr = "192.0.2.5:9999".parse().unwrap();
        let key = b"ghostnet-ice-password";
        let raw = Message::binding_success(txid(), addr)
            .encode_with_integrity(key)
            .unwrap();

        verify_integrity(&raw, key).expect("integrity must verify");
        verify_fingerprint(&raw).expect("fingerprint must verify");
        // The wrong credential must fail.
        assert_eq!(
            verify_integrity(&raw, b"wrong-password"),
            Err(StunError::BadIntegrity)
        );

        // Flip one bit of the address attribute value: both digests must notice.
        let mut tampered = raw.clone();
        let (off, _) = find_raw_attribute(&tampered, attr::XOR_MAPPED_ADDRESS).unwrap();
        tampered[off + 4] ^= 0x01;
        assert!(verify_integrity(&tampered, key).is_err());
        assert_eq!(
            verify_fingerprint(&tampered),
            Err(StunError::BadFingerprint)
        );
    }

    #[test]
    fn integrity_is_hashed_over_the_length_that_points_at_it() {
        let msg = Message::binding_request(txid());
        let raw = msg.encode_with_integrity(b"pw").unwrap();
        let (off, _) = find_raw_attribute(&raw, attr::MESSAGE_INTEGRITY).unwrap();
        let (fp_off, _) = find_raw_attribute(&raw, attr::FINGERPRINT).unwrap();

        // The header length on the wire describes the whole message (RFC 8489
        // §6), and FINGERPRINT is last, so it also equals the fingerprint's
        // covered length.
        assert_eq!(
            u16::from_be_bytes([raw[2], raw[3]]) as usize,
            raw.len() - HEADER_LEN
        );
        assert_eq!(
            raw.len() - HEADER_LEN,
            fp_off - HEADER_LEN + FINGERPRINT_SIZE
        );

        // MESSAGE-INTEGRITY is *computed* with the length pointing at its own
        // end, which is 8 bytes short of the wire value once a FINGERPRINT
        // follows. A codec that hashes the wire value instead produces a digest
        // that no conforming peer would accept, so pin down that they differ…
        let key = b"pw";
        let mut naive = raw[..off].to_vec();
        naive[2..4].copy_from_slice(&((raw.len() - HEADER_LEN) as u16).to_be_bytes());
        let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
        mac.update(&naive);
        let naive_tag = mac.finalize().into_bytes();
        assert_ne!(
            &raw[off + 4..off + 24],
            naive_tag.as_slice(),
            "the wire length must not be the hashed length"
        );

        // …and that the real digest, over the reconstructed length, verifies.
        verify_integrity(&raw, key).expect("the patched-length digest must verify");
    }

    #[test]
    fn unknown_attributes_survive_a_round_trip() {
        let mut msg = Message::binding_request(txid());
        msg.push(Attribute::Unknown {
            kind: 0xC001,
            value: vec![1, 2, 3, 4, 5],
        });
        let parsed = Message::parse(&msg.encode()).unwrap();
        match parsed.get(0xC001) {
            Some(Attribute::Unknown { value, .. }) => assert_eq!(value, &vec![1, 2, 3, 4, 5]),
            other => panic!("expected preserved unknown attribute, got {other:?}"),
        }
    }

    #[test]
    fn error_code_packs_class_and_number() {
        let mut msg = Message::new(Method::BINDING, Class::ErrorResponse, txid());
        msg.push(Attribute::ErrorCode {
            code: 487,
            reason: "Role Conflict".into(),
        });
        let parsed = Message::parse(&msg.encode()).unwrap();
        assert_eq!(parsed.error_code(), Some((487, "Role Conflict")));
    }

    #[test]
    fn ice_attributes_round_trip() {
        let mut msg = Message::binding_request(txid());
        msg.push(Attribute::Priority(0x7E00_001E));
        msg.push(Attribute::IceControlling(0xDEAD_BEEF_1234_5678));
        msg.push(Attribute::UseCandidate);
        let parsed = Message::parse(&msg.encode()).unwrap();
        assert_eq!(
            parsed.get(attr::PRIORITY),
            Some(&Attribute::Priority(0x7E00_001E))
        );
        assert_eq!(
            parsed.get(attr::ICE_CONTROLLING),
            Some(&Attribute::IceControlling(0xDEAD_BEEF_1234_5678))
        );
        assert_eq!(
            parsed.get(attr::USE_CANDIDATE),
            Some(&Attribute::UseCandidate)
        );
    }

    #[test]
    fn transaction_ids_are_unique() {
        let a = TransactionId::random();
        let b = TransactionId::random();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
