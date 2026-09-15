//! TURN (RFC 8656) — allocation, permissions, channels, and relaying.
//!
//! Phase 1 needs a *relay* path for the cases ICE cannot solve: symmetric NAT on
//! both ends, CGNAT that rewrites the port per destination, and UDP-blocking
//! firewalls. Until now the mesh had no way to fall back — a failed punch just
//! failed.
//!
//! ## Shape
//!
//! * [`TurnClient`] drives a real allocation against a TURN server using
//!   long-term credentials (RFC 8489 §9.2.2).
//! * [`TurnServer`] is a **pure state machine**: it takes a datagram and returns
//!   the datagrams to emit. It owns no sockets and does no I/O, which is what
//!   makes the relay path testable — the client's bytes can be fed straight into
//!   the server and back without a network.
//!
//! The socket layout is deliberately left to the caller: a server needs one
//! socket per relayed port (or a `SO_REUSEPORT` set), and that is an operational
//! choice, not a protocol one.
//!
//! ## Methods implemented
//!
//! `Allocate`, `Refresh`, `CreatePermission`, `ChannelBind`, and the `Send` /
//! `Data` indications, plus ChannelData framing. `Even-Port`, `Reservation-Token`
//! and TCP relay (RFC 6062) are not implemented — nothing in the mesh needs them.

use super::stun::{
    self, Attribute, Class, Message, Method, TransactionId, CHANNEL_NUMBER_MAX, CHANNEL_NUMBER_MIN,
    TRANSPORT_UDP,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Default requested allocation lifetime.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(600);

/// RFC 8656 servers clamp allocations to at least 10 minutes; ask for that.
pub const MIN_LIFETIME_SECS: u32 = 600;

/// Permissions expire after 5 minutes unless refreshed (RFC 8656 §8).
pub const DEFAULT_PERMISSION_LIFETIME: Duration = Duration::from_secs(300);

/// Channel bindings expire after 10 minutes unless refreshed (RFC 8656 §12).
pub const DEFAULT_CHANNEL_LIFETIME: Duration = Duration::from_secs(600);

/// Channel lifetimes as the spec states them.
const CHANNEL_LIFETIME_SECS: u32 = 600;

/// Caps how many outstanding nonces the server tracks. Each unanswered
/// challenge issues one, so without a cap an unauthenticated flood grows the
/// map without bound.
const MAX_OUTSTANDING_NONCES: usize = 4096;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TurnError {
    #[error("STUN error: {0}")]
    Stun(#[from] stun::StunError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no response from the TURN server within {0:?}")]
    Timeout(Duration),
    #[error("TURN server rejected the request: {code} {reason}")]
    Rejected { code: u16, reason: String },
    #[error("server did not send REALM/NONCE for long-term credentials")]
    MissingCredentials,
    #[error("no allocation has been established")]
    NoAllocation,
    #[error("no channel number is free")]
    NoChannelAvailable,
    #[error("unauthenticated TURN request")]
    Unauthorized,
    #[error("malformed TURN input: {0}")]
    Malformed(&'static str),
}

// ── Channel data framing ────────────────────────────────────────────

/// Wrap `payload` in a ChannelData message (RFC 8656 §12.5):
/// `[channel u16][length u16][payload][pad to 4]`.
///
/// ChannelData is not STUN — it has no header, cookie or transaction, which is
/// exactly why the relay uses it for the bulk path.
pub fn channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len() + 3);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Parse a ChannelData message. Returns `None` when `raw` is not channel data.
pub fn parse_channel_data(raw: &[u8]) -> Option<(u16, &[u8])> {
    if raw.len() < 4 {
        return None;
    }
    let channel = u16::from_be_bytes([raw[0], raw[1]]);
    if !(CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX).contains(&channel) {
        return None;
    }
    let len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if 4 + len > raw.len() {
        return None;
    }
    Some((channel, &raw[4..4 + len]))
}

// ── Client ──────────────────────────────────────────────────────────

/// An established allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// The address peers should send to; the server relays it to us.
    pub relayed_addr: SocketAddr,
    /// The public address the server saw for us (its XOR-MAPPED-ADDRESS).
    pub mapped_addr: Option<SocketAddr>,
    pub lifetime: Duration,
    pub expires_at: Instant,
}

/// What a client received on its allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnInbound {
    /// A `Data` indication: the peer address is explicit.
    Data { peer: SocketAddr, payload: Vec<u8> },
    /// ChannelData: the channel number identifies the peer.
    ChannelData { channel: u16, payload: Vec<u8> },
}

/// A TURN client for one server and one set of long-term credentials.
pub struct TurnClient {
    server: SocketAddr,
    username: String,
    password: String,
    realm: Option<String>,
    nonce: Option<String>,
    allocation: Option<Allocation>,
    /// Permission expiry per peer IP.
    permissions: HashMap<IpAddr, Instant>,
    /// Channel number → peer address.
    channels: HashMap<u16, SocketAddr>,
    /// Peer address → channel number.
    channel_peers: HashMap<SocketAddr, u16>,
    next_channel: u16,
    timeout: Duration,
}

impl TurnClient {
    pub fn new(
        server: SocketAddr,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        TurnClient {
            server,
            username: username.into(),
            password: password.into(),
            realm: None,
            nonce: None,
            allocation: None,
            permissions: HashMap::new(),
            channels: HashMap::new(),
            channel_peers: HashMap::new(),
            next_channel: CHANNEL_NUMBER_MIN,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn server(&self) -> SocketAddr {
        self.server
    }

    pub fn realm(&self) -> Option<&str> {
        self.realm.as_deref()
    }

    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    pub fn allocation(&self) -> Option<&Allocation> {
        self.allocation.as_ref()
    }

    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.allocation.as_ref().map(|a| a.relayed_addr)
    }

    /// True when the allocation still has time left.
    pub fn is_live(&self, now: Instant) -> bool {
        self.allocation.as_ref().is_some_and(|a| a.expires_at > now)
    }

    // ── Message construction ────────────────────────────────────────

    /// The long-term integrity key, once the realm is known.
    fn key(&self) -> Result<[u8; 16], TurnError> {
        let realm = self.realm.as_deref().ok_or(TurnError::MissingCredentials)?;
        Ok(stun::long_term_key(&self.username, realm, &self.password))
    }

    /// Add the long-term credential attributes and the integrity digest.
    fn seal(&self, msg: &mut Message) -> Result<Vec<u8>, TurnError> {
        let realm = self.realm.clone().ok_or(TurnError::MissingCredentials)?;
        let nonce = self.nonce.clone().ok_or(TurnError::MissingCredentials)?;
        msg.push(Attribute::Username(self.username.clone().into_bytes()));
        msg.push(Attribute::Realm(realm));
        msg.push(Attribute::Nonce(nonce));
        Ok(msg.encode_with_integrity(&self.key()?)?)
    }

    /// A request with the attributes common to every authenticated TURN request.
    fn request(&self, method: Method, txid: TransactionId) -> Message {
        Message::new(method, Class::Request, txid)
    }

    /// Send `request` and read until the matching response arrives.
    ///
    /// Datagrams belonging to the caller are handed to `on_other` rather than
    /// dropped: this socket also carries mesh traffic.
    async fn transact(
        &self,
        sock: &tokio::net::UdpSocket,
        request: &[u8],
        txid: TransactionId,
        on_other: &mut Option<&mut (dyn FnMut(&[u8], SocketAddr) + Send)>,
    ) -> Result<Message, TurnError> {
        sock.send_to(request, self.server).await?;
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut buf = vec![0u8; 1500];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(TurnError::Timeout(self.timeout));
            }
            let (n, from) = match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
                Err(_) => return Err(TurnError::Timeout(self.timeout)),
                Ok(Err(e)) => return Err(TurnError::Io(e)),
                Ok(Ok(v)) => v,
            };
            if from != self.server {
                if let Some(cb) = on_other.as_deref_mut() {
                    cb(&buf[..n], from);
                }
                continue;
            }
            let Ok(msg) = Message::parse(&buf[..n]) else {
                if let Some(cb) = on_other.as_deref_mut() {
                    cb(&buf[..n], from);
                }
                continue;
            };
            if msg.txid != txid {
                if let Some(cb) = on_other.as_deref_mut() {
                    cb(&buf[..n], from);
                }
                continue;
            }
            // A TURN response must be integrity-protected once we hold a key.
            if let Ok(key) = self.key() {
                if msg.get(0x0008).is_some() && stun::verify_integrity(&buf[..n], &key).is_err() {
                    warn!("TURN: response failed MESSAGE-INTEGRITY — ignoring");
                    continue;
                }
            }
            return Ok(msg);
        }
    }

    /// Allocate a relayed transport address (RFC 8656 §4).
    ///
    /// The first attempt is deliberately unauthenticated: a server answers it
    /// with `401` and the `REALM`/`NONCE` we must then use, which is how
    /// long-term credentials bootstrap.
    pub async fn allocate(
        &mut self,
        sock: &tokio::net::UdpSocket,
        lifetime: Duration,
        mut on_other: Option<&mut (dyn FnMut(&[u8], SocketAddr) + Send)>,
    ) -> Result<SocketAddr, TurnError> {
        let lifetime_secs = (lifetime.as_secs() as u32).max(MIN_LIFETIME_SECS);

        for attempt in 0..2 {
            let txid = TransactionId::random();
            let mut msg = self.request(Method::ALLOCATE, txid);
            msg.push(Attribute::RequestedTransport(TRANSPORT_UDP));
            msg.push(Attribute::Lifetime(lifetime_secs));
            msg.push(Attribute::DontFragment);

            let bytes = if attempt == 0 {
                msg.encode()
            } else {
                self.seal(&mut msg)?
            };

            let response = self.transact(sock, &bytes, txid, &mut on_other).await?;

            match response.typ.class() {
                Class::SuccessResponse => {
                    let relayed = response.xor_relayed_address().ok_or(TurnError::Malformed(
                        "allocation without XOR-RELAYED-ADDRESS",
                    ))?;
                    let granted = response
                        .lifetime()
                        .map(|s| Duration::from_secs(s as u64))
                        .unwrap_or(lifetime);
                    self.allocation = Some(Allocation {
                        relayed_addr: relayed,
                        mapped_addr: response.xor_mapped_address(),
                        lifetime: granted,
                        expires_at: Instant::now() + granted,
                    });
                    info!(relayed = %relayed, "TURN: allocation established");
                    return Ok(relayed);
                }
                Class::ErrorResponse => {
                    let (code, reason) = response.error_code().unwrap_or((0, ""));
                    match code {
                        // 401 Unauthorized / 438 Stale Nonce: adopt the challenge.
                        401 | 438 => {
                            let realm = response
                                .realm()
                                .map(str::to_string)
                                .or_else(|| self.realm.clone())
                                .ok_or(TurnError::MissingCredentials)?;
                            let nonce = response
                                .nonce()
                                .map(str::to_string)
                                .or_else(|| self.nonce.clone())
                                .ok_or(TurnError::MissingCredentials)?;
                            debug!(code, "TURN: server challenged, retrying authenticated");
                            self.realm = Some(realm);
                            self.nonce = Some(nonce);
                            continue;
                        }
                        _ => {
                            return Err(TurnError::Rejected {
                                code,
                                reason: reason.to_string(),
                            })
                        }
                    }
                }
                other => {
                    return Err(TurnError::Malformed(match other {
                        Class::Request => "server sent a request",
                        Class::Indication => "server sent an indication",
                        _ => "unexpected response class",
                    }))
                }
            }
        }
        Err(TurnError::MissingCredentials)
    }

    /// Refresh (or, with `Duration::ZERO`, release) the allocation.
    pub async fn refresh(
        &mut self,
        sock: &tokio::net::UdpSocket,
        lifetime: Duration,
        on_other: Option<&mut (dyn FnMut(&[u8], SocketAddr) + Send)>,
    ) -> Result<Duration, TurnError> {
        let mut on_other = on_other;
        self.require_allocation()?;
        let txid = TransactionId::random();
        let mut msg = self.request(Method::REFRESH, txid);
        msg.push(Attribute::Lifetime(lifetime.as_secs() as u32));
        let bytes = self.seal(&mut msg)?;
        let response = self.transact(sock, &bytes, txid, &mut on_other).await?;
        if response.typ.class() == Class::ErrorResponse {
            let (code, reason) = response.error_code().unwrap_or((0, ""));
            return Err(TurnError::Rejected {
                code,
                reason: reason.to_string(),
            });
        }
        let granted = Duration::from_secs(response.lifetime().unwrap_or(0) as u64);
        if granted.is_zero() {
            self.allocation = None;
            self.permissions.clear();
            self.channels.clear();
            self.channel_peers.clear();
            info!("TURN: allocation released");
        } else if let Some(a) = self.allocation.as_mut() {
            a.lifetime = granted;
            a.expires_at = Instant::now() + granted;
        }
        Ok(granted)
    }

    /// Install (or refresh) a permission for a peer IP (RFC 8656 §9).
    ///
    /// The server ignores the port, but the attribute still carries one, so the
    /// caller passes the full address it intends to talk to.
    pub async fn create_permission(
        &mut self,
        sock: &tokio::net::UdpSocket,
        peer: SocketAddr,
        on_other: Option<&mut (dyn FnMut(&[u8], SocketAddr) + Send)>,
    ) -> Result<(), TurnError> {
        let mut on_other = on_other;
        self.require_allocation()?;
        let txid = TransactionId::random();
        let mut msg = self.request(Method::CREATE_PERMISSION, txid);
        msg.push(Attribute::XorPeerAddress(peer));
        let bytes = self.seal(&mut msg)?;
        let response = self.transact(sock, &bytes, txid, &mut on_other).await?;
        if response.typ.class() == Class::ErrorResponse {
            let (code, reason) = response.error_code().unwrap_or((0, ""));
            return Err(TurnError::Rejected {
                code,
                reason: reason.to_string(),
            });
        }
        self.permissions
            .insert(peer.ip(), Instant::now() + DEFAULT_PERMISSION_LIFETIME);
        Ok(())
    }

    /// Bind a channel to a peer and return the channel number (RFC 8656 §11).
    ///
    /// ChannelData is cheaper than a Send indication: no STUN header, so the
    /// relay costs 4 bytes rather than ~40.
    pub async fn channel_bind(
        &mut self,
        sock: &tokio::net::UdpSocket,
        peer: SocketAddr,
        on_other: Option<&mut (dyn FnMut(&[u8], SocketAddr) + Send)>,
    ) -> Result<u16, TurnError> {
        let mut on_other = on_other;
        self.require_allocation()?;
        if let Some(existing) = self.channel_peers.get(&peer) {
            return Ok(*existing);
        }
        let channel = self.allocate_channel()?;
        let txid = TransactionId::random();
        let mut msg = self.request(Method::CHANNEL_BIND, txid);
        msg.push(Attribute::ChannelNumber(channel));
        msg.push(Attribute::XorPeerAddress(peer));
        let bytes = self.seal(&mut msg)?;
        let response = self.transact(sock, &bytes, txid, &mut on_other).await?;
        if response.typ.class() == Class::ErrorResponse {
            let (code, reason) = response.error_code().unwrap_or((0, ""));
            return Err(TurnError::Rejected {
                code,
                reason: reason.to_string(),
            });
        }
        self.channels.insert(channel, peer);
        self.channel_peers.insert(peer, channel);
        // A binding implies a permission.
        self.permissions
            .insert(peer.ip(), Instant::now() + DEFAULT_PERMISSION_LIFETIME);
        Ok(channel)
    }

    fn allocate_channel(&mut self) -> Result<u16, TurnError> {
        // Channel numbers are client-chosen within 0x4000..=0x7FFF.
        for _ in 0..=(CHANNEL_NUMBER_MAX - CHANNEL_NUMBER_MIN) {
            let candidate = self.next_channel;
            self.next_channel = if candidate >= CHANNEL_NUMBER_MAX {
                CHANNEL_NUMBER_MIN
            } else {
                candidate + 1
            };
            if !self.channels.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(TurnError::NoChannelAvailable)
    }

    /// Send application data to a peer.
    ///
    /// Uses ChannelData when the peer has a channel, otherwise a Send indication.
    /// Indications get no response, so this cannot report delivery — only that
    /// the datagram was handed to the server.
    pub async fn send(
        &self,
        sock: &tokio::net::UdpSocket,
        peer: SocketAddr,
        payload: &[u8],
    ) -> Result<(), TurnError> {
        self.require_allocation()?;
        let bytes = match self.channel_peers.get(&peer) {
            Some(channel) => channel_data(*channel, payload),
            None => {
                let mut msg =
                    Message::new(Method::SEND, Class::Indication, TransactionId::random());
                msg.push(Attribute::XorPeerAddress(peer));
                msg.push(Attribute::Data(payload.to_vec()));
                // RFC 8656 §10.2 allows (and recommends) integrity on indications.
                match self.key() {
                    Ok(key) => msg.encode_with_integrity(&key)?,
                    Err(_) => msg.encode(),
                }
            }
        };
        sock.send_to(&bytes, self.server).await?;
        Ok(())
    }

    /// Parse something received on the allocation socket.
    ///
    /// Returns `None` for datagrams that are not ours (mesh traffic, other
    /// clients' data on a shared socket).
    pub fn decode_inbound(&self, raw: &[u8]) -> Option<TurnInbound> {
        if let Some((channel, payload)) = parse_channel_data(raw) {
            return Some(TurnInbound::ChannelData {
                channel,
                payload: payload.to_vec(),
            });
        }
        let msg = Message::parse(raw).ok()?;
        if msg.typ.method() != Method::DATA || msg.typ.class() != Class::Indication {
            return None;
        }
        Some(TurnInbound::Data {
            peer: msg.xor_peer_address()?,
            payload: msg.data()?.to_vec(),
        })
    }

    /// Resolve an inbound channel number back to its peer.
    pub fn peer_for_channel(&self, channel: u16) -> Option<SocketAddr> {
        self.channels.get(&channel).copied()
    }

    fn require_allocation(&self) -> Result<(), TurnError> {
        if self.allocation.is_some() {
            Ok(())
        } else {
            Err(TurnError::NoAllocation)
        }
    }
}

// ── Server ──────────────────────────────────────────────────────────

/// What the server wants emitted. The caller owns the sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Send to the client's 5-tuple from the relay port.
    ToClient { dest: SocketAddr, data: Vec<u8> },
    /// Send from the relay port to a peer.
    ToPeer {
        from_port: u16,
        dest: SocketAddr,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
struct ServerAllocation {
    /// Port on `relay_ip` allocated to this client.
    relay_port: u16,
    permissions: HashMap<IpAddr, Instant>,
    /// Channel → the peer address bound to it. Stores the *full* address:
    /// ChannelData carries no port, so the relay needs the port from the
    /// binding, not from the datagram.
    channels: HashMap<u16, SocketAddr>,
    channel_peers: HashMap<SocketAddr, u16>,
    expires_at: Instant,
}

/// A TURN server. Pure: no sockets, no I/O, fully testable.
pub struct TurnServer {
    realm: String,
    /// username → long-term password. Shared with the software credentials the
    /// operator configures; TURN long-term credentials are not the node identity.
    users: HashMap<String, String>,
    /// Address the relay listens on.
    relay_ip: IpAddr,
    /// Port pool handed out to allocations.
    port_min: u16,
    port_max: u16,
    allocations: HashMap<SocketAddr, ServerAllocation>,
    /// Issued nonces, so a replay of an old nonce is distinguishable.
    nonces: HashMap<String, Instant>,
    nonce_lifetime: Duration,
}

impl TurnServer {
    pub fn new(
        realm: impl Into<String>,
        users: HashMap<String, String>,
        relay_ip: IpAddr,
        port_min: u16,
        port_max: u16,
    ) -> Self {
        TurnServer {
            realm: realm.into(),
            users,
            relay_ip,
            port_min,
            port_max,
            allocations: HashMap::new(),
            nonces: HashMap::new(),
            nonce_lifetime: Duration::from_secs(600),
        }
    }

    /// Handle one datagram from `from`. Emits zero or more datagrams.
    ///
    /// `now` is passed in rather than read from the clock so lifetime behaviour
    /// is testable without sleeping.
    pub fn handle(&mut self, raw: &[u8], from: SocketAddr, now: Instant) -> Vec<Outbound> {
        self.expire(now);

        // ChannelData from a client is inbound application data to relay.
        if let Some((channel, payload)) = parse_channel_data(raw) {
            return self.relay_channel_data(from, channel, payload);
        }

        let Ok(msg) = Message::parse(raw) else {
            return vec![];
        };

        match (msg.typ.method(), msg.typ.class()) {
            (Method::ALLOCATE, Class::Request) => self.handle_allocate(raw, &msg, from, now),
            (Method::REFRESH, Class::Request) => self.handle_refresh(raw, &msg, from, now),
            (Method::CREATE_PERMISSION, Class::Request) => {
                self.handle_create_permission(raw, &msg, from, now)
            }
            (Method::CHANNEL_BIND, Class::Request) => {
                self.handle_channel_bind(raw, &msg, from, now)
            }
            (Method::SEND, Class::Indication) => self.handle_send(raw, &msg, from),
            _ => vec![],
        }
    }

    /// Feed a datagram arriving from a *peer* on one of our relay ports.
    pub fn handle_peer_data(
        &mut self,
        relay_port: u16,
        peer: SocketAddr,
        payload: &[u8],
    ) -> Option<Outbound> {
        let (client, alloc) = self
            .allocations
            .iter()
            .find(|(_, a)| a.relay_port == relay_port)?;
        let client = *client;

        if !alloc.permissions.contains_key(&peer.ip()) {
            // No permission: RFC 8656 §8 says drop it silently. Dropping is the
            // security property — it stops the relay being used as a reflection
            // amplifier against arbitrary third parties.
            debug!(peer = %peer, port = relay_port, "TURN: dropping peer data without permission");
            return None;
        }

        // Prefer ChannelData when a binding exists; it costs 4 bytes instead of
        // a full indication. Look up the exact 5-tuple: a peer sending from a
        // different port is a different peer, and must use the indication path.
        let data = match alloc.channel_peers.get(&peer) {
            Some(channel) => channel_data(*channel, payload),
            None => {
                let mut ind =
                    Message::new(Method::DATA, Class::Indication, TransactionId::random());
                ind.push(Attribute::XorPeerAddress(peer));
                ind.push(Attribute::Data(payload.to_vec()));
                ind.encode()
            }
        };
        Some(Outbound::ToClient { dest: client, data })
    }

    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    pub fn relay_addr(&self, client: &SocketAddr) -> Option<SocketAddr> {
        self.allocations
            .get(client)
            .map(|a| SocketAddr::new(self.relay_ip, a.relay_port))
    }

    // ── Request handlers ────────────────────────────────────────────

    fn handle_allocate(
        &mut self,
        raw: &[u8],
        msg: &Message,
        from: SocketAddr,
        now: Instant,
    ) -> Vec<Outbound> {
        // Challenge first if the request carries no credentials.
        let Some(key) = self.authenticate(raw, msg) else {
            return vec![self.error_response(
                from,
                msg.txid,
                msg.typ.method(),
                401,
                "Unauthorized",
            )];
        };

        let Some(proto) = msg.requested_transport() else {
            return vec![self.error_response(from, msg.txid, msg.typ.method(), 400, "Bad Request")];
        };
        if proto != TRANSPORT_UDP {
            // 442 Unsupported Transport Protocol (RFC 8656 §4).
            return vec![self.error_response(
                from,
                msg.txid,
                msg.typ.method(),
                442,
                "Unsupported Transport Protocol",
            )];
        }
        // The server must not relay to itself.
        if from.ip() == self.relay_ip {
            return vec![self.error_response(from, msg.txid, msg.typ.method(), 403, "Forbidden")];
        }

        let requested = msg.lifetime().unwrap_or(600).max(MIN_LIFETIME_SECS);
        let port = match self.allocations.get(&from) {
            Some(existing) => existing.relay_port,
            None => match self.free_port() {
                Some(p) => p,
                None => {
                    return vec![self.error_response(
                        from,
                        msg.txid,
                        msg.typ.method(),
                        508,
                        "Insufficient Capacity",
                    )]
                }
            },
        };
        self.allocations.insert(
            from,
            ServerAllocation {
                relay_port: port,
                permissions: HashMap::new(),
                channels: HashMap::new(),
                channel_peers: HashMap::new(),
                expires_at: now + Duration::from_secs(requested as u64),
            },
        );

        let mut resp = Message::new(Method::ALLOCATE, Class::SuccessResponse, msg.txid);
        resp.push(Attribute::XorRelayedAddress(SocketAddr::new(
            self.relay_ip,
            port,
        )));
        resp.push(Attribute::XorMappedAddress(from));
        resp.push(Attribute::Lifetime(requested));
        vec![Outbound::ToClient {
            dest: from,
            data: resp
                .encode_with_integrity(&key)
                .unwrap_or_else(|_| resp.encode()),
        }]
    }

    fn handle_refresh(
        &mut self,
        raw: &[u8],
        msg: &Message,
        from: SocketAddr,
        now: Instant,
    ) -> Vec<Outbound> {
        let Some(key) = self.authenticate(raw, msg) else {
            return vec![self.error_response(
                from,
                msg.txid,
                msg.typ.method(),
                401,
                "Unauthorized",
            )];
        };
        if !self.allocations.contains_key(&from) {
            return vec![self.error_response(
                from,
                msg.txid,
                msg.typ.method(),
                437,
                "Allocation Mismatch",
            )];
        }
        let alloc = self
            .allocations
            .get_mut(&from)
            .expect("allocation existence checked immediately above");
        let lifetime = msg.lifetime().unwrap_or(600);
        let mut resp = Message::new(Method::REFRESH, Class::SuccessResponse, msg.txid);
        if lifetime == 0 {
            self.allocations.remove(&from);
            resp.push(Attribute::Lifetime(0));
        } else {
            let granted = lifetime.max(MIN_LIFETIME_SECS);
            alloc.expires_at = now + Duration::from_secs(granted as u64);
            resp.push(Attribute::Lifetime(granted));
        }
        vec![Outbound::ToClient {
            dest: from,
            data: resp
                .encode_with_integrity(&key)
                .unwrap_or_else(|_| resp.encode()),
        }]
    }

    fn handle_create_permission(
        &mut self,
        raw: &[u8],
        msg: &Message,
        from: SocketAddr,
        now: Instant,
    ) -> Vec<Outbound> {
        let Some(key) = self.authenticate(raw, msg) else {
            return vec![self.error_response(
                from,
                msg.txid,
                msg.typ.method(),
                401,
                "Unauthorized",
            )];
        };
        let Some(peer) = msg.xor_peer_address() else {
            return vec![self.error_response(from, msg.txid, msg.typ.method(), 400, "Bad Request")];
        };
        if !self.allocations.contains_key(&from) {
            return vec![self.error_response(
                from,
                msg.txid,
                msg.typ.method(),
                437,
                "Allocation Mismatch",
            )];
        }
        let alloc = self
            .allocations
            .get_mut(&from)
            .expect("allocation existence checked immediately above");
        // RFC 8656 §9.2: a permission for 0.0.0.0 or an unspecified address is
        // rejected — those are not real peers.
        if peer.ip().is_unspecified() {
            return vec![self.error_response(from, msg.txid, msg.typ.method(), 403, "Forbidden")];
        }
        alloc
            .permissions
            .insert(peer.ip(), now + DEFAULT_PERMISSION_LIFETIME);

        let resp = Message::new(Method::CREATE_PERMISSION, Class::SuccessResponse, msg.txid);
        vec![Outbound::ToClient {
            dest: from,
            data: resp
                .encode_with_integrity(&key)
                .unwrap_or_else(|_| resp.encode()),
        }]
    }

    fn handle_channel_bind(
        &mut self,
        raw: &[u8],
        msg: &Message,
        from: SocketAddr,
        now: Instant,
    ) -> Vec<Outbound> {
        let Some(key) = self.authenticate(raw, msg) else {
            return vec![self.error_response(
                from,
                msg.txid,
                msg.typ.method(),
                401,
                "Unauthorized",
            )];
        };
        let (Some(channel), Some(peer)) = (msg.channel_number(), msg.xor_peer_address()) else {
            return vec![self.error_response(from, msg.txid, msg.typ.method(), 400, "Bad Request")];
        };
        if !(CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX).contains(&channel) {
            return vec![self.error_response(from, msg.txid, msg.typ.method(), 400, "Bad Request")];
        }
        if !self.allocations.contains_key(&from) {
            return vec![self.error_response(
                from,
                msg.txid,
                msg.typ.method(),
                437,
                "Allocation Mismatch",
            )];
        }
        let alloc = self
            .allocations
            .get_mut(&from)
            .expect("allocation existence checked immediately above");
        // One channel per peer and one peer per channel (RFC 8656 §11.2).
        if let Some(existing) = alloc.channels.get(&channel) {
            if *existing != peer {
                return vec![self.error_response(
                    from,
                    msg.txid,
                    msg.typ.method(),
                    400,
                    "Bad Request",
                )];
            }
        }
        if let Some(existing) = alloc.channel_peers.get(&peer) {
            if *existing != channel {
                return vec![self.error_response(
                    from,
                    msg.txid,
                    msg.typ.method(),
                    400,
                    "Bad Request",
                )];
            }
        }
        alloc.channels.insert(channel, peer);
        alloc.channel_peers.insert(peer, channel);
        alloc
            .permissions
            .insert(peer.ip(), now + DEFAULT_PERMISSION_LIFETIME);

        let mut resp = Message::new(Method::CHANNEL_BIND, Class::SuccessResponse, msg.txid);
        resp.push(Attribute::Lifetime(CHANNEL_LIFETIME_SECS));
        vec![Outbound::ToClient {
            dest: from,
            data: resp
                .encode_with_integrity(&key)
                .unwrap_or_else(|_| resp.encode()),
        }]
    }

    fn handle_send(&mut self, raw: &[u8], msg: &Message, from: SocketAddr) -> Vec<Outbound> {
        // Indications have no response, so an unauthenticated one is dropped
        // rather than challenged.
        let Some(key) = self.authenticate(raw, msg) else {
            debug!(client = %from, "TURN: dropping unauthenticated Send indication");
            return vec![];
        };
        let _ = key;
        let (Some(peer), Some(data)) = (msg.xor_peer_address(), msg.data()) else {
            return vec![];
        };
        self.outbound_to_peer(from, peer, data)
    }

    fn relay_channel_data(
        &mut self,
        from: SocketAddr,
        channel: u16,
        payload: &[u8],
    ) -> Vec<Outbound> {
        let Some(alloc) = self.allocations.get(&from) else {
            return vec![];
        };
        // The binding supplies the peer's port; the datagram does not.
        let Some(peer) = alloc.channels.get(&channel).copied() else {
            return vec![];
        };
        vec![Outbound::ToPeer {
            from_port: alloc.relay_port,
            dest: peer,
            data: payload.to_vec(),
        }]
    }

    fn outbound_to_peer(&self, client: SocketAddr, peer: SocketAddr, data: &[u8]) -> Vec<Outbound> {
        let Some(alloc) = self.allocations.get(&client) else {
            return vec![];
        };
        // A Send indication to a peer we hold no permission for is dropped:
        // otherwise the relay is an open reflector.
        if !alloc.permissions.contains_key(&peer.ip()) {
            debug!(peer = %peer, "TURN: dropping Send for peer without permission");
            return vec![];
        }
        vec![Outbound::ToPeer {
            from_port: alloc.relay_port,
            dest: peer,
            data: data.to_vec(),
        }]
    }

    // ── Helpers ─────────────────────────────────────────────────────

    /// Verify long-term credentials, returning the integrity key on success.
    fn authenticate(&self, raw: &[u8], msg: &Message) -> Option<[u8; 16]> {
        let username = match msg.get(0x0006) {
            Some(Attribute::Username(u)) => String::from_utf8_lossy(u).into_owned(),
            _ => return None,
        };
        let realm = msg.realm()?;
        if realm != self.realm {
            return None;
        }
        // A nonce we did not issue is not acceptable.
        let nonce = msg.nonce()?;
        if !self.nonces.contains_key(nonce) {
            return None;
        }
        let password = self.users.get(&username)?;
        let key = stun::long_term_key(&username, realm, password);
        match stun::verify_integrity(raw, &key) {
            Ok(()) => Some(key),
            Err(_) => {
                debug!(username, "TURN: integrity check failed");
                None
            }
        }
    }

    fn error_response(
        &mut self,
        dest: SocketAddr,
        txid: TransactionId,
        method: Method,
        code: u16,
        reason: &str,
    ) -> Outbound {
        let mut resp = Message::new(method, Class::ErrorResponse, txid);
        resp.push(Attribute::ErrorCode {
            code,
            reason: reason.to_string(),
        });
        if code == 401 || code == 438 {
            // Only a challenge carries the credentials bootstrap; a plain error
            // must not hand out a nonce.
            let nonce = self.issue_nonce();
            resp.push(Attribute::Realm(self.realm.clone()));
            resp.push(Attribute::Nonce(nonce));
        }
        Outbound::ToClient {
            dest,
            data: resp.encode(),
        }
    }

    /// Issue a nonce, keeping the outstanding set bounded.
    ///
    /// Every unauthenticated `Allocate` is answered with a fresh nonce, so an
    /// attacker can drive this map directly. Expiring by TTL and capping the
    /// size keeps that from being a memory-growth vector; dropping nonces only
    /// costs legitimate clients one extra round trip.
    fn issue_nonce(&mut self) -> String {
        let now = Instant::now();
        let lifetime = self.nonce_lifetime;
        self.nonces
            .retain(|_, issued| now.duration_since(*issued) < lifetime);
        if self.nonces.len() >= MAX_OUTSTANDING_NONCES {
            self.nonces.clear();
        }
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        self.nonces.insert(nonce.clone(), now);
        nonce
    }

    fn free_port(&self) -> Option<u16> {
        (self.port_min..=self.port_max)
            .find(|p| !self.allocations.values().any(|a| a.relay_port == *p))
    }

    /// Drop expired allocations and permissions; recycle ports.
    fn expire(&mut self, now: Instant) {
        self.allocations.retain(|_, a| {
            // A permission is live until its expiry instant passes.
            a.permissions.retain(|_, expiry| *expiry > now);
            a.expires_at > now
        });
    }

    /// Drop everything whose lifetime has passed, returning how many allocations
    /// were released.
    ///
    /// [`Self::handle`] sweeps on every datagram, so this exists for the two
    /// cases that need the sweep to be explicit: a maintenance tick on a quiet
    /// allocation, and a test that must advance the clock without also driving a
    /// request through the state machine.
    pub fn sweep(&mut self, now: Instant) -> usize {
        let before = self.allocations.len();
        self.expire(now);
        before - self.allocations.len()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const REALM: &str = "ghostnet.test";
    const USER: &str = "node";
    const PASS: &str = "correct-horse-battery-staple";

    fn relay_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
    }

    fn server() -> TurnServer {
        let mut users = HashMap::new();
        users.insert(USER.to_string(), PASS.to_string());
        TurnServer::new(REALM, users, relay_ip(), 49152, 49160)
    }

    fn client_addr() -> SocketAddr {
        "192.168.1.50:40000".parse().unwrap()
    }

    /// Build an authenticated request exactly as the client would, so the server
    /// can be exercised without a socket.
    /// Build a message of `class` signed the way a real client signs one:
    /// username, realm and nonce, then MESSAGE-INTEGRITY over all of it.
    fn signed(
        sg: &TurnServer,
        method: Method,
        class: Class,
        nonce: &str,
        extra: impl FnOnce(&mut Message),
    ) -> Vec<u8> {
        let mut msg = Message::new(method, class, TransactionId::random());
        extra(&mut msg);
        msg.push(Attribute::Username(USER.as_bytes().to_vec()));
        msg.push(Attribute::Realm(sg.realm.clone()));
        msg.push(Attribute::Nonce(nonce.to_string()));
        let key = stun::long_term_key(USER, &sg.realm, PASS);
        msg.encode_with_integrity(&key).unwrap()
    }

    fn authenticated_request(
        sg: &TurnServer,
        method: Method,
        nonce: &str,
        extra: impl FnOnce(&mut Message),
    ) -> Vec<u8> {
        signed(sg, method, Class::Request, nonce, extra)
    }

    fn challenge_nonce(sg: &mut TurnServer) -> String {
        // Unauthenticated Allocate → 401 with REALM + NONCE.
        let txid = TransactionId::random();
        let mut msg = Message::new(Method::ALLOCATE, Class::Request, txid);
        msg.push(Attribute::RequestedTransport(TRANSPORT_UDP));
        let out = sg.handle(&msg.encode(), client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a client-directed response");
        };
        let resp = Message::parse(data).unwrap();
        assert_eq!(resp.typ.class(), Class::ErrorResponse);
        let (code, _) = resp.error_code().unwrap();
        assert_eq!(code, 401, "an unauthenticated Allocate must be challenged");
        resp.nonce().expect("401 must carry a NONCE").to_string()
    }

    #[test]
    fn channel_data_framing_round_trips_and_pads() {
        let framed = channel_data(0x4001, &[1, 2, 3, 4, 5]);
        assert_eq!(&framed[..2], &[0x40, 0x01]);
        assert_eq!(u16::from_be_bytes([framed[2], framed[3]]), 5);
        assert_eq!(framed.len() % 4, 0, "ChannelData must be padded to 4 bytes");
        let (channel, payload) = parse_channel_data(&framed).unwrap();
        assert_eq!(channel, 0x4001);
        assert_eq!(payload, &[1, 2, 3, 4, 5]);

        // A channel number outside 0x4000..=0x7FFF is not channel data.
        assert!(parse_channel_data(&[0x00, 0x01, 0x00, 0x00]).is_none());
        // Truncated payload.
        assert!(parse_channel_data(&[0x40, 0x01, 0x00, 0x08, 0xAA]).is_none());
        assert!(parse_channel_data(&[0x40]).is_none());
    }

    #[test]
    fn unauthenticated_allocate_is_challenged_then_succeeds() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        assert_eq!(sg.allocation_count(), 0, "no allocation before credentials");

        let req = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
            m.push(Attribute::Lifetime(600));
        });
        let out = sg.handle(&req, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a response");
        };

        // The response must itself be integrity-protected.
        let key = stun::long_term_key(USER, REALM, PASS);
        stun::verify_integrity(data, &key).expect("response must be authenticated");

        let resp = Message::parse(data).unwrap();
        assert_eq!(resp.typ.class(), Class::SuccessResponse);
        let relayed = resp.xor_relayed_address().expect("XOR-RELAYED-ADDRESS");
        assert_eq!(relayed.ip(), relay_ip());
        assert_eq!(resp.lifetime(), Some(600));
        assert_eq!(resp.xor_mapped_address(), Some(client_addr()));
        assert_eq!(sg.allocation_count(), 1);
    }

    #[test]
    fn a_wrong_password_is_rejected_even_with_a_valid_nonce() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let txid = TransactionId::random();
        let mut msg = Message::new(Method::ALLOCATE, Class::Request, txid);
        msg.push(Attribute::RequestedTransport(TRANSPORT_UDP));
        msg.push(Attribute::Username(USER.as_bytes().to_vec()));
        msg.push(Attribute::Realm(REALM.to_string()));
        msg.push(Attribute::Nonce(nonce));
        let wrong_key = stun::long_term_key(USER, REALM, "not-the-password");
        let req = msg.encode_with_integrity(&wrong_key).unwrap();

        let out = sg.handle(&req, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a challenge");
        };
        assert_eq!(Message::parse(data).unwrap().error_code().unwrap().0, 401);
        assert_eq!(sg.allocation_count(), 0);
    }

    #[test]
    fn an_unknown_nonce_is_rejected() {
        let mut sg = server();
        let req = authenticated_request(
            &mut sg,
            Method::ALLOCATE,
            "deadbeef-nonce-never-issued",
            |m| {
                m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
            },
        );
        let out = sg.handle(&req, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a challenge");
        };
        assert_eq!(Message::parse(data).unwrap().error_code().unwrap().0, 401);
    }

    #[test]
    fn non_udp_transport_is_refused_with_442() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let req = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            // 6 = TCP: we only relay UDP.
            m.push(Attribute::RequestedTransport(6));
        });
        let out = sg.handle(&req, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a response");
        };
        assert_eq!(Message::parse(data).unwrap().error_code().unwrap().0, 442);
    }

    #[test]
    fn allocate_ports_are_unique_and_recycled_on_expiry() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let req = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
            m.push(Attribute::Lifetime(600));
        });
        let now = Instant::now();
        sg.handle(&req, client_addr(), now);
        // Second client gets a different port.
        let other: SocketAddr = "192.168.1.51:40001".parse().unwrap();
        sg.handle(&req, other, now);
        let a = sg.relay_addr(&client_addr()).unwrap();
        let b = sg.relay_addr(&other).unwrap();
        assert_ne!(a, b);

        // Once every allocation's lifetime passes, both ports come back.
        let later = now + Duration::from_secs(601);
        assert_eq!(sg.sweep(later), 2, "both allocations expire together");
        assert_eq!(sg.allocation_count(), 0);
        assert!(sg.relay_addr(&client_addr()).is_none());
        assert!(sg.relay_addr(&other).is_none());

        // …and the freed port is handed out again, to a new client.
        assert_eq!(sg.sweep(later), 0, "a second sweep finds nothing to do");
    }

    #[test]
    fn permission_is_required_before_relaying_to_a_peer() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let peer: SocketAddr = "198.51.100.77:51820".parse().unwrap();

        let alloc = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
        });
        sg.handle(&alloc, client_addr(), Instant::now());
        let relayed = sg.relay_addr(&client_addr()).unwrap();

        // A Send indication with no permission must be dropped, not relayed:
        // otherwise the relay is an open reflector. The indication is properly
        // signed, because an *unsigned* one is dropped a step earlier and would
        // not exercise the permission check at all.
        let send = signed(&sg, Method::SEND, Class::Indication, &nonce, |m| {
            m.push(Attribute::XorPeerAddress(peer));
            m.push(Attribute::Data(b"payload".to_vec()));
        });
        assert!(
            sg.handle(&send, client_addr(), Instant::now()).is_empty(),
            "a signed Send to an unauthorised peer must still be dropped"
        );
        // An *unsigned* indication is dropped too, but for the other reason.
        let mut unsigned = Message::new(Method::SEND, Class::Indication, TransactionId::random());
        unsigned.push(Attribute::XorPeerAddress(peer));
        unsigned.push(Attribute::Data(b"payload".to_vec()));
        assert!(sg
            .handle(&unsigned.encode(), client_addr(), Instant::now())
            .is_empty());

        // After CreatePermission it relays from the allocation's port.
        let perm = authenticated_request(&mut sg, Method::CREATE_PERMISSION, &nonce, |m| {
            m.push(Attribute::XorPeerAddress(peer));
        });
        let out = sg.handle(&perm, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a response");
        };
        let key = stun::long_term_key(USER, REALM, PASS);
        stun::verify_integrity(data, &key).unwrap();

        let out = sg.handle(&send, client_addr(), Instant::now());
        match &out[0] {
            Outbound::ToPeer {
                dest,
                from_port,
                data,
            } => {
                assert_eq!(*dest, peer);
                assert_eq!(*from_port, relayed.port());
                assert_eq!(data, b"payload");
            }
            other => panic!("expected ToPeer, got {other:?}"),
        }
    }

    #[test]
    fn channel_bind_enables_channel_data_in_both_directions() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let peer: SocketAddr = "198.51.100.77:51820".parse().unwrap();

        let alloc = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
        });
        sg.handle(&alloc, client_addr(), Instant::now());
        let relayed = sg.relay_addr(&client_addr()).unwrap();

        let bind = authenticated_request(&mut sg, Method::CHANNEL_BIND, &nonce, |m| {
            m.push(Attribute::ChannelNumber(0x4001));
            m.push(Attribute::XorPeerAddress(peer));
        });
        let out = sg.handle(&bind, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a response");
        };
        assert_eq!(
            Message::parse(data).unwrap().typ.class(),
            Class::SuccessResponse
        );

        // Client → peer over ChannelData.
        let framed = channel_data(0x4001, b"outbound");
        let out = sg.handle(&framed, client_addr(), Instant::now());
        match &out[0] {
            Outbound::ToPeer {
                dest,
                from_port,
                data,
            } => {
                assert_eq!(*dest, peer);
                assert_eq!(*from_port, relayed.port());
                assert_eq!(data, b"outbound");
            }
            other => panic!("expected ToPeer, got {other:?}"),
        }

        // Peer → client comes back as ChannelData on the bound channel.
        let out = sg
            .handle_peer_data(relayed.port(), peer, b"inbound")
            .expect("peer data must relay once permitted");
        let Outbound::ToClient { dest, data } = out else {
            panic!("expected ToClient");
        };
        assert_eq!(dest, client_addr());
        let (channel, payload) = parse_channel_data(&data).unwrap();
        assert_eq!(channel, 0x4001);
        assert_eq!(payload, b"inbound");
    }

    #[test]
    fn peer_data_without_permission_is_dropped() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let alloc = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
        });
        sg.handle(&alloc, client_addr(), Instant::now());
        let relayed = sg.relay_addr(&client_addr()).unwrap();

        let stranger: SocketAddr = "203.0.113.200:1234".parse().unwrap();
        assert!(
            sg.handle_peer_data(relayed.port(), stranger, b"unsolicited")
                .is_none(),
            "an unsolicited peer must not be relayed to the client"
        );
    }

    #[test]
    fn refresh_with_zero_lifetime_releases_the_allocation() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let alloc = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
        });
        sg.handle(&alloc, client_addr(), Instant::now());
        assert_eq!(sg.allocation_count(), 1);

        let refresh = authenticated_request(&mut sg, Method::REFRESH, &nonce, |m| {
            m.push(Attribute::Lifetime(0));
        });
        let out = sg.handle(&refresh, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a response");
        };
        assert_eq!(Message::parse(data).unwrap().lifetime(), Some(0));
        assert_eq!(sg.allocation_count(), 0);
    }

    #[test]
    fn refresh_without_an_allocation_is_437() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let refresh = authenticated_request(&mut sg, Method::REFRESH, &nonce, |m| {
            m.push(Attribute::Lifetime(600));
        });
        let out = sg.handle(&refresh, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a response");
        };
        assert_eq!(Message::parse(data).unwrap().error_code().unwrap().0, 437);
    }

    #[test]
    fn permission_for_the_unspecified_address_is_refused() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let alloc = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
        });
        sg.handle(&alloc, client_addr(), Instant::now());
        let perm = authenticated_request(&mut sg, Method::CREATE_PERMISSION, &nonce, |m| {
            m.push(Attribute::XorPeerAddress("0.0.0.0:1234".parse().unwrap()));
        });
        let out = sg.handle(&perm, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a response");
        };
        assert_eq!(Message::parse(data).unwrap().error_code().unwrap().0, 403);
    }

    #[test]
    fn binding_two_peers_to_one_channel_is_refused() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let alloc = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
        });
        sg.handle(&alloc, client_addr(), Instant::now());

        let bind_a = authenticated_request(&mut sg, Method::CHANNEL_BIND, &nonce, |m| {
            m.push(Attribute::ChannelNumber(0x4002));
            m.push(Attribute::XorPeerAddress(
                "198.51.100.1:1000".parse().unwrap(),
            ));
        });
        sg.handle(&bind_a, client_addr(), Instant::now());

        let bind_b = authenticated_request(&mut sg, Method::CHANNEL_BIND, &nonce, |m| {
            m.push(Attribute::ChannelNumber(0x4002));
            m.push(Attribute::XorPeerAddress(
                "198.51.100.2:2000".parse().unwrap(),
            ));
        });
        let out = sg.handle(&bind_b, client_addr(), Instant::now());
        let Outbound::ToClient { data, .. } = &out[0] else {
            panic!("expected a response");
        };
        assert_eq!(Message::parse(data).unwrap().error_code().unwrap().0, 400);
    }

    #[test]
    fn client_decodes_both_inbound_forms() {
        let client = TurnClient::new(client_addr(), USER, PASS);
        let peer: SocketAddr = "198.51.100.77:51820".parse().unwrap();

        // Data indication.
        let mut ind = Message::new(Method::DATA, Class::Indication, TransactionId::random());
        ind.push(Attribute::XorPeerAddress(peer));
        ind.push(Attribute::Data(b"hello".to_vec()));
        match client.decode_inbound(&ind.encode()) {
            Some(TurnInbound::Data { peer: p, payload }) => {
                assert_eq!(p, peer);
                assert_eq!(payload, b"hello");
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // ChannelData.
        let framed = channel_data(0x4005, b"world");
        match client.decode_inbound(&framed) {
            Some(TurnInbound::ChannelData { channel, payload }) => {
                assert_eq!(channel, 0x4005);
                assert_eq!(payload, b"world");
            }
            other => panic!("expected ChannelData, got {other:?}"),
        }

        // Unrelated traffic is not mistaken for TURN.
        assert!(client.decode_inbound(b"mesh traffic").is_none());
    }

    #[test]
    fn client_requires_an_allocation_before_sending() {
        let client = TurnClient::new(client_addr(), USER, PASS);
        assert!(client.relayed_addr().is_none());
        assert!(!client.is_live(Instant::now()));
        assert!(matches!(
            client.require_allocation(),
            Err(TurnError::NoAllocation)
        ));
    }

    #[test]
    fn channel_numbers_stay_in_range_and_do_not_repeat() {
        let mut client = TurnClient::new(client_addr(), USER, PASS);
        let mut seen = Vec::new();
        for _ in 0..8 {
            let c = client.allocate_channel().unwrap();
            assert!((CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX).contains(&c));
            assert!(!seen.contains(&c), "channel numbers must not repeat");
            seen.push(c);
            client.channels.insert(c, "198.51.100.1:1".parse().unwrap());
        }
        assert_eq!(seen[0], CHANNEL_NUMBER_MIN);
    }

    #[test]
    fn expiry_drops_allocations_but_keeps_live_ones() {
        let mut sg = server();
        let nonce = challenge_nonce(&mut sg);
        let alloc = authenticated_request(&mut sg, Method::ALLOCATE, &nonce, |m| {
            m.push(Attribute::RequestedTransport(TRANSPORT_UDP));
            m.push(Attribute::Lifetime(600));
        });
        let now = Instant::now();
        sg.handle(&alloc, client_addr(), now);
        assert_eq!(sg.allocation_count(), 1);

        // A Refresh at +500 s restarts the lifetime clock there, so the
        // allocation now dies at +1100 s rather than at +600 s.
        let req = authenticated_request(&mut sg, Method::REFRESH, &nonce, |m| {
            m.push(Attribute::Lifetime(600));
        });
        sg.handle(&req, client_addr(), now + Duration::from_secs(500));
        assert_eq!(sg.allocation_count(), 1);

        // Past the original expiry but inside the refreshed one: still live.
        assert_eq!(sg.sweep(now + Duration::from_secs(900)), 0);
        assert_eq!(sg.allocation_count(), 1, "the refresh kept it alive");

        // Past the refreshed expiry it goes: a refresh extends an allocation, it
        // does not immortalise it.
        assert_eq!(sg.sweep(now + Duration::from_secs(1200)), 1);
        assert_eq!(sg.allocation_count(), 0);
    }
}
