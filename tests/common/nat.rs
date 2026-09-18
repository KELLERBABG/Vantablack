//! A software NAT for the Phase 1 gate.
//!
//! The Phase 1 gate is a *network topology* claim: "two real
//! machines behind residential NAT44/CGNAT + a phone on LTE establish a tunnel
//! without port forwarding". That is impossible to assert on a developer machine
//! — and impossible to assert in CI — with `iptables` alone, so the behaviour is
//! modelled here instead: RFC 4787 mapping and filtering, per client, with the
//! port-allocation consequence that makes symmetric NATs hard.
//!
//! Modelling rather than mocking is the point. A NAT that accepts everything
//! would make any ICE implementation look correct; this one drops datagrams for
//! the same reasons a real one does (no mapping, or the filter does not admit
//! the source), which is what lets `tests/p1_nat.rs` distinguish a working
//! connectivity check from a hopeful one.
//!
//! ## What is modelled (RFC 4787 §4)
//!
//! | Mapping | External port depends on |
//! |---|---|
//! | `EndpointIndependent` | nothing — one port reused for every destination (full cone) |
//! | `AddressDependent` | the destination *IP* |
//! | `AddressAndPortDependent` | the destination IP **and** port — this is a symmetric NAT |
//!
//! | Filtering | Inbound admitted from |
//! |---|---|
//! | `EndpointIndependent` | anywhere, once a mapping exists (full cone) |
//! | `AddressDependent` | hosts we have sent to (restricted cone) |
//! | `AddressAndPortDependent` | the exact host:port we have sent to (port-restricted cone) |
//!
//! CGNAT is the interesting combination in practice: `AddressAndPortDependent`
//! mapping *and* filtering, shared across many subscribers.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// How a NAT allocates an external port for an outbound datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    /// One external port for every destination ("full cone" mapping).
    EndpointIndependent,
    /// A distinct external port per destination IP.
    AddressDependent,
    /// A distinct external port per destination IP **and** port (symmetric).
    AddressAndPortDependent,
}

/// Which external sources a NAT will admit inbound datagrams from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filtering {
    /// Anyone may send to an existing mapping (full cone filtering).
    EndpointIndependent,
    /// Only hosts the internal endpoint has sent to.
    AddressDependent,
    /// Only the exact host:port the internal endpoint has sent to.
    AddressAndPortDependent,
}

/// The private address behind simulated client `i`. Fixed, because the NAT model
/// only needs a stable internal endpoint per side.
pub fn client_addr_of(i: usize) -> SocketAddr {
    if i == 0 {
        "192.168.1.50:40000".parse().unwrap()
    } else {
        "10.0.0.7:51000".parse().unwrap()
    }
}

impl Mapping {
    /// The identity of the mapping a datagram belongs to, given its destination.
    fn key(&self, client: SocketAddr, dest: SocketAddr) -> (SocketAddr, IpAddr, u16) {
        match self {
            Mapping::EndpointIndependent => {
                (client, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            }
            Mapping::AddressDependent => (client, dest.ip(), 0),
            Mapping::AddressAndPortDependent => (client, dest.ip(), dest.port()),
        }
    }
}

/// One NAT device with a single internal client.
#[derive(Debug)]
pub struct Nat {
    name: &'static str,
    /// The public address every mapping is bound to.
    external_ip: IpAddr,
    /// Next external port to hand out.
    next_port: u16,
    mapping: Mapping,
    filtering: Filtering,
    /// Mapping identity → external port.
    ports: HashMap<(SocketAddr, IpAddr, u16), u16>,
    /// External port → who owns it, and who we have sent to from it.
    state: HashMap<u16, MappingState>,
}

#[derive(Debug, Default)]
struct MappingState {
    /// Index of the internal client that owns the port.
    client: Option<usize>,
    /// Destinations this mapping has sent to — what the filter is built from.
    peers: Vec<SocketAddr>,
}

impl Nat {
    pub fn new(
        name: &'static str,
        external_ip: IpAddr,
        first_port: u16,
        mapping: Mapping,
        filtering: Filtering,
    ) -> Self {
        Self {
            name,
            external_ip,
            next_port: first_port,
            mapping,
            filtering,
            ports: HashMap::new(),
            state: HashMap::new(),
        }
    }

    /// A residential-style NAT: endpoint-independent mapping, port-restricted
    /// filtering. This is what most home routers do, and direct ICE through two
    /// of them works.
    pub fn residential(name: &'static str, external_ip: IpAddr, first_port: u16) -> Self {
        Self::new(
            name,
            external_ip,
            first_port,
            Mapping::EndpointIndependent,
            Filtering::AddressAndPortDependent,
        )
    }

    /// A carrier-grade NAT: symmetric mapping *and* port-restricted filtering.
    pub fn carrier_grade(name: &'static str, external_ip: IpAddr, first_port: u16) -> Self {
        Self::new(
            name,
            external_ip,
            first_port,
            Mapping::AddressAndPortDependent,
            Filtering::AddressAndPortDependent,
        )
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn external_ip(&self) -> IpAddr {
        self.external_ip
    }

    /// The external address a datagram from `client` to `dest` will appear to
    /// come from, allocating a mapping if this is the first one.
    ///
    /// Calling this *is* the act of sending: the mapping exists afterwards, and
    /// the destination is remembered for the filter.
    pub fn translate_out(&mut self, owner: usize, dest: SocketAddr) -> SocketAddr {
        let key = self.mapping.key(client_addr_of(owner), dest);
        let port = match self.ports.get(&key) {
            Some(p) => *p,
            None => {
                let p = self.next_port;
                self.next_port = self.next_port.saturating_add(1);
                self.ports.insert(key, p);
                self.state.entry(p).or_default().client = Some(owner);
                p
            }
        };
        let entry = self.state.entry(port).or_default();
        if !entry.peers.contains(&dest) {
            entry.peers.push(dest);
        }
        SocketAddr::new(self.external_ip, port)
    }

    /// Deliver an inbound datagram addressed to `external`, coming from `from`.
    ///
    /// `None` means the NAT dropped it: either nothing is bound to that external
    /// port, or the filter does not admit `from`. Both cases are silent on a real
    /// NAT, which is exactly why hole punching needs retransmission.
    pub fn translate_in(&mut self, external: SocketAddr, from: SocketAddr) -> Option<usize> {
        if external.ip() != self.external_ip {
            return None;
        }
        let entry = self.state.get(&external.port())?;
        let allowed = match self.filtering {
            Filtering::EndpointIndependent => true,
            Filtering::AddressDependent => entry.peers.iter().any(|p| p.ip() == from.ip()),
            Filtering::AddressAndPortDependent => entry.peers.contains(&from),
        };
        if !allowed {
            return None;
        }
        entry.client
    }

    /// Whether `addr` is one of this NAT's external addresses.
    pub fn owns(&self, addr: SocketAddr) -> bool {
        addr.ip() == self.external_ip && self.state.contains_key(&addr.port())
    }
}

/// Two NATed clients, one simulated path between them, and a way to see what a
/// STUN server would report.
#[derive(Debug)]
pub struct SimNet {
    clients: [SocketAddr; 2],
    nats: [Nat; 2],
    /// The address of the STUN server both sides discover themselves through.
    pub stun_server: SocketAddr,
    /// Datagrams the network dropped, with the reason — asserted on in tests.
    pub dropped: Vec<DropRecord>,
}

/// A datagram the network admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// Which simulated client received it.
    pub client: usize,
    /// The external address it appears to come from.
    pub from: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropRecord {
    pub to: SocketAddr,
    pub from: SocketAddr,
    pub reason: DropReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Nothing is bound to that external port on the receiving NAT.
    NoMapping,
    /// A mapping exists, but its filter does not admit this source.
    Filtered,
    /// The address is a private one, so it is not routable to the peer at all.
    Unroutable,
}

impl SimNet {
    pub fn new(clients: [SocketAddr; 2], nats: [Nat; 2], stun_server: SocketAddr) -> Self {
        Self {
            clients,
            nats,
            stun_server,
            dropped: Vec::new(),
        }
    }

    pub fn client(&self, i: usize) -> SocketAddr {
        self.clients[i]
    }

    pub fn nat(&self, i: usize) -> &Nat {
        &self.nats[i]
    }

    /// What a STUN server sees when client `i` asks: the reflexive address. This
    /// allocates a mapping toward the STUN server, just as the real discovery
    /// does, which is what makes a symmetric NAT's advertised port wrong for
    /// every other destination.
    pub fn reflexive_addr(&mut self, i: usize) -> SocketAddr {
        self.nats[i].translate_out(i, self.stun_server)
    }

    /// Send `payload` from client `from` to `to`, applying the sender's mapping
    /// and the receiver's filter. `None` means the network dropped it.
    ///
    /// The [`Delivery`] reports the address the datagram *appears* to come from,
    /// because that is the address the receiver must answer — a peer never sees
    /// the sender's private address, and the sender's NAT only accepts the reply
    /// to the very mapping it just created.
    pub fn send(&mut self, from: usize, to: SocketAddr, payload: &[u8]) -> Option<Delivery> {
        let src = self.nats[from].translate_out(from, to);
        // Which NAT, if any, terminates this address?
        let dest_nat = self.nats.iter().position(|n| n.owns(to));
        let Some(dest_nat) = dest_nat else {
            self.dropped.push(DropRecord {
                to,
                from: src,
                reason: if to.ip().is_private() {
                    DropReason::Unroutable
                } else {
                    DropReason::NoMapping
                },
            });
            return None;
        };
        match self.nats[dest_nat].translate_in(to, src) {
            Some(client) => Some(Delivery {
                client,
                from: src,
                payload: payload.to_vec(),
            }),
            None => {
                self.dropped.push(DropRecord {
                    to,
                    from: src,
                    reason: DropReason::Filtered,
                });
                None
            }
        }
    }

    /// Send from client `i` to a host on the public internet — a relay, a STUN
    /// server, any address no simulated NAT owns.
    ///
    /// The datagram leaves through the client's NAT, which is the whole point:
    /// the mapping it creates is the only thing that later admits an inbound
    /// datagram from that host. Returns the public source address the host sees,
    /// which is how a relay learns where to forward to.
    pub fn send_to_public(&mut self, from: usize, to: SocketAddr) -> SocketAddr {
        self.nats[from].translate_out(from, to)
    }

    /// Send `payload` from an address that is already on the public internet — a
    /// relay, a TURN server, a website — to `to`, applying only the receiver's
    /// NAT.
    ///
    /// No mapping is created on the sender's side, because a public host has no
    /// NAT: `from` *is* the address the receiver sees. This is the direction that
    /// matters for the relay fallback, and the one a NAT drops unless the internal
    /// endpoint has already sent something out toward `from`.
    pub fn send_external(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
        payload: &[u8],
    ) -> Option<Delivery> {
        let dest_nat = self.nats.iter().position(|n| n.owns(to));
        let Some(dest_nat) = dest_nat else {
            self.dropped.push(DropRecord {
                to,
                from,
                reason: if to.ip().is_private() {
                    DropReason::Unroutable
                } else {
                    DropReason::NoMapping
                },
            });
            return None;
        };
        match self.nats[dest_nat].translate_in(to, from) {
            Some(client) => Some(Delivery {
                client,
                from,
                payload: payload.to_vec(),
            }),
            None => {
                self.dropped.push(DropRecord {
                    to,
                    from,
                    reason: DropReason::Filtered,
                });
                None
            }
        }
    }

    /// How many datagrams the network dropped for a given reason.
    pub fn dropped_for(&self, reason: DropReason) -> usize {
        self.dropped.iter().filter(|d| d.reason == reason).count()
    }
}

/// Whether the given IP is in a private or otherwise unroutable range.
trait PrivateIp {
    fn is_private(&self) -> bool;
}

impl PrivateIp for IpAddr {
    fn is_private(&self) -> bool {
        match self {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }
}
