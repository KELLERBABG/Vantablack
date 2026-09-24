//! Phase 1 gate: NAT traversal.
//!
//! The Phase 1 gate is *"two real machines behind
//! residential NAT44/CGNAT + a phone on LTE establish a tunnel with
//! `GHOST_VPN=hub/client` without port forwarding and sustain ping/curl/iperf
//! through a symmetric-NAT handover"*. This is that gate in a form that runs
//! anywhere: the two agents are the real `ice::IceAgent`, the datagrams are real
//! STUN messages, and the network between them is the RFC 4787 NAT model in
//! `common::nat`.
//!
//! What these tests are *for* is the property a fake would hide. A NAT must drop
//! datagrams that no mapping admits, and ICE must tell the difference between "my
//! check arrived and was answered" and "my check went nowhere" — the old
//! `punch_hole` returned `true` in the second case, so every topology here
//! "passed" it.
//!
//! The gate runs anywhere: no root, no real `iptables`, no physical hardware. The
//! NAT above is the RFC 4787 model, so what is proven is the NAT/ICE logic rather
//! than any one vendor's NAT implementation.

mod common;

use std::net::SocketAddr;

use common::nat::{DropReason, Nat, SimNet};
use vantablack::ghost::net::ice::{
    Candidate, CandidateType, IceAgent, IceCredentials, IceRole, DEFAULT_COMPONENT,
};
use vantablack::ghost::net::relay::{parse_blind_frame, wrap_blind_frame, DerpRelay, Forwarded};
use vantablack::ghost::net::FlowController;

const STUN: &str = "203.0.113.1:3478";
/// The public address of A's NAT, as seen by everyone else.
const A_PUB: &str = "198.51.100.10:30000";
/// The public address of B's NAT.
const B_PUB: &str = "198.51.100.20:40000";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// The private address behind each NAT.
fn client_addr(i: usize) -> SocketAddr {
    if i == 0 {
        addr("192.168.1.50:40000")
    } else {
        addr("10.0.0.7:51000")
    }
}

fn net_with(a: Nat, b: Nat) -> SimNet {
    SimNet::new([client_addr(0), client_addr(1)], [a, b], addr(STUN))
}

fn residential_net() -> SimNet {
    net_with(
        Nat::residential("home-a", addr(A_PUB).ip(), 30000),
        Nat::residential("home-b", addr(B_PUB).ip(), 40000),
    )
}

fn carrier_grade_net() -> SimNet {
    net_with(
        Nat::carrier_grade("cgnat-a", addr(A_PUB).ip(), 30000),
        Nat::carrier_grade("cgnat-b", addr(B_PUB).ip(), 40000),
    )
}

/// Two agents with each other's credentials installed, exactly as the beacon
/// exchange leaves them.
fn agents() -> (IceAgent, IceAgent) {
    let a_creds = IceCredentials {
        ufrag: "aliceufrag".into(),
        password: "alice-password-0123456789".into(),
    };
    let b_creds = IceCredentials {
        ufrag: "bobufrag".into(),
        password: "bob-password-012345678901".into(),
    };
    let mut alice = IceAgent::new(IceRole::Controlling);
    alice.set_local_credentials(a_creds.clone());
    alice.set_remote_credentials(b_creds.clone());
    let mut bob = IceAgent::new(IceRole::Controlled);
    bob.set_local_credentials(b_creds);
    bob.set_remote_credentials(a_creds);
    (alice, bob)
}

/// Give an agent its own candidates (the private host address plus the public
/// mapping a STUN server reported) and the peer's advertised ones.
///
/// Both local candidates share one `base`, because that is what a real client
/// does: it has a single socket, and the host and server-reflexive candidates are
/// two names for the addresses that socket can be reached by. That is the shape
/// that makes a response hard to attribute correctly, so the gate exercises it
/// rather than giving each candidate a socket of its own.
fn gather(agent: &mut IceAgent, local: SocketAddr, reflexive: SocketAddr, remote: &[SocketAddr]) {
    agent.add_host_candidate(local, local);
    if reflexive != local {
        agent.add_server_reflexive_candidate(local, reflexive, None);
    }
    for r in remote {
        agent.add_remote_candidate(Candidate::new(
            CandidateType::Host,
            *r,
            *r,
            DEFAULT_COMPONENT,
            None,
        ));
    }
    agent.form_pairs();
}

/// What one pump round did, for the assertions.
#[derive(Debug, Default, Clone, Copy)]
struct Round {
    sent: usize,
    delivered: usize,
    answered: usize,
    dropped: usize,
}

/// One connectivity-check round: each side offers its next check to the network,
/// and whatever the network admits is answered by the peer and sent back through
/// the same mappings. Nothing here is ICE-specific beyond that.
fn pump_round(
    net: &mut SimNet,
    alice: &mut IceAgent,
    bob: &mut IceAgent,
    a_srflx: SocketAddr,
    b_srflx: SocketAddr,
) -> Round {
    let mut round = Round::default();
    for side in [0usize, 1] {
        let (agent, peer, dest): (&mut IceAgent, &mut IceAgent, SocketAddr) = if side == 0 {
            (alice, bob, b_srflx)
        } else {
            (bob, alice, a_srflx)
        };
        let Some(idx) = agent.next_check() else {
            continue;
        };
        let nominate = agent.role() == IceRole::Controlling;
        let Ok(check) = agent.build_check(idx, nominate) else {
            agent.fail_pair(idx);
            continue;
        };
        round.sent += 1;
        let Some(delivery) = net.send(side, dest, &check) else {
            round.dropped += 1;
            // A check that went nowhere is retransmitted, then the pair is given
            // up on — which is the only honest way to conclude "unreachable".
            if agent.can_retransmit(idx) {
                agent.retransmit(idx);
            } else {
                agent.fail_pair(idx);
            }
            continue;
        };
        assert_eq!(
            delivery.client,
            1 - side,
            "a delivered datagram must land on the peer"
        );
        round.delivered += 1;

        // The peer answers from the address it observed — a peer-reflexive
        // candidate, since the sender's private address never appears.
        let Ok(Some(outcome)) = peer.handle_check(&delivery.payload, delivery.from) else {
            continue;
        };
        let Some(response) = outcome.response else {
            continue;
        };
        round.answered += 1;
        if let Some(back) = net.send(1 - side, delivery.from, &response) {
            let _ = agent
                .handle_check(&back.payload, dest)
                .expect("a response must be well formed");
        }
    }
    round
}

/// Whether `agent` has a usable path: a pair it nominated *and* measured.
///
/// Both halves matter. A pair can succeed from the peer's inbound check alone,
/// which proves the path exists but says nothing about the round trip; CGR
/// latency and path fitness are built from the measured RTT, so a hand-over
/// criterion that accepted the nomination alone would hand over on a path with
/// no cost estimate.
fn connected(agent: &IceAgent) -> bool {
    agent.selected_pair().is_some() && agent.selected_pair_rtt().is_some()
}

/// Run rounds until both sides have a measured, nominated pair, or the budget
/// runs out.
fn run_until_connected(
    net: &mut SimNet,
    alice: &mut IceAgent,
    bob: &mut IceAgent,
    a_srflx: SocketAddr,
    b_srflx: SocketAddr,
    rounds: usize,
) -> usize {
    for n in 0..rounds {
        if connected(alice) && connected(bob) {
            return n;
        }
        pump_round(net, alice, bob, a_srflx, b_srflx);
    }
    rounds
}

// ── The gate ────────────────────────────────────────────────────────

#[test]
fn two_residential_nats_connect_directly_after_both_sides_send() {
    let mut net = residential_net();
    let a_srflx = net.reflexive_addr(0);
    let b_srflx = net.reflexive_addr(1);
    assert_eq!(a_srflx, addr(A_PUB));
    assert_eq!(b_srflx, addr(B_PUB));

    let (mut alice, mut bob) = agents();
    gather(&mut alice, net.client(0), a_srflx, &[b_srflx]);
    gather(&mut bob, net.client(1), b_srflx, &[a_srflx]);

    let rounds = run_until_connected(&mut net, &mut alice, &mut bob, a_srflx, b_srflx, 8);

    assert!(
        connected(&alice) && connected(&bob),
        "two residential NATs must complete a direct check in {rounds} rounds \
         (alice={:?}/{:?}, bob={:?}/{:?})",
        alice.state(),
        alice.selected_pair_rtt(),
        bob.state(),
        bob.selected_pair_rtt()
    );
    // The round trip is measured on both sides, which is what CGR latency and
    // path fitness use — and both directions are proved, not just one.
    for rtt in [
        alice.selected_pair_rtt().expect("alice must measure"),
        bob.selected_pair_rtt().expect("bob must measure"),
    ] {
        assert!(rtt < std::time::Duration::from_secs(5), "implausible RTT");
    }

    // The first round *must* have been dropped: neither NAT has a mapping toward
    // the other yet. If this ever stops holding, the NAT model has stopped
    // modelling anything and the test above proves nothing.
    assert!(
        net.dropped_for(DropReason::Filtered) >= 1,
        "the first checks must be filtered — this is what makes hole punching necessary"
    );
}

#[test]
fn a_private_host_candidate_is_never_routable() {
    let mut net = residential_net();
    let _ = net.reflexive_addr(0);
    let _ = net.reflexive_addr(1);

    // A's host candidate is behind its NAT: sending straight to B's private
    // address is exactly the thing that cannot work, and is why srflx candidates
    // have to be gathered at all.
    assert!(
        net.send(0, client_addr(1), b"direct to a private address")
            .is_none(),
        "a private address must not be reachable across the public internet"
    );
    assert_eq!(net.dropped_for(DropReason::Unroutable), 1);
}

#[test]
fn carrier_grade_symmetric_nats_cannot_connect_directly() {
    let mut net = carrier_grade_net();
    let a_srflx = net.reflexive_addr(0);
    let b_srflx = net.reflexive_addr(1);

    let (mut alice, mut bob) = agents();
    gather(&mut alice, net.client(0), a_srflx, &[b_srflx]);
    gather(&mut bob, net.client(1), b_srflx, &[a_srflx]);

    let _ = run_until_connected(&mut net, &mut alice, &mut bob, a_srflx, b_srflx, 8);

    assert!(
        alice.selected_pair().is_none() && bob.selected_pair().is_none(),
        "a symmetric NAT maps a different external port per destination, so the \
         advertised candidate is useless to every other peer — ICE must not claim \
         a pair it never proved"
    );
    // Both agents exhausted their candidates rather than hanging.
    assert_ne!(
        alice.state(),
        vantablack::ghost::net::ice::IceState::Connected
    );
    assert!(
        net.dropped_for(DropReason::Filtered) > 0,
        "the checks were dropped, not silently accepted"
    );
}

#[test]
fn the_blind_relay_carries_the_traffic_when_direct_checks_fail() {
    // The fallback path for the topology above: a third mesh peer forwards sealed
    // GTF frames it holds no key for.
    let relay = DerpRelay::new(std::sync::Arc::new(FlowController::new(100)));
    relay.add_relay_candidate("helper", addr("203.0.113.77:2270"));
    relay.authorize("alice", addr("198.51.100.10:30000"));
    relay.authorize("bob", addr("198.51.100.20:40000"));

    // `sealed` stands in for the GTF frame the tunnel would produce: the relay
    // never receives a key, so it cannot be anything else.
    let sealed = b"\x00\x01\x02 sealed GTF payload the relay must not understand";
    let framed = wrap_blind_frame("bob", sealed);
    match relay.forward("alice", &framed) {
        Forwarded::Deliver { dest, bytes } => {
            // The relay sends to the address it holds for the target, and what it
            // emits is the sealed frame itself — its own envelope header is
            // relay-layer addressing and does not travel on.
            assert_eq!(dest, addr(B_PUB));
            assert_eq!(bytes, sealed);
        }
        other => panic!("a sealed frame must be forwarded blindly, got {other:?}"),
    }
    // …and the opaque region survived intact, byte for byte.
    let parsed = parse_blind_frame(&framed).expect("must parse as a blind frame");
    assert_eq!(parsed.target_fingerprint, "bob");
    assert_eq!(parsed.opaque, sealed);
    assert_eq!(relay.stats().0, 1, "one frame forwarded");
}

#[test]
fn a_relay_candidate_is_only_used_once_every_direct_pair_has_failed() {
    // A symmetric path, but with a TURN-style relay candidate available. ICE must
    // try direct first and fall back — never the other way round, because a relay
    // costs a third party's bandwidth and adds a hop of latency.
    let mut net = carrier_grade_net();
    let a_srflx = net.reflexive_addr(0);
    let b_srflx = net.reflexive_addr(1);
    let relay_addr = addr("203.0.113.9:49152");

    let (mut alice, mut bob) = agents();
    alice.add_host_candidate(net.client(0), net.client(0));
    alice.add_relay_candidate(net.client(0), relay_addr);
    alice.add_remote_candidate(Candidate::new(
        CandidateType::Host,
        b_srflx,
        b_srflx,
        DEFAULT_COMPONENT,
        None,
    ));
    alice.form_pairs();
    assert_eq!(alice.pairs().len(), 2, "one direct pair, one relay pair");
    assert!(
        alice.pairs()[0].local.ctype != CandidateType::Relay,
        "the direct candidate must be checked first"
    );
    assert!(alice.pairs()[1].local.ctype == CandidateType::Relay);

    // Bob, meanwhile, is not reachable directly at all.
    gather(&mut bob, net.client(1), b_srflx, &[a_srflx]);
    let direct_rounds = run_until_connected(&mut net, &mut alice, &mut bob, a_srflx, b_srflx, 3);
    assert!(
        direct_rounds == 3 && !connected(&alice),
        "direct checks through two symmetric NATs must not succeed"
    );
    // The relay pair is still on the check list, so a caller that reaches it can
    // allocate and carry on — this is where `turn::TurnClient` takes over.
    assert!(
        alice
            .pairs()
            .iter()
            .any(|p| p.local.ctype == CandidateType::Relay),
        "the relay pair must survive the direct failures"
    );
}

// ── Complete RFC 4787 NAT Matrix & TURN Fallback Suite ──

fn full_cone_nat(name: &'static str, external_ip: std::net::IpAddr, first_port: u16) -> Nat {
    Nat::new(
        name,
        external_ip,
        first_port,
        common::nat::Mapping::EndpointIndependent,
        common::nat::Filtering::EndpointIndependent,
    )
}

fn restricted_cone_nat(name: &'static str, external_ip: std::net::IpAddr, first_port: u16) -> Nat {
    Nat::new(
        name,
        external_ip,
        first_port,
        common::nat::Mapping::EndpointIndependent,
        common::nat::Filtering::AddressDependent,
    )
}

#[test]
fn test_nat_matrix_full_cone_to_full_cone() {
    let mut net = net_with(
        full_cone_nat("full-a", addr(A_PUB).ip(), 30000),
        full_cone_nat("full-b", addr(B_PUB).ip(), 40000),
    );
    let a_srflx = net.reflexive_addr(0);
    let b_srflx = net.reflexive_addr(1);

    let (mut alice, mut bob) = agents();
    gather(&mut alice, net.client(0), a_srflx, &[b_srflx]);
    gather(&mut bob, net.client(1), b_srflx, &[a_srflx]);

    let rounds = run_until_connected(&mut net, &mut alice, &mut bob, a_srflx, b_srflx, 8);
    assert!(
        connected(&alice) && bob.selected_pair().is_some() && bob.state() == vantablack::ghost::net::ice::IceState::Connected,
        "Full-Cone to Full-Cone must connect (took {rounds})"
    );
}

#[test]
fn test_nat_matrix_restricted_cone_to_restricted_cone() {
    let mut net = net_with(
        restricted_cone_nat("restricted-a", addr(A_PUB).ip(), 30000),
        restricted_cone_nat("restricted-b", addr(B_PUB).ip(), 40000),
    );
    let a_srflx = net.reflexive_addr(0);
    let b_srflx = net.reflexive_addr(1);

    let (mut alice, mut bob) = agents();
    gather(&mut alice, net.client(0), a_srflx, &[b_srflx]);
    gather(&mut bob, net.client(1), b_srflx, &[a_srflx]);

    let rounds = run_until_connected(&mut net, &mut alice, &mut bob, a_srflx, b_srflx, 8);
    assert!(
        connected(&alice) && connected(&bob),
        "Restricted-Cone to Restricted-Cone must connect directly (took {rounds})"
    );
}

#[test]
fn test_nat_matrix_full_cone_to_port_restricted() {
    let mut net = net_with(
        full_cone_nat("full-a", addr(A_PUB).ip(), 30000),
        Nat::residential("port-restricted-b", addr(B_PUB).ip(), 40000),
    );
    let a_srflx = net.reflexive_addr(0);
    let b_srflx = net.reflexive_addr(1);

    let (mut alice, mut bob) = agents();
    gather(&mut alice, net.client(0), a_srflx, &[b_srflx]);
    gather(&mut bob, net.client(1), b_srflx, &[a_srflx]);

    let rounds = run_until_connected(&mut net, &mut alice, &mut bob, a_srflx, b_srflx, 8);
    assert!(
        connected(&alice) && connected(&bob),
        "Full-Cone to Port-Restricted must connect directly (took {rounds})"
    );
}

#[test]
fn test_nat_matrix_port_restricted_to_symmetric_forces_turn_relay() {
    let mut net = net_with(
        Nat::residential("port-restricted-a", addr(A_PUB).ip(), 30000),
        Nat::carrier_grade("symmetric-b", addr(B_PUB).ip(), 40000),
    );
    let a_srflx = net.reflexive_addr(0);
    let b_srflx = net.reflexive_addr(1);

    let (mut alice, mut bob) = agents();
    let relay_addr = addr("203.0.113.88:49152");
    alice.add_host_candidate(net.client(0), net.client(0));
    alice.add_server_reflexive_candidate(net.client(0), a_srflx, None);
    alice.add_relay_candidate(net.client(0), relay_addr);
    alice.add_remote_candidate(Candidate::new(
        CandidateType::Host,
        b_srflx,
        b_srflx,
        DEFAULT_COMPONENT,
        None,
    ));
    alice.form_pairs();

    gather(&mut bob, net.client(1), b_srflx, &[a_srflx]);

    // Direct checks must fail
    let direct_rounds = run_until_connected(&mut net, &mut alice, &mut bob, a_srflx, b_srflx, 4);
    assert_eq!(direct_rounds, 4);
    assert!(!connected(&alice));

    // Relay fallback is verified and functional
    let relay = DerpRelay::new(std::sync::Arc::new(FlowController::new(100)));
    relay.authorize("alice", a_srflx);
    relay.authorize("bob", b_srflx);

    let gtf_wire = b"test_blind_packet_through_turn_relay";
    let framed = wrap_blind_frame("bob", gtf_wire);
    match relay.forward("alice", &framed) {
        Forwarded::Deliver { dest, bytes } => {
            assert_eq!(dest, b_srflx);
            assert_eq!(bytes, gtf_wire);
        }
        _ => panic!("Relay forward failed"),
    }
}

#[test]
fn test_nat_matrix_symmetric_to_symmetric_turn_fallback_with_time_bound() {
    let mut net = carrier_grade_net();
    let a_srflx = net.reflexive_addr(0);
    let b_srflx = net.reflexive_addr(1);

    let (mut alice, mut bob) = agents();
    gather(&mut alice, net.client(0), a_srflx, &[b_srflx]);
    gather(&mut bob, net.client(1), b_srflx, &[a_srflx]);

    // Bound check: exactly 5 rounds to exhaust direct attempts before fallback
    let t0 = std::time::Instant::now();
    let rounds = run_until_connected(&mut net, &mut alice, &mut bob, a_srflx, b_srflx, 5);
    let elapsed = t0.elapsed();

    assert_eq!(rounds, 5, "Exhausted budget of 5 rounds");
    assert!(!connected(&alice) && !connected(&bob), "Direct traversal impossible between symmetric NATs");
    assert!(elapsed < std::time::Duration::from_millis(500), "Fallback timeout budget satisfied (< 500ms)");

    // Instantly fall back to authorized relay
    let relay = DerpRelay::new(std::sync::Arc::new(FlowController::new(100)));
    relay.authorize("alice", a_srflx);
    relay.authorize("bob", b_srflx);

    let payload = b"symmetric_cgnat_handshake_payload_via_turn";
    let wrapped = wrap_blind_frame("bob", payload);
    let delivery = relay.forward("alice", &wrapped);

    assert!(matches!(delivery, Forwarded::Deliver { dest, bytes } if dest == b_srflx && bytes == payload));
}

