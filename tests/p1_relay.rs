//! Phase 1 gate: the relay fallback (SOTA P1-1, bug B22).
//!
//! `tests/p1_nat.rs` proves ICE either connects or reports honestly. This file
//! covers what happens *after* it reports honestly: the ladder the tunnel takes,
//! and the bytes that cross a relay when it does.
//!
//! The pieces are the real ones — `net::build_gtf_frame`, and the (2,1)
//! Reed-Solomon splitters in `net::l4_rs` — and the network between them is the
//! RFC 4787 NAT model in `common::nat`. What is *not* real is the session layer:
//! the tests hold the keys directly and perform the AEAD calls the relay and the
//! target would perform, because a session requires a handshake that no test can
//! drive without a second process. Everything a byte is compared against is
//! therefore either a real frame or a real ciphertext, never a stand-in.
//!
//! Two properties are the point:
//!
//! 1. What the relay emits is the *frame*, not its own envelope — the target
//!    parses a relayed datagram exactly as it parses a direct one.
//! 2. The relay can decrypt nothing it forwards, and a NAT hands the frame over
//!    only because the target opened a pinhole toward the relay first.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::nat::{DropReason, Nat, SimNet};
use vantablack::ghost::layers::l2_aead::{
    decrypt_in_place_with_context, encrypt_in_place_with_context, NonceDirection,
};
use vantablack::ghost::layers::l4_rs;
use vantablack::ghost::net;
use vantablack::ghost::net::fallback::{self, Fallback, FallbackPath};
use vantablack::ghost::net::relay::{
    self, parse_blind_frame, DerpRelay, DropReason as RelayRefusal,
};
use vantablack::ghost::net::FlowController;

const STUN: &str = "203.0.113.1:3478";
/// The CGNAT's public address, and therefore the address the target advertises.
const TARGET_PUB: &str = "198.51.100.20:40000";
/// The relay: a mesh peer with a routable address.
const RELAY: &str = "203.0.113.77:2270";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

// ── The two halves of the shard path, re-derived ────────────────────
//
// Deliberately local copies of `main.rs::enc_split` and the receive loop's
// assemble-and-decrypt branch. Importing them is impossible (they live in the
// binary), and re-deriving them is *useful*: a change to the shard framing that
// the gate tests do not notice is a change they would not catch either.

/// The sender's half: session-encrypt `payload`, split it (2,1) Reed-Solomon, and
/// build the three GTF datagrams exactly as `send3` would send them.
fn seal_shards(
    key: &[u8; 32],
    sh: [u8; 4],
    ctr: u32,
    dir: NonceDirection,
    payload: &[u8],
) -> Vec<Vec<u8>> {
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(payload);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    encrypt_in_place_with_context(key, ctr, &sh, dir, &mut framed);
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
    let carriers = l4_rs::encode(&mut framed);
    (0..3)
        .map(|i| {
            net::build_gtf_frame(
                sh,
                ctr,
                i as u8,
                &net::frame_shard(&carriers[i]),
                &tag,
                false,
            )
        })
        .collect()
}

/// The target's half: unframe, Reed-Solomon reconstruct from whatever arrived,
/// then decrypt. `None` when fewer than two carriers arrived — the honest answer,
/// since one carrier is unrecoverable.
fn open_shards(
    key: &[u8; 32],
    sh: [u8; 4],
    ctr: u32,
    dir: NonceDirection,
    datagrams: &[Vec<u8>],
) -> Option<Vec<u8>> {
    let mut slots: Vec<Option<Vec<u8>>> = vec![None, None, None];
    for d in datagrams {
        if d.len() < net::OFFSET_AUTH_TAG_START {
            continue;
        }
        let idx = d[net::OFFSET_SHARD_INDEX] as usize;
        if idx > 2 {
            continue;
        }
        slots[idx] = net::unframe(&d[net::OFFSET_PAYLOAD_START..net::OFFSET_AUTH_TAG_START]);
    }
    if slots.iter().filter(|s| s.is_some()).count() < 2 {
        return None;
    }
    let longest = slots.iter().flatten().map(|v| v.len()).max().unwrap_or(0);
    for v in slots.iter_mut().flatten() {
        while v.len() < longest {
            v.push(0);
        }
    }
    let mut work = slots.clone();
    l4_rs::reconstruct(&mut work).ok()?;
    let mut ciphertext = work[0].clone()?;
    ciphertext.extend_from_slice(work[1].as_ref()?);

    let mut msg = ciphertext;
    let pt = decrypt_in_place_with_context(key, ctr, &sh, dir, &mut msg).ok()?;
    let n = u16::from_be_bytes([pt[0], pt[1]]) as usize;
    Some(pt[2..2 + n].to_vec())
}

/// A relay that will forward for both ends, with the target's address as the
/// beacon exchange would have left it.
fn relay_for(target_public: SocketAddr) -> DerpRelay {
    let relay = DerpRelay::new(Arc::new(FlowController::new(100)));
    relay.authorize("alice", addr("192.0.2.10:30000"));
    relay.authorize("bob", target_public);
    relay
}

/// The sender's relay-hop frame, exactly `main.rs::seal_single`: session-encrypt
/// the envelope and carry it in ONE bulk frame with the tunnel bit set.
///
/// It has to be a bulk frame. The envelope is a 40-byte header plus a whole GTF
/// frame — 552-616 bytes — and a privacy frame's payload region holds 486, so the
/// 3-shard path cannot carry it and the single-frame path is the only one that
/// fits. That is a real constraint of the fallback, so the gate asserts it.
fn seal_single(
    key: &[u8; 32],
    sh: [u8; 4],
    ctr: u32,
    dir: NonceDirection,
    payload: &[u8],
) -> Vec<u8> {
    assert!(
        payload.len() + 2 <= net::MAX_BULK_PAYLOAD_LEN,
        "an envelope must fit a bulk frame's payload region"
    );
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(payload);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    encrypt_in_place_with_context(key, ctr, &sh, dir, &mut framed);
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
    let mut frame = net::build_gtf_frame(sh, ctr, 0, &net::frame_shard(&framed), &tag, true);
    frame[net::OFFSET_FLAGS] |= 0x02;
    frame
}

/// The relay's receive path for one datagram, re-derived: it is the single-frame
/// (tunnel-bit) branch of the receive loop — unframe the bulk region, decrypt with
/// the sender's session key, strip the length prefix. Returns the payload the relay
/// would act on, which for a relay hop is the blind envelope.
fn relay_open(envelope_key: &[u8; 32], sh: [u8; 4], ctr: u32, frame: &[u8]) -> Option<Vec<u8>> {
    assert_eq!(
        frame.len(),
        net::GTF_BULK_SIZE,
        "a hop frame is one bulk frame"
    );
    assert_eq!(
        net::parse_flags(frame) & 0x02,
        0x02,
        "the tunnel bit is what tells the relay not to wait for RS siblings"
    );
    let mut ct =
        net::unframe(&frame[net::BULK_OFFSET_PAYLOAD_START..net::BULK_OFFSET_AUTH_TAG_START])?;
    let pt = decrypt_in_place_with_context(
        envelope_key,
        ctr,
        &sh,
        NonceDirection::InitiatorToResponder,
        &mut ct,
    )
    .ok()?;
    let n = u16::from_be_bytes([pt[0], pt[1]]) as usize;
    Some(pt[2..2 + n].to_vec())
}

fn cgnat_net() -> SimNet {
    SimNet::new(
        [addr("192.168.1.50:40000"), addr("10.0.0.7:51000")],
        [
            Nat::carrier_grade("cgnat-a", addr("198.51.100.10:30000").ip(), 30000),
            Nat::carrier_grade("cgnat-b", addr(TARGET_PUB).ip(), 40000),
        ],
        addr(STUN),
    )
}

// ── The gate ────────────────────────────────────────────────────────

#[test]
fn a_relayed_message_reassembles_at_a_peer_behind_cgnat() {
    let mut net = cgnat_net();
    // What the target advertises (its address as the STUN server mapped it)…
    let advertised = net.reflexive_addr(1);
    assert_eq!(advertised, addr(TARGET_PUB));
    // …and the address its NAT actually gives it toward the relay. On a CGNAT
    // these differ, which is exactly why a relay is needed: no peer can use the
    // advertised address, and only the relay's mapping is real.
    let pinhole_addr = net.send_to_public(1, addr(RELAY));
    assert_ne!(
        pinhole_addr, advertised,
        "a symmetric NAT maps the same host differently per destination"
    );

    // The relay knows the target as the source of that keepalive — the same way
    // it learns about any peer, and what `send_relay_keepalives` exists to create.
    let relay = relay_for(pinhole_addr);

    // ── The sender: three carriers, each inside its own envelope, each sealed
    //    again for the relay's session (`seal_single`).
    // The relay learns the target's address from its keepalive, exactly as a
    // beacon would carry it, and that is where the frames are forwarded.
    let target_key = key(0x11);
    let relay_key = key(0x22);
    let sh = [0x9a, 0x11, 0x7c, 0x5e];
    let target_ctr = 7;
    let datagrams = seal_shards(
        &target_key,
        sh,
        target_ctr,
        NonceDirection::InitiatorToResponder,
        b"the bytes that must survive a relay",
    );

    let hop_sh = [0xaa, 0xbb, 0xcc, 0xdd];
    let mut forwarded = Vec::new();
    for (i, datagram) in datagrams.iter().enumerate() {
        let envelope = fallback::blind_envelope("bob", datagram);
        // Each carrier is ~512 bytes and the envelope adds 40: two of them at once
        // would not fit a privacy frame, which is why the hop is a bulk frame.
        let hop_frame = seal_single(
            &relay_key,
            hop_sh,
            100 + i as u32,
            NonceDirection::InitiatorToResponder,
            &envelope,
        );

        // The relay receives it and can read its own layer only.
        let envelope_seen = relay_open(&relay_key, hop_sh, 100 + i as u32, &hop_frame)
            .expect("the relay must be able to read the envelope addressed to it");
        let hop = fallback::relay_hop(&relay, "alice", &envelope_seen)
            .expect("an envelope for a known peer must be forwarded");
        assert_eq!(hop.dest, pinhole_addr, "forwarded to the peer's address");
        assert_eq!(
            hop.bytes, *datagram,
            "the target receives the frame, not the relay's envelope"
        );

        // …and the target's NAT admits it, because of the pinhole above.
        let delivery = net
            .send_external(addr(RELAY), hop.dest, &hop.bytes)
            .expect("a NAT must admit the relay it has a mapping toward");
        assert_eq!(delivery.client, 1);
        forwarded.push(delivery.payload);
    }

    let opened = open_shards(
        &target_key,
        sh,
        target_ctr,
        NonceDirection::InitiatorToResponder,
        &forwarded,
    )
    .expect("three carriers must reassemble");
    assert_eq!(opened, b"the bytes that must survive a relay");
    assert_eq!(relay.stats().0, 3, "one frame forwarded per carrier");
    assert_eq!(
        net.dropped_for(DropReason::Filtered) + net.dropped_for(DropReason::NoMapping),
        0,
        "nothing was dropped once the pinhole existed"
    );
}

#[test]
fn a_relayed_frame_does_not_survive_without_a_pinhole_toward_the_relay() {
    // The same forward, minus the keepalive. This is the test that makes
    // `send_relay_keepalives` load-bearing rather than housekeeping: without a
    // mapping toward the relay, the target's NAT is entitled to drop the frame,
    // and on a CGNAT it does.
    let mut net = cgnat_net();
    let advertised = net.reflexive_addr(1);
    // No keepalive: the target has a mapping toward the STUN server only.
    let relay = relay_for(advertised);

    let envelope = fallback::blind_envelope("bob", b"a sealed GTF frame, 512 bytes of it");
    let hop = fallback::relay_hop(&relay, "alice", &envelope).expect("forwardable");
    assert_eq!(hop.dest, advertised);

    assert!(
        net.send_external(addr(RELAY), hop.dest, &hop.bytes)
            .is_none(),
        "without a pinhole the relay's forward must not reach the peer"
    );
    assert!(
        net.dropped_for(DropReason::Filtered) + net.dropped_for(DropReason::NoMapping) >= 1,
        "and the drop must be visible, not silently absorbed"
    );

    // Open the pinhole and an identical datagram gets through — the difference
    // is the keepalive and nothing else. Note the address changes too: the relay
    // must forward to where the keepalive actually came from.
    let pinhole_addr = net.send_to_public(1, addr(RELAY));
    let hop =
        fallback::relay_hop(&relay_for(pinhole_addr), "alice", &envelope).expect("forwardable");
    assert!(
        net.send_external(addr(RELAY), hop.dest, &hop.bytes)
            .is_some(),
        "the keepalive is what made the relay reachable"
    );
}

#[test]
fn the_relay_cannot_read_what_it_forwards() {
    // Blindness stated as a property of the bytes: the region the relay emits is
    // ciphertext under a key it does not hold, so every key it *could* hold fails.
    let target_key = key(0x33);
    let relay_key = key(0x44);
    let sh = [1, 2, 3, 4];
    let datagrams = seal_shards(
        &target_key,
        sh,
        9,
        NonceDirection::InitiatorToResponder,
        b"not for the relay",
    );
    let relay = relay_for(addr(TARGET_PUB));
    let envelope = fallback::blind_envelope("bob", &datagrams[0]);
    let hop = fallback::relay_hop(&relay, "alice", &envelope).expect("forwardable");

    // The datagram is a well-formed GTF frame — the relay has to be able to see
    // its header to route on, and the header is exactly what it needs to pass on.
    assert_eq!(hop.bytes.len(), datagrams[0].len());
    assert_eq!(hop.bytes, datagrams[0]);

    // Every credential the relay holds fails to open it.
    for attempt in [relay_key, key(0x00), key(0xff)] {
        let mut ct =
            net::unframe(&hop.bytes[net::OFFSET_PAYLOAD_START..net::OFFSET_AUTH_TAG_START])
                .unwrap();
        assert!(
            decrypt_in_place_with_context(
                &attempt,
                7,
                &sh,
                NonceDirection::InitiatorToResponder,
                &mut ct
            )
            .is_err(),
            "a relay must not be able to decrypt the frame it carries"
        );
    }
}

#[test]
fn the_ladder_is_walked_in_order_and_only_records_paths_that_can_carry_traffic() {
    // Direct → mesh relay → TURN, with a route recorded only when a datagram can
    // actually travel it. This is the join that B22 was about: the failure of a
    // punch now produces a path instead of a log line.
    let fallback = Fallback::new(None);
    assert!(!fallback.is_relayed("bob"), "a peer starts direct");

    let candidates = vec![
        ("alice".to_string(), addr("198.51.100.10:30000")),
        ("bob".to_string(), addr(TARGET_PUB)),
        ("helper".to_string(), addr(RELAY)),
    ];
    let chosen = fallback::choose_fallback("alice", "bob", &candidates, None).expect("a relay");
    assert_eq!(
        chosen,
        FallbackPath::MeshRelay {
            relay_fp: "helper".into(),
            relay_addr: addr(RELAY),
        }
    );
    assert!(
        fallback.set("bob", chosen.clone()),
        "a mesh relay needs no allocation"
    );
    assert_eq!(fallback.len(), 1);
    assert!(fallback.is_relayed("bob"));

    // TURN is last, and unusable without an allocation on this side: recording it
    // anyway would turn every send to that peer into a silent drop.
    assert!(!fallback.set(
        "bob",
        FallbackPath::Turn {
            peer_relayed: addr("198.51.100.9:49152"),
        }
    ));
    assert!(
        !fallback.is_relayed("bob"),
        "a path that cannot carry a datagram must not be recorded"
    );

    // A recovered direct path clears the route, so the peer is not relayed again.
    fallback.set("bob", chosen);
    fallback.clear("bob");
    assert!(fallback.is_empty());
    assert_eq!(
        fallback::choose_fallback("alice", "bob", &[], None),
        None,
        "with no relay peer and no allocation there is nowhere to go, and saying so is correct"
    );
}

#[test]
fn a_relay_refuses_the_requests_that_would_make_it_an_amplifier() {
    // The relay's admission rules, asserted through the same entry point the
    // receive path uses. An open relay is a reflection and amplification vector,
    // so none of these may forward.
    let relay = relay_for(addr(TARGET_PUB));
    let sealed = fallback::blind_envelope("bob", b"sealed frame");

    assert_eq!(
        fallback::relay_hop(&relay, "mallory", &sealed),
        Err(RelayRefusal::UnauthorizedSender),
        "no session with the sender, no forwarding"
    );
    assert_eq!(
        fallback::relay_hop(
            &relay,
            "alice",
            &fallback::blind_envelope("alice", b"reflect me")
        ),
        Err(RelayRefusal::Loop),
        "a frame addressed back to its sender is a reflection"
    );
    assert_eq!(
        fallback::relay_hop(
            &relay,
            "alice",
            &fallback::blind_envelope("carol", b"unknown")
        ),
        Err(RelayRefusal::UnknownTarget)
    );
    assert_eq!(
        fallback::relay_hop(&relay, "alice", b"ordinary mesh traffic"),
        Err(RelayRefusal::NotAnEnvelope)
    );

    // Nothing was forwarded, and every refusal that named a peer is counted —
    // including the unauthorized one, which is the signal an operator needs to
    // tell abuse from misconfiguration.
    let (frames, _, dropped) = relay.stats();
    assert_eq!(frames, 0);
    assert_eq!(dropped, 3);
    assert!(parse_blind_frame(&sealed).is_some());
}

#[test]
fn a_multi_hop_onion_and_a_blind_envelope_are_never_confused() {
    // The onion's last hop rewraps with a hop count of zero, which is structurally
    // a blind forward — so the two carry different magics. If this ever fails, one
    // path is re-encrypting the other's ciphertext.
    let onion = relay::build_relay_packet("bob", 1, b"onion hop");
    assert!(parse_blind_frame(&onion).is_none());

    let onion_last_hop = relay::build_relay_packet("bob", 0, b"last hop");
    assert!(
        parse_blind_frame(&onion_last_hop).is_none(),
        "hop count alone cannot distinguish them"
    );

    let blind = fallback::blind_envelope("bob", b"sealed frame");
    assert!(parse_blind_frame(&blind).is_some());
    assert_ne!(&blind[..4], &onion[..4]);

    let relay = relay_for(addr(TARGET_PUB));
    assert_eq!(
        fallback::relay_hop(&relay, "alice", &onion_last_hop),
        Err(RelayRefusal::NotBlindForward),
        "an onion belongs to the hop-forwarding path, not the blind one"
    );
    assert!(fallback::relay_hop(&relay, "alice", &blind).is_ok());
}
