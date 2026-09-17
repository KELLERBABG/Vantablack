//! P2-2 wire gate: the GTF v2 frame, the XChaCha epoch seal with a transmitted
//! 96-bit nonce, and the hybrid session ratchet — exercised through the library's
//! public surface, so this is the same code the node runs.
//!
//! The v1 format's end-to-end coverage lives in `tests/simulation.rs`, which is
//! deliberately pinned to v1: a v2 node still has to *accept* v1 frames, and a
//! test that only ever speaks the new format would never notice if it stopped.
//!
//! Run with `cargo test --test p2_wire`.

use vantablack::ghost::layers::l2_aead::{
    random_xnonce, xchacha_open, xchacha_open_with_aad, xchacha_seal_in_place,
    xchacha_seal_in_place_with_aad, NonceDirection,
};

use vantablack::ghost::net::{
    build_gtf_v2_frame, extract_auth_tag, extract_payload, frame_shard, is_v2_frame,
    parse_gtf_v2_header, tail_for, unframe, GtfV2Header, GTF_BASE_SIZE, GTF_VERSION, JITTER_MAX,
};
use vantablack::ghost::session::ratchet::{SessionRatchet, StepSecrets};
use vantablack::ghost::session::{Session, SessionRole};

const SESSION: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// The bytes one `seal_*` call carries: `[len u16][plaintext][pad]` sealed, then
/// handed to the framing layer the way the node does it — `frame_shard` puts a
/// length prefix in front of the ciphertext, and the 16-byte tag travels with the
/// ciphertext as well as in the frame's tag region.
fn sealed_carrier(key: &[u8; 32], epoch: u64, shard: u8, counter: u64, body: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let nonce = random_xnonce();
    let mut framed = (body.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(body);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    xchacha_seal_in_place(
        key,
        &nonce,
        epoch,
        NonceDirection::InitiatorToResponder,
        &mut framed,
    )
    .expect("seal");
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().expect("tag");
    let header = GtfV2Header {
        session_hash: SESSION,
        counter,
        epoch,
        nonce,
        shard_index: shard,
        flags: 0,
        bulk: false,
        // This helper seals with empty associated data (the pre-P3-1 shape), so
        // its tail is empty too: the frame's tail and the AEAD's AAD must agree or
        // a real receiver rejects the frame. The tail's authentication is covered
        // by `p3_1_a_rewritten_jitter_tail_fails_the_tag` below.
        tail: [0u8; JITTER_MAX],
    };
    (build_gtf_v2_frame(&header, &frame_shard(&framed), &tag), tag)
}

/// The ciphertext a receiver recovers from a frame: the framed shard's contents,
/// tag still appended — exactly what `xchacha_open` wants.
fn carried_ciphertext(frame: &[u8]) -> Vec<u8> {
    unframe(extract_payload(frame)).expect("a framed shard")
}

#[test]
fn a_v2_frame_carries_its_epoch_and_nonce_on_the_wire() {
    let key = [0x11u8; 32];
    let (frame, tag) = sealed_carrier(&key, 7, 2, 0x1_0000_0009, b"hello ghost");
    assert!(is_v2_frame(&frame));
    assert!(frame.len() >= GTF_BASE_SIZE);
    assert_eq!(frame[4..8], [0u8; 4], "the reserved word stays zero");

    let h = parse_gtf_v2_header(&frame).expect("a v2 header");
    assert_eq!(h.epoch, 7);
    assert_eq!(h.counter, 0x1_0000_0009, "a counter past the 32-bit wall");
    assert_eq!(h.shard_index, 2);
    assert_eq!(h.session_hash, SESSION);
    assert_eq!(GTF_VERSION, 2);

    // The receiver opens it with the *named* epoch and the *transmitted* nonce.
    let mut ciphertext = carried_ciphertext(&frame);
    let plain = xchacha_open(
        &key,
        &h.nonce,
        h.epoch,
        NonceDirection::InitiatorToResponder,
        &mut ciphertext,
    )
    .expect("open");
    assert_eq!(&plain[2..2 + 11], b"hello ghost");
    // The frame's tag region carries the same tag as the ciphertext's tail.
    assert_eq!(extract_auth_tag(&frame), &tag[..]);
}

#[test]
fn the_wrong_epoch_never_opens_a_v2_frame() {
    // The property the epoch field exists for: a frame is bound to the key
    // generation that sealed it, so a receiver cannot silently use another.
    let key = [0x22u8; 32];
    let (frame, _tag) = sealed_carrier(&key, 3, 0, 42, b"bound to epoch 3");
    let h = parse_gtf_v2_header(&frame).expect("v2 header");
    for wrong in [0u64, 2, 4, 3_000] {
        let mut buf = carried_ciphertext(&frame);
        assert!(
            xchacha_open(
                &key,
                &h.nonce,
                wrong,
                NonceDirection::InitiatorToResponder,
                &mut buf
            )
            .is_err(),
            "epoch {wrong} must not open an epoch-3 frame"
        );
    }
}

#[test]
fn two_sessions_reach_one_key_through_the_ratchet_step() {
    // The whole P2-2 step over the node's own API: one hybrid exchange, two
    // ratchets, one key per direction — checked by sealing with one side and
    // opening with the other.
    let alice = Session::new_with_role([0x5Au8; 32], "alice".into(), SessionRole::Initiator);
    let bob = Session::new_with_role([0x5Au8; 32], "bob".into(), SessionRole::Responder);

    // Epoch 0 keys already agree, because both derive them from one handshake key.
    assert_eq!(
        alice.seal_key(NonceDirection::InitiatorToResponder),
        bob.open_key(0, NonceDirection::InitiatorToResponder, 0).unwrap()
    );

    let (a_x, a_kem) = alice.begin_ratchet_step().expect("alice starts a step");
    let answer = bob
        .answer_ratchet_step(&a_x, &a_kem)
        .expect("bob answers the step");
    // Bob has *prepared* epoch 1, not installed it: he can open it (which the rest
    // of this test then does) but keeps sealing on epoch 0 until a frame he could
    // actually open under the new key arrives.
    assert_eq!(bob.epoch(), 0);
    assert_eq!(bob.prepared_epoch(), Some(1));
    assert_eq!(alice.finish_ratchet_step(&answer), Some(1));
    assert_eq!(alice.epoch(), 1);

    // Alice seals a frame in epoch 1; Bob opens it with the epoch the frame names.
    let material = alice.seal_material();
    assert_eq!(material.epoch, 1);
    let frame = {
        let mut framed = 6u16.to_be_bytes().to_vec();
        framed.extend_from_slice(b"epoch1");
        xchacha_seal_in_place(
            &material.key,
            &material.nonce,
            material.epoch,
            material.direction,
            &mut framed,
        )
        .expect("seal");
        let tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
        let header = GtfV2Header {
            session_hash: SESSION,
            counter: material.counter,
            epoch: material.epoch,
            nonce: material.nonce,
            shard_index: 0,
            flags: 0,
            bulk: false,
            tail: [0u8; JITTER_MAX],
        };
        build_gtf_v2_frame(&header, &frame_shard(&framed), &tag)
    };

    let h = parse_gtf_v2_header(&frame).expect("v2 header");
    let bob_key = bob
        .open_key(h.epoch, NonceDirection::InitiatorToResponder, h.counter)
        .expect("bob holds the epoch alice sealed in");
    let mut buf = carried_ciphertext(&frame);
    let plain = xchacha_open(
        &bob_key,
        &h.nonce,
        h.epoch,
        NonceDirection::InitiatorToResponder,
        &mut buf,
    )
    .expect("bob opens alice's epoch-1 frame");
    assert_eq!(&plain[2..8], b"epoch1");

    // And the epoch-0 key Bob still retains (for frames in flight) will not do it.
    let stale = bob
        .open_key(0, NonceDirection::InitiatorToResponder, h.counter)
        .expect("epoch 0 is still in the grace window");
    let mut buf2 = carried_ciphertext(&frame);
    assert!(xchacha_open(
        &stale,
        &h.nonce,
        h.epoch,
        NonceDirection::InitiatorToResponder,
        &mut buf2
    )
    .is_err());

    // The frame that authenticated under epoch 1 is what installs it — the same
    // `activate_epoch` the receive path calls when a v2 frame names a newer epoch.
    assert!(bob.activate_epoch(1), "the authenticated frame installs the epoch");
    assert_eq!(bob.epoch(), 1);
    assert_eq!(bob.prepared_epoch(), None);
    assert_eq!(
        bob.seal_key(NonceDirection::ResponderToInitiator),
        alice.open_key(1, NonceDirection::ResponderToInitiator, 0).unwrap(),
        "both sides now seal the new epoch in their own direction"
    );
}

#[test]
fn the_ratchet_step_is_refused_without_the_right_secrets() {
    // A substituted X25519 half must not advance the epoch: the confirmation tag
    // is what turns a silently divergent step into a refusal.
    let alice = Session::new_with_role([0x11u8; 32], "alice".into(), SessionRole::Initiator);
    let bob = Session::new_with_role([0x11u8; 32], "bob".into(), SessionRole::Responder);
    let (a_x, a_kem) = alice.begin_ratchet_step().unwrap();
    let answer = bob.answer_ratchet_step(&a_x, &a_kem).unwrap();

    let forged = vantablack::ghost::session::RatchetAnswer {
        x_public: [0u8; 32],
        kem_ct: answer.kem_ct,
        confirm: answer.confirm,
        epoch: answer.epoch,
    };
    assert!(alice.finish_ratchet_step(&forged).is_none());
    assert_eq!(alice.epoch(), 0);
    assert!(alice.check_inbound(0x1_0000_0000), "64-bit window");
}

#[test]
fn a_ratchet_step_replaces_the_epoch_key() {
    let mut ratchet = SessionRatchet::new([0x77u8; 32]);
    let epoch0 = ratchet.seal_key(NonceDirection::InitiatorToResponder);
    let secrets = StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]);
    assert_eq!(ratchet.step(&secrets), 1);
    let epoch1 = ratchet.seal_key(NonceDirection::InitiatorToResponder);
    assert_ne!(epoch0, epoch1);
    // One chain step is what separates them, and it only goes forward.
    assert_eq!(ratchet.open_key(0, NonceDirection::InitiatorToResponder, 0), Some(epoch0));
}

/// SOTA P3-1: the jitter tail is authenticated.
///
/// Three claims, because the tail's job changed from "a variable amount of noise"
/// to "a constant amount of *authenticated* noise":
///
/// 1. a privacy frame is a **constant** 576 B — length is not a signal;
/// 2. an untouched frame opens, with the tail fed to the AEAD as associated data;
/// 3. a **single flipped tail byte** makes the tag check fail — which is the whole
///    point, and was not true before: the tail sat outside Poly1305, so an
///    on-path attacker could rewrite it and the frame still opened.
#[test]
fn p3_1_a_rewritten_jitter_tail_fails_the_tag() {
    let key = [0x33u8; 32];
    let nonce = random_xnonce();
    let epoch = 5u64;
    let dir = NonceDirection::InitiatorToResponder;

    // The sender derives the tail from the seal metadata (it must be known before
    // sealing, and all three shards of one message share it).
    let tail = tail_for(&key, &nonce, epoch, dir);
    let mut framed = 4u16.to_be_bytes().to_vec();
    framed.extend_from_slice(b"body");
    xchacha_seal_in_place_with_aad(&key, &nonce, epoch, dir, &mut framed, &tail).expect("seal");
    let tag: [u8; 16] = framed[framed.len() - 16..].try_into().expect("tag");

    let header = GtfV2Header {
        session_hash: SESSION,
        counter: 1,
        epoch,
        nonce,
        shard_index: 0,
        flags: 0,
        bulk: false,
        tail,
    };
    let mut frame = build_gtf_v2_frame(&header, &frame_shard(&framed), &tag);
    assert_eq!(
        frame.len(),
        GTF_BASE_SIZE + JITTER_MAX,
        "a privacy frame is a constant 576 B"
    );

    // (2) Honest frame: the wire tail is what the sender sealed.
    let mut ct = carried_ciphertext(&frame);
    assert!(
        xchacha_open_with_aad(&key, &nonce, epoch, dir, &mut ct, &frame[GTF_BASE_SIZE..]).is_ok(),
        "the receiver uses the tail it read off the wire"
    );

    // (3) One flipped tail byte.
    frame[GTF_BASE_SIZE] ^= 0xFF;
    let mut ct = carried_ciphertext(&frame);
    assert!(
        xchacha_open_with_aad(&key, &nonce, epoch, dir, &mut ct, &frame[GTF_BASE_SIZE..]).is_err(),
        "a rewritten jitter tail must fail the tag"
    );
}
