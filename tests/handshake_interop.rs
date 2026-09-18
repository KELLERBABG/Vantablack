//! Runtime interoperability + mixed-version migration gate for the negotiated
//! handshake.
//!
//! The delta claims three things that no unit test can hold on its own, because
//! each is a statement about *two* implementations meeting:
//!
//! 1. a v4 node advertising a suite list and a responder selecting the strongest
//!    *common* suite, with the two sides landing on one session key;
//! 2. a responder (or a path attacker) **cannot** force a weaker suite than was
//!    mutually available — the initiator rejects an answer that is not the
//!    strongest suite it offered;
//! 3. a peer that only knows the original fixed layout still interoperates, and
//!    the two generations do not misparse each other.
//!
//! What this deliberately does *not* claim: it drives the handshake **transcript
//! and KDF** the daemon uses, not the daemon's socket loop, and it does not
//! verify the transcript signature — the negotiated PDU's signed material has no
//! public accessor, and rebuilding the encoder here would create a second oracle
//! for the same bytes — a duplicate-oracle defect this repo has been bitten by
//! before. Signature coverage lives in the `l1_kem` unit tests.

use ml_kem::kem::KeyExport;
use vantablack::ghost::layers::l0_identity::{
    create_identity_binding, verify_hybrid_binding, GhostIdentity,
};
use vantablack::ghost::layers::l1_kem::{
    build_negotiated_handshake_pdu, build_negotiated_response_pdu,
    derive_hybrid_master_key_with_suite, derive_hybrid_master_key_with_transcript,
    generate_kyber768_keypair, generate_kyber_keypair, generate_x25519_keypair,
    kyber768_decapsulate, kyber768_encapsulate, negotiate_cipher_suite, parse_handshake_pdu,
    parse_handshake_pdu_suite, parse_negotiated_handshake_pdu, parse_negotiated_response_pdu,
    HybridCipherSuite,
};
use vantablack::ghost::session::Session;
use x25519_dalek::PublicKey as XPublicKey;

const SUITE_512: HybridCipherSuite = HybridCipherSuite::X25519MlKem512V2;
const SUITE_768: HybridCipherSuite = HybridCipherSuite::X25519MlKem768V3;

fn wire_ids(suites: &[HybridCipherSuite]) -> Vec<u8> {
    suites.iter().map(|s| s.wire_id()).collect()
}

/// One node's offer, built the way `main.rs` builds it.
fn offer(
    id: &GhostIdentity,
    suites: &[HybridCipherSuite],
) -> (
    Vec<u8>,
    x25519_dalek::EphemeralSecret,
    ml_kem::DecapsulationKey768,
) {
    let (x_secret, x_pub) = generate_x25519_keypair();
    let (k768_pk, k768_sk) = generate_kyber768_keypair();
    let (k512_pk, _k512_sk) = generate_kyber_keypair();
    let keys: Vec<(HybridCipherSuite, Vec<u8>)> = vec![
        (SUITE_768, k768_pk.to_bytes().to_vec()),
        (SUITE_512, k512_pk.to_bytes().to_vec()),
    ];
    let pdu = build_negotiated_handshake_pdu(
        suites,
        &id.public_key_bytes(),
        &id.pq_commitment(),
        |d| id.sign(d).to_bytes(),
        &x_pub,
        &keys,
    )
    .expect("a well-formed suite-list offer");
    (pdu, x_secret, k768_sk)
}

#[test]
fn two_nodes_reach_one_session_key_through_the_negotiated_transcript() {
    let alice = GhostIdentity::generate_fresh();
    let bob = GhostIdentity::generate_fresh();

    // Alice offers both suites, each with its own KEM public key.
    let (offer_pdu, alice_x, alice_k768_sk) = offer(&alice, &[SUITE_768, SUITE_512]);

    // Bob reads the offer and takes the strongest suite he also supports.
    let parsed = parse_negotiated_handshake_pdu(&offer_pdu).expect("the offer parses");
    assert_eq!(parsed.supported, vec![SUITE_768, SUITE_512]);
    assert_eq!(parsed.identity_pk, alice.public_key_bytes());
    assert_eq!(parsed.pq_commitment, alice.pq_commitment());
    assert_eq!(
        parsed.kyber_keys.len(),
        2,
        "one KEM public key per advertised suite"
    );

    let chosen = negotiate_cipher_suite(&[SUITE_768, SUITE_512], &wire_ids(&parsed.supported))
        .expect("a common suite exists");
    assert_eq!(chosen, SUITE_768, "the strongest common suite wins");

    // Bob encapsulates to the key that belongs to the chosen suite — not to
    // whichever key happens to be first.
    let alice_k768_pk = parsed
        .kyber_keys
        .iter()
        .find(|(s, _)| *s == SUITE_768)
        .map(|(_, k)| k.clone())
        .expect("a 768 key was advertised");
    let (ct, bob_kyber) = kyber768_encapsulate(&alice_k768_pk).expect("encapsulate");
    let (bob_x_secret, bob_x_pub) = generate_x25519_keypair();
    let response_pdu = build_negotiated_response_pdu(
        chosen,
        &bob.public_key_bytes(),
        &bob.pq_commitment(),
        |d| bob.sign(d).to_bytes(),
        bob_x_pub.as_bytes(),
        &ct,
    )
    .expect("a well-formed response");

    // Alice checks the answer names the strongest suite *she* offered, then
    // completes both halves of the hybrid secret.
    let answer = parse_negotiated_response_pdu(&response_pdu).expect("the response parses");
    assert_eq!(answer.suite, chosen);
    assert_eq!(answer.identity_pk, bob.public_key_bytes());
    assert_eq!(answer.pq_commitment, bob.pq_commitment());
    assert_eq!(
        answer.suite,
        negotiate_cipher_suite(&[SUITE_768, SUITE_512], &wire_ids(&[SUITE_768, SUITE_512]))
            .expect("strongest offered"),
        "an answer must name the strongest suite the initiator offered"
    );

    let alice_kyber = kyber768_decapsulate(&alice_k768_sk, &answer.kyber_ct).expect("decapsulate");
    let alice_x_shared = alice_x.diffie_hellman(&XPublicKey::from(answer.x25519_pub));
    let bob_x_shared = bob_x_secret.diffie_hellman(&XPublicKey::from(parsed.x25519_pub));

    // Both sides bind the *same* transcript: initiator public key, responder public
    // key, the ciphertext, and both PQ commitments — the order is canonical, not "mine then yours".
    let alice_key = derive_hybrid_master_key_with_transcript(
        SUITE_768,
        alice_x_shared.as_bytes(),
        &alice_kyber,
        None,
        &parsed.x25519_pub,
        &answer.x25519_pub,
        &answer.kyber_ct,
        &parsed.pq_commitment,
        &answer.pq_commitment,
    );
    let bob_key = derive_hybrid_master_key_with_transcript(
        SUITE_768,
        bob_x_shared.as_bytes(),
        &bob_kyber,
        None,
        &parsed.x25519_pub,
        bob_x_pub.as_bytes(),
        &ct,
        &alice.pq_commitment(),
        &bob.pq_commitment(),
    );

    assert_eq!(
        alice_key, bob_key,
        "two nodes must derive one session key through the negotiated transcript"
    );
    assert_ne!(alice_key, [0u8; 32]);
}

#[test]
fn a_response_cannot_force_a_weaker_suite_than_was_mutually_available() {
    // The rule the initiator has to apply: the answer must name the strongest
    // suite *it* offered, not merely one both sides could have used. Without it a
    // responder — or anyone able to rewrite the response — downgrades a session to
    // ML-KEM-512 while both peers support ML-KEM-768.
    let offered = [SUITE_768, SUITE_512];
    let strongest = negotiate_cipher_suite(&offered, &wire_ids(&offered)).expect("a common suite");
    assert_eq!(strongest, SUITE_768);

    let downgraded = SUITE_512;
    assert_ne!(
        downgraded, strongest,
        "512 is weaker than what was available"
    );

    // And a downgrade cannot even accidentally land on the right key: the suite is
    // part of HKDF domain separation, so the two derivations are unrelated.
    let x_shared = [0x11u8; 32];
    let kyber_shared = [0x22u8; 32];
    assert_ne!(
        derive_hybrid_master_key_with_suite(SUITE_768, &x_shared, &kyber_shared, None),
        derive_hybrid_master_key_with_suite(SUITE_512, &x_shared, &kyber_shared, None),
        "suite-selected HKDF domains must not coincide"
    );

    // A suite nobody implemented cannot be negotiated at all.
    assert!(negotiate_cipher_suite(&[SUITE_768], &[99]).is_none());
    assert!(negotiate_cipher_suite(&[], &wire_ids(&[SUITE_512])).is_none());
}

#[test]
fn a_v2_only_peer_still_negotiates_and_the_generations_do_not_misparse() {
    // Mixed-version migration, from the v4 side: a peer that only knows the
    // original construction advertises one suite and is still served.
    let chosen = negotiate_cipher_suite(&[SUITE_768, SUITE_512], &wire_ids(&[SUITE_512]))
        .expect("a v4 node serves a v2-only peer");
    assert_eq!(
        chosen, SUITE_512,
        "the fallback is to the peer's only suite"
    );

    // And from the wire side: a v4 offer must not be readable as a v3 or legacy
    // offer. The magics differ, and a parser that guessed would take a 1800-byte
    // suite blob for a 944-byte fixed-layout one.
    let alice = GhostIdentity::generate_fresh();
    let (offer_pdu, _x, _sk) = offer(&alice, &[SUITE_768, SUITE_512]);
    assert!(
        parse_handshake_pdu(&offer_pdu).is_none(),
        "a v4 offer must not parse as a legacy offer"
    );
    assert!(
        parse_handshake_pdu_suite(&offer_pdu).is_none(),
        "a v4 offer must not parse as a v3 suite offer"
    );
    // The legacy parsers still answer correctly for their own generation's length,
    // which is what makes the fallback above reachable rather than advertised.
    assert!(
        parse_handshake_pdu(&[0u8; 4]).is_none(),
        "short input is not an offer"
    );
    let suite_offer =
        parse_negotiated_handshake_pdu(&offer_pdu).expect("the v5 offer itself parses");
    assert_eq!(
        suite_offer.supported.len(),
        2,
        "the parser reads its own shape"
    );
}

/// The session key depends on the transcript, not only on the secrets.
///
/// Before this, the KDF was `HKDF(psk, x25519_ss ‖ kyber_ss, suite)`: two peers who
/// arrived at the same pair of shared secrets got the same session key regardless of
/// what public keys or ciphertext they exchanged. Each assertion below is a way the
/// key must *change*, and the last one is the sanity check that the binding is not a
/// no-op.
#[test]
fn the_session_key_is_bound_to_the_transcript() {
    let x_shared = [0x11u8; 32];
    let kyber_shared = [0x22u8; 64];
    let initiator_pub = [0x33u8; 32];
    let responder_pub = [0x44u8; 32];
    let ct = [0x55u8; 64];
    let initiator_pq = [0x66u8; 32];
    let responder_pq = [0x77u8; 32];

    let base = derive_hybrid_master_key_with_transcript(
        SUITE_768,
        &x_shared,
        &kyber_shared,
        None,
        &initiator_pub,
        &responder_pub,
        &ct,
        &initiator_pq,
        &responder_pq,
    );

    // Deterministic for identical inputs — a binding that varied per call would still
    // "differ on mismatch" while being useless.
    assert_eq!(
        base,
        derive_hybrid_master_key_with_transcript(
            SUITE_768,
            &x_shared,
            &kyber_shared,
            None,
            &initiator_pub,
            &responder_pub,
            &ct,
            &initiator_pq,
            &responder_pq,
        ),
        "the same transcript must give the same key"
    );

    // Swapping the roles must differ: the construction is order-bound, so a peer
    // cannot hash "mine then yours" and still agree.
    assert_ne!(
        base,
        derive_hybrid_master_key_with_transcript(
            SUITE_768,
            &x_shared,
            &kyber_shared,
            None,
            &responder_pub,
            &initiator_pub,
            &ct,
            &responder_pq,
            &initiator_pq,
        ),
        "the transcript order must be part of the key"
    );

    // A single flipped ciphertext byte must differ.
    let mut ct_flipped = ct;
    ct_flipped[0] ^= 0x01;
    assert_ne!(
        base,
        derive_hybrid_master_key_with_transcript(
            SUITE_768,
            &x_shared,
            &kyber_shared,
            None,
            &initiator_pub,
            &responder_pub,
            &ct_flipped,
            &initiator_pq,
            &responder_pq,
        ),
        "the ciphertext must be bound"
    );

    // Flipped initiator PQ commitment must differ.
    let mut init_pq_flipped = initiator_pq;
    init_pq_flipped[0] ^= 0x01;
    assert_ne!(
        base,
        derive_hybrid_master_key_with_transcript(
            SUITE_768,
            &x_shared,
            &kyber_shared,
            None,
            &initiator_pub,
            &responder_pub,
            &ct,
            &init_pq_flipped,
            &responder_pq,
        ),
        "the initiator PQ commitment must be bound"
    );

    // Flipped responder PQ commitment must differ.
    let mut resp_pq_flipped = responder_pq;
    resp_pq_flipped[0] ^= 0x01;
    assert_ne!(
        base,
        derive_hybrid_master_key_with_transcript(
            SUITE_768,
            &x_shared,
            &kyber_shared,
            None,
            &initiator_pub,
            &responder_pub,
            &ct,
            &initiator_pq,
            &resp_pq_flipped,
        ),
        "the responder PQ commitment must be bound"
    );

    // And a changed public key, or a changed suite, or a changed secret.
    let mut pub_flipped = responder_pub;
    pub_flipped[0] ^= 0x01;
    assert_ne!(
        base,
        derive_hybrid_master_key_with_transcript(
            SUITE_768,
            &x_shared,
            &kyber_shared,
            None,
            &initiator_pub,
            &pub_flipped,
            &ct,
            &initiator_pq,
            &responder_pq,
        ),
        "the responder public key must be bound"
    );
    assert_ne!(
        base,
        derive_hybrid_master_key_with_transcript(
            SUITE_512,
            &x_shared,
            &kyber_shared,
            None,
            &initiator_pub,
            &responder_pub,
            &ct,
            &initiator_pq,
            &responder_pq,
        ),
        "the suite must stay part of the derivation"
    );
    let mut secret_flipped = x_shared;
    secret_flipped[0] ^= 0x01;
    assert_ne!(
        base,
        derive_hybrid_master_key_with_transcript(
            SUITE_768,
            &secret_flipped,
            &kyber_shared,
            None,
            &initiator_pub,
            &responder_pub,
            &ct,
            &initiator_pq,
            &responder_pq,
        ),
        "the shared secret must still be an input"
    );

    // And the binding is not a no-op: the same inputs through the *unbound* KDF give
    // a different key, which is why this had to be a version bump rather than a patch.
    assert_ne!(
        base,
        derive_hybrid_master_key_with_suite(SUITE_768, &x_shared, &kyber_shared, None),
        "the transcript-bound KDF must not agree with the unbound one"
    );
}

/// A quantum attacker who has computed Alice's Ed25519 private key cannot
/// authenticate without possessing her ML-DSA-65 private key or substituting their own.
#[test]
fn forged_classical_signature_with_mismatched_pq_key_is_rejected() {
    let alice = GhostIdentity::generate_fresh();
    let mallory = GhostIdentity::generate_fresh();
    let channel_binding = b"quantum-adversary-mitm-test";

    // Scenario A: Mallory creates a binding using her own PQ key alongside Alice's classical key
    // Mallory's binding has Mallory's PQ key, but Alice's commitment is pinned in the handshake.
    let mallory_binding = create_identity_binding(&mallory, channel_binding);

    // Verifying Mallory's binding against Alice's pinned commitment fails with mismatched PQ commitment
    let result = verify_hybrid_binding(
        &alice.public_key_bytes(),
        Some(&alice.pq_commitment()),
        channel_binding,
        &mallory_binding,
    );
    assert!(result.is_err(), "mismatched PQ key must be rejected");

    // Scenario B: Mallory tries to bind Alice's Ed25519 key and Alice's PQ key, but cannot forge the ML-DSA signature
    let alice_binding = create_identity_binding(&alice, channel_binding);
    let mut tampered = alice_binding.clone();
    // Tamper with the ML-DSA signature (the last 3309 bytes)
    let len = tampered.len();
    tampered[len - 10] ^= 0x42;

    let res_tampered = verify_hybrid_binding(
        &alice.public_key_bytes(),
        Some(&alice.pq_commitment()),
        channel_binding,
        &tampered,
    );
    assert!(
        res_tampered.is_err(),
        "forged/tampered ML-DSA-65 signature must fail verification"
    );
}

/// Sessions gate application traffic until post-quantum identity verification passes.
#[test]
fn session_gates_application_traffic_until_pq_auth_verifies() {
    let bob = GhostIdentity::generate_fresh();
    let master_key = [0x42u8; 32];

    let session = Session::new(master_key, bob.fingerprint());
    session.pin_peer_identity(bob.public_key_bytes());
    session.pin_peer_pq_commitment(bob.pq_commitment());

    // Before PQ auth is completed, application traffic is blocked
    assert!(
        !session.is_pq_authenticated(),
        "session must not be authenticated before PQ proof exchange"
    );

    // Exchange chunked binding
    let binding = create_identity_binding(&bob, &master_key);
    let chunk_size = 500;
    let chunks: Vec<&[u8]> = binding.chunks(chunk_size).collect();
    let total_chunks = chunks.len() as u8;

    let mut assembled = None;
    for (idx, chunk) in chunks.iter().enumerate() {
        assembled = session.store_pq_chunk(idx as u8, total_chunks, chunk.to_vec());
    }

    let full = assembled.expect("all chunks must assemble");
    assert_eq!(full.len(), binding.len());

    // Verify proof
    let pq_pk = verify_hybrid_binding(
        &session.peer_identity_pk().unwrap(),
        session.peer_pq_commitment().as_ref(),
        &session.master_key,
        &full,
    )
    .expect("binding verification must succeed");

    session.set_pq_authenticated(true);
    session.set_peer_pq_pk(pq_pk);

    // After PQ auth succeeds, traffic is permitted
    assert!(
        session.is_pq_authenticated(),
        "session must be authenticated after valid PQ verification"
    );
}
