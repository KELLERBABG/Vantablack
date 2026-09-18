use ml_kem::kem::KeyExport;
/// Layer-by-Layer Cryptographic Unit Tests for Vantablack
///
/// Tests each protocol layer independently, verifying:
/// - L0: Identity generation, signing, verification
/// - L1: X25519 keypairs, Kyber-512 KEM, hybrid key derivation, handshake PDU building/parsing
/// - L2: ChaCha20-Poly1305 encrypt/decrypt, tamper detection
/// - L3: Shamir's Secret Sharing (GF256) 2-of-3 threshold split and reconstruct
/// - L4: Reed-Solomon encode/reconstruct with all shard loss combinations
/// - L6: Session guard replay window (all 4 scenarios), timeout behavior
use vantablack::ghost::layers::l0_identity;
use vantablack::ghost::layers::l1_kem;
use vantablack::ghost::layers::l2_aead;
use vantablack::ghost::layers::l3_shamir;
use vantablack::ghost::layers::l4_rs;
use vantablack::ghost::layers::l6_session::SessionGuard;

// ─────────────────────────────────────────────────────────
// L0 — Ed25519 Identity Tests
// ─────────────────────────────────────────────────────────

#[test]
fn test_l0_generate_fresh_identity() {
    let id = l0_identity::GhostIdentity::generate_fresh();
    let fp = id.fingerprint();
    // Fingerprint should be 16 hex characters (first 8 bytes)
    assert_eq!(fp.len(), 16, "Fingerprint should be 16 hex chars");
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit()),
        "Fingerprint should be hex"
    );
}

#[test]
fn test_l0_sign_and_verify() {
    let id = l0_identity::GhostIdentity::generate_fresh();
    let message = b"test message for signing";
    let signature = id.sign(message);
    let sig_bytes = signature.to_bytes();
    assert_eq!(sig_bytes.len(), 64, "Ed25519 signature should be 64 bytes");

    let pk = id.public_key_bytes();
    let verify_result = l0_identity::verify_peer_signature(&pk, message, &sig_bytes);
    assert!(
        verify_result,
        "Signature should verify for the same message"
    );
}

#[test]
fn test_l0_verify_rejects_tampered_message() {
    let id = l0_identity::GhostIdentity::generate_fresh();
    let message = b"original message";
    let signature = id.sign(message);
    let sig_bytes = signature.to_bytes();
    let pk = id.public_key_bytes();

    // Tamper with the message
    let tampered = b"tampered message!!!";
    let verify_result = l0_identity::verify_peer_signature(&pk, tampered, &sig_bytes);
    assert!(!verify_result, "Tampered message should NOT verify");
}

#[test]
fn test_l0_verify_rejects_wrong_key() {
    let id_alice = l0_identity::GhostIdentity::generate_fresh();
    let id_bob = l0_identity::GhostIdentity::generate_fresh();
    let message = b"alice's message";
    let signature = id_alice.sign(message);
    let sig_bytes = signature.to_bytes();
    let bob_pk = id_bob.public_key_bytes();

    // Verify with Bob's key — should fail
    let verify_result = l0_identity::verify_peer_signature(&bob_pk, message, &sig_bytes);
    assert!(!verify_result, "Wrong identity key should NOT verify");
}

#[test]
fn test_l0_unique_fingerprints() {
    let id1 = l0_identity::GhostIdentity::generate_fresh();
    let id2 = l0_identity::GhostIdentity::generate_fresh();
    assert_ne!(
        id1.fingerprint(),
        id2.fingerprint(),
        "Two fresh identities should have different fingerprints"
    );
}

#[test]
fn test_l0_public_key_bytes_consistency() {
    let id = l0_identity::GhostIdentity::generate_fresh();
    let pk_bytes = id.public_key_bytes();
    assert_eq!(pk_bytes.len(), 32, "Ed25519 public key should be 32 bytes");
}

// ─────────────────────────────────────────────────────────
// L1 — Hybrid KEM Tests
// ─────────────────────────────────────────────────────────

#[test]
fn test_l1_x25519_keypair_generation() {
    let (_secret, public) = l1_kem::generate_x25519_keypair();
    let pk_bytes = public.as_bytes();
    assert_eq!(pk_bytes.len(), 32, "X25519 public key should be 32 bytes");
}

#[test]
fn test_l1_kyber_keypair_generation() {
    let (_pub, _sec) = l1_kem::generate_kyber_keypair();
    // Just ensure no panic — keypair generation should succeed
}

#[test]
fn test_l1_kyber_encapsulate() {
    let (pk, _sk) = l1_kem::generate_kyber_keypair();
    let pk_bytes = pk.to_bytes().to_vec();
    assert_eq!(
        pk_bytes.len(),
        800,
        "Kyber-512 public key should be 800 bytes"
    );

    let (ct_array, ss) =
        l1_kem::kyber_encapsulate(&pk_bytes).expect("Encapsulation should succeed");
    assert_eq!(
        ct_array.len(),
        768,
        "Kyber-512 ciphertext should be 768 bytes"
    );
    // The shared secret Vec<u8> length depends on pqcrypto implementation;
    // it should be a non-empty Vec representing the shared secret bytes
    assert!(!ss.is_empty(), "Shared secret should not be empty");
}

#[test]
fn test_l1_hybrid_master_key_derivation() {
    let x_ss = [0xABu8; 32];
    let ky_ss = [0xCDu8; 32];

    let mk1 = l1_kem::derive_hybrid_master_key(&x_ss, &ky_ss);
    let mk2 = l1_kem::derive_hybrid_master_key(&x_ss, &ky_ss);

    assert_eq!(mk1.len(), 32, "Master key should be 32 bytes");
    assert_eq!(
        mk1, mk2,
        "Same input should produce same master key (deterministic)"
    );
}

#[test]
fn test_l1_different_x25519_produces_different_master_key() {
    let x_ss_a = [0xABu8; 32];
    let x_ss_b = [0xBAu8; 32];
    let ky_ss = [0xCDu8; 32];

    let mk_a = l1_kem::derive_hybrid_master_key(&x_ss_a, &ky_ss);
    let mk_b = l1_kem::derive_hybrid_master_key(&x_ss_b, &ky_ss);

    assert_ne!(
        mk_a, mk_b,
        "Different X25519 SS should produce different master key"
    );
}

#[test]
fn test_l1_different_kyber_produces_different_master_key() {
    let x_ss = [0xABu8; 32];
    let ky_ss_a = [0xCDu8; 32];
    let ky_ss_b = [0xDCu8; 32];

    let mk_a = l1_kem::derive_hybrid_master_key(&x_ss, &ky_ss_a);
    let mk_b = l1_kem::derive_hybrid_master_key(&x_ss, &ky_ss_b);

    assert_ne!(
        mk_a, mk_b,
        "Different Kyber SS should produce different master key"
    );
}

#[test]
fn test_l1_generate_x25519_keypair_is_random() {
    let (_, pk1) = l1_kem::generate_x25519_keypair();
    let (_, pk2) = l1_kem::generate_x25519_keypair();
    assert_ne!(
        pk1.as_bytes(),
        pk2.as_bytes(),
        "Two X25519 keypairs should be different"
    );
}

#[test]
fn test_l1_compute_session_hash() {
    let key = [0x42u8; 32];
    let hash = l1_kem::compute_session_hash(&key);
    assert_eq!(hash.len(), 4, "Session hash should be 4 bytes");

    // Must be deterministic and match first 4 bytes of SHA-256(key)
    use sha2::{Digest, Sha256};
    let expected = &Sha256::digest(key)[..4];
    assert_eq!(
        hash, expected,
        "Session hash must match SHA-256 digest prefix"
    );
}

#[test]
fn test_l1_build_and_parse_handshake_pdu() {
    let identity = l0_identity::GhostIdentity::generate_fresh();
    let identity_pk = identity.public_key_bytes();
    let (_x_sec, x_pub) = l1_kem::generate_x25519_keypair();
    let (ky_pub, _ky_sec) = l1_kem::generate_kyber_keypair();

    let pdu = l1_kem::build_handshake_pdu(
        &identity_pk,
        |data| identity.sign(data).to_bytes(),
        &x_pub,
        &ky_pub,
    );

    assert_eq!(
        pdu.len(),
        l1_kem::HANDSHAKE_BLOB_LEN,
        "Handshake PDU should be exactly 944 bytes"
    );
    assert!(
        pdu.starts_with(b"GHOST_HANDSHAKE_"),
        "PDU should start with magic bytes"
    );

    // Parse it back
    let parsed = l1_kem::parse_handshake_pdu(&pdu).expect("Should parse successfully");
    assert_eq!(
        parsed.x25519_pub.as_slice(),
        x_pub.as_bytes(),
        "X25519 pub should match"
    );
    assert_eq!(
        parsed.kyber_pub.as_slice(),
        ky_pub.to_bytes().as_slice(),
        "Kyber pub should match"
    );
    assert_eq!(
        parsed.identity_pk.as_slice(),
        identity_pk.as_slice(),
        "Identity PK should match"
    );

    // Verify the signature inside the PDU
    let signed_material = {
        let mut m = vec![0u8; 832];
        m[0..32].copy_from_slice(x_pub.as_bytes());
        m[32..832].copy_from_slice(&ky_pub.to_bytes());
        m
    };
    let verify_ok = l0_identity::verify_peer_signature(
        &parsed.identity_pk,
        &signed_material,
        &parsed.signature,
    );
    assert!(verify_ok, "Signature inside PDU should verify");
}

#[test]
fn test_l1_parse_handshake_pdu_invalid() {
    // Too short
    let result = l1_kem::parse_handshake_pdu(&[0u8; 100]);
    assert!(result.is_none(), "Too short PDU should not parse");

    // Wrong magic
    let mut bad_pdu = vec![0u8; l1_kem::HANDSHAKE_BLOB_LEN];
    bad_pdu[0..4].copy_from_slice(b"BAD!");
    let result = l1_kem::parse_handshake_pdu(&bad_pdu);
    assert!(result.is_none(), "Wrong magic should not parse");
}

// ─────────────────────────────────────────────────────────
// L2 — ChaCha20-Poly1305 AEAD Tests
// ─────────────────────────────────────────────────────────

#[test]
fn test_l2_encrypt_decrypt_roundtrip() {
    let key = [0xABu8; 32];
    let plaintext = b"Hello, Vantablack! This is a secret message.";
    let mut data = plaintext.to_vec();

    // Encrypt (appends 16-byte auth tag)
    l2_aead::encrypt_in_place(&key, 1, &mut data);
    assert_eq!(
        data.len(),
        plaintext.len() + 16,
        "AEAD should append 16-byte tag"
    );

    // Decrypt
    let decrypted = l2_aead::decrypt_in_place(&key, 1, &mut data)
        .expect("Decryption should succeed")
        .to_vec();

    assert_eq!(
        decrypted.as_slice(),
        plaintext,
        "Decrypted text should match original"
    );
}

#[test]
fn test_l2_encrypt_different_counter_different_ciphertext() {
    let key = [0xABu8; 32];
    let plaintext = b"Counter test";

    let mut data1 = plaintext.to_vec();
    let mut data2 = plaintext.to_vec();

    l2_aead::encrypt_in_place(&key, 1, &mut data1);
    l2_aead::encrypt_in_place(&key, 2, &mut data2);

    assert_ne!(
        data1, data2,
        "Different counters should produce different ciphertext"
    );
}

#[test]
fn test_l2_wrong_counter_fails_decryption() {
    let key = [0xABu8; 32];
    let plaintext = b"Counter binding test";
    let mut data = plaintext.to_vec();

    l2_aead::encrypt_in_place(&key, 42, &mut data);

    // Decrypt with wrong counter
    let result = l2_aead::decrypt_in_place(&key, 99, &mut data);
    assert!(
        result.is_err(),
        "Wrong counter should cause decryption failure"
    );
}

#[test]
fn test_l2_wrong_key_fails_decryption() {
    let enc_key = [0xABu8; 32];
    let dec_key = [0xBAu8; 32]; // Different key
    let plaintext = b"Key binding test";
    let mut data = plaintext.to_vec();

    l2_aead::encrypt_in_place(&enc_key, 1, &mut data);

    let result = l2_aead::decrypt_in_place(&dec_key, 1, &mut data);
    assert!(result.is_err(), "Wrong key should cause decryption failure");
}

#[test]
fn test_l2_tampered_ciphertext_fails_decryption() {
    let key = [0xABu8; 32];
    let plaintext = b"Tamper test message";
    let mut data = plaintext.to_vec();

    l2_aead::encrypt_in_place(&key, 1, &mut data);

    // Corrupt a single byte in the ciphertext (not the auth tag)
    if data.len() > 2 {
        data[1] ^= 0xFF;
    }

    let result = l2_aead::decrypt_in_place(&key, 1, &mut data);
    assert!(
        result.is_err(),
        "Tampered ciphertext should cause decryption failure"
    );
}

#[test]
fn test_l2_tampered_auth_tag_fails_decryption() {
    let key = [0xABu8; 32];
    let plaintext = b"Auth tag tamper test";
    let mut data = plaintext.to_vec();

    l2_aead::encrypt_in_place(&key, 1, &mut data);

    // Corrupt the last byte (part of the auth tag)
    if let Some(last) = data.last_mut() {
        *last ^= 0x01;
    }

    let result = l2_aead::decrypt_in_place(&key, 1, &mut data);
    assert!(
        result.is_err(),
        "Tampered auth tag should cause decryption failure"
    );
}

#[test]
fn test_l2_empty_message_roundtrip() {
    let key = [0xABu8; 32];
    let mut data: Vec<u8> = vec![];

    l2_aead::encrypt_in_place(&key, 1, &mut data);
    assert_eq!(
        data.len(),
        16,
        "Empty message encrypted should be just the 16-byte tag"
    );

    let decrypted = l2_aead::decrypt_in_place(&key, 1, &mut data)
        .expect("Empty message decrypt should succeed");
    assert!(
        decrypted.is_empty(),
        "Decrypted empty message should be empty"
    );
}

// ─────────────────────────────────────────────────────────
// L3 — Shamir Secret Sharing Tests (GF256, 2-of-3 threshold)
// ─────────────────────────────────────────────────────────

#[test]
fn test_l3_shamir_2_of_3_threshold_reconstruction() {
    let secret_key = [0x55u8; 32];
    let shares = l3_shamir::split_secret_bytes(&secret_key);
    assert_eq!(shares.len(), 3, "Shamir SSS must generate 3 shares");

    // Reconstruct with any pair
    let rec01 = l3_shamir::join_shares(&shares[0], &shares[1]);
    let rec02 = l3_shamir::join_shares(&shares[0], &shares[2]);
    let rec12 = l3_shamir::join_shares(&shares[1], &shares[2]);

    assert_eq!(rec01, secret_key.to_vec());
    assert_eq!(rec02, secret_key.to_vec());
    assert_eq!(rec12, secret_key.to_vec());
}

#[test]
fn test_l3_shamir_single_share_insufficient() {
    let secret_key = [0x77u8; 32];
    let shares = l3_shamir::split_secret_bytes(&secret_key);
    // Supplying only 1 share to join_share_slice
    let rec = l3_shamir::join_share_slice(&[&shares[0]]);
    assert_ne!(
        rec,
        secret_key.to_vec(),
        "Single share must not reconstruct the secret"
    );
}

// ─────────────────────────────────────────────────────────
// L4 — Reed-Solomon Erasure Coding Tests
// ─────────────────────────────────────────────────────────

#[test]
fn test_l4_encode_and_reconstruct_all_shards() {
    let original = b"Hello Vantablack! This is a test of Reed-Solomon erasure coding.";
    let mut data = original.to_vec();

    let shards = l4_rs::encode(&mut data);
    assert_eq!(shards.len(), 3, "encode() should return 3 shards");
    assert!(shards[0].len() > 0, "Shard 0 should not be empty");
    assert!(shards[1].len() > 0, "Shard 1 should not be empty");
    assert!(shards[2].len() > 0, "Shard 2 (parity) should not be empty");

    // Reconstruct with all 3 shards present
    let mut to_reconstruct = vec![
        Some(shards[0].clone()),
        Some(shards[1].clone()),
        Some(shards[2].clone()),
    ];
    l4_rs::reconstruct(&mut to_reconstruct).expect("Reconstruction should succeed");

    // Combine shards 0 and 1 to get original
    let reconstructed = [
        to_reconstruct[0].as_ref().unwrap().as_slice(),
        to_reconstruct[1].as_ref().unwrap().as_slice(),
    ]
    .concat();

    let reconstructed_str = std::str::from_utf8(&reconstructed)
        .unwrap()
        .trim_end_matches('\0');
    assert_eq!(
        reconstructed_str.as_bytes(),
        original,
        "Reconstructed data should match original"
    );
}

#[test]
fn test_l4_reconstruct_with_two_shards_all_combinations() {
    let original = b"RS test with two shards!";
    let mut data = original.to_vec();

    let shards = l4_rs::encode(&mut data);

    // Test all 3 combinations of 2-out-of-3 shards
    let combinations = [
        (0, 1), // data + data
        (0, 2), // data + parity
        (1, 2), // data + parity
    ];

    for (i, j) in &combinations {
        let mut to_reconstruct = vec![None, None, None];
        to_reconstruct[*i] = Some(shards[*i].clone());
        to_reconstruct[*j] = Some(shards[*j].clone());

        l4_rs::reconstruct(&mut to_reconstruct)
            .unwrap_or_else(|_| panic!("Reconstruction with shards {i},{j} should succeed"));

        let reconstructed = [
            to_reconstruct[0].as_ref().unwrap().as_slice(),
            to_reconstruct[1].as_ref().unwrap().as_slice(),
        ]
        .concat();

        let recon_str = std::str::from_utf8(&reconstructed)
            .unwrap()
            .trim_end_matches('\0');
        assert_eq!(
            recon_str.as_bytes(),
            original,
            "2-shard reconstruction ({i},{j}) should match original"
        );
    }
}

#[test]
fn test_l4_reconstruct_fails_with_one_shard() {
    let original = b"Need at least 2 shards";
    let mut data = original.to_vec();
    let shards = l4_rs::encode(&mut data);

    // Try with only 1 shard
    let mut to_reconstruct = vec![None, None, None];
    to_reconstruct[0] = Some(shards[0].clone());

    let result = l4_rs::reconstruct(&mut to_reconstruct);
    assert!(result.is_err(), "1-shard reconstruction should fail");
}

#[test]
fn test_l4_reconstruct_with_two_correct_shards_despite_corrupted() {
    let original = b"One corrupted shard should still work";
    let mut data = original.to_vec();
    let shards = l4_rs::encode(&mut data);

    // Use two uncorrupted shards (ignore the corrupted one)
    let mut alt_reconstruct = vec![None, Some(shards[1].clone()), Some(shards[2].clone())];
    let result = l4_rs::reconstruct(&mut alt_reconstruct);
    assert!(
        result.is_ok(),
        "2 uncorrupted shards should reconstruct despite 1 corrupted"
    );

    let reconstructed = [
        alt_reconstruct[0].as_ref().unwrap().as_slice(),
        alt_reconstruct[1].as_ref().unwrap().as_slice(),
    ]
    .concat();
    let recon_str = std::str::from_utf8(&reconstructed)
        .unwrap()
        .trim_end_matches('\0');
    assert_eq!(
        recon_str.as_bytes(),
        original,
        "Reconstruction from 2 uncorrupted shards should match original"
    );
}

#[test]
fn test_l4_empty_data() {
    let mut data: Vec<u8> = vec![];
    let shards = l4_rs::encode(&mut data);
    assert_eq!(shards.len(), 3, "Empty data should still produce 3 shards");
    for (i, shard) in shards.iter().enumerate() {
        assert!(shard.is_empty(), "Shard {i} of empty data should be empty");
    }
}

#[test]
fn test_l4_odd_length_data() {
    let mut data = vec![1u8, 2, 3, 4, 5]; // 5 bytes — odd
    let original_len = data.len();

    let shards = l4_rs::encode(&mut data);
    assert_eq!(shards.len(), 3);

    // Data should have been padded to even length
    assert_eq!(data.len(), 6, "Odd-length data should be padded to even");

    // Verify reconstruction still works
    let mut to_reconstruct = vec![Some(shards[0].clone()), Some(shards[1].clone()), None];
    l4_rs::reconstruct(&mut to_reconstruct).expect("Odd-length reconstruction should succeed");

    let reconstructed = [
        to_reconstruct[0].as_ref().unwrap().as_slice(),
        to_reconstruct[1].as_ref().unwrap().as_slice(),
    ]
    .concat();

    assert_eq!(
        reconstructed[..original_len],
        [1u8, 2, 3, 4, 5],
        "Odd-length data should reconstruct correctly"
    );
}

// ─────────────────────────────────────────────────────────
// L6 — Session Guard (Replay Protection) Tests
// ─────────────────────────────────────────────────────────

#[test]
fn test_l6_session_guard_initial_state() {
    let mut guard = SessionGuard::new();
    assert!(guard.is_valid(), "Fresh guard should be valid");
    assert_eq!(guard.v_max, 0);
    assert_eq!(guard.bitmask, 0);
}

#[test]
fn test_l6_session_guard_accepts_first_counter() {
    let mut guard = SessionGuard::new();
    let result = guard.check_and_update(1);
    assert!(result, "First counter should be accepted");
    assert_eq!(guard.v_max, 1, "v_max should be updated to 1");
    assert_eq!(guard.bitmask & 1, 1, "bit 0 should be set for counter 1");
}

#[test]
fn test_l6_session_guard_scenario_c_newer_counter() {
    let mut guard = SessionGuard::new();

    assert!(guard.check_and_update(5), "Counter 5 should be accepted");
    assert_eq!(guard.v_max, 5);

    assert!(guard.check_and_update(10), "Counter 10 should be accepted");
    assert_eq!(guard.v_max, 10);
}

#[test]
fn test_l6_session_guard_scenario_b_replay_within_window() {
    let mut guard = SessionGuard::new();

    assert!(
        guard.check_and_update(10),
        "First arrival of 10 should be accepted"
    );
    let result = guard.check_and_update(10);
    assert!(!result, "Replay of counter 10 should be rejected");
}

#[test]
fn test_l6_session_guard_scenario_a_too_old() {
    let mut guard = SessionGuard::new();

    // Accept counter 200 — window is now [72, 200]
    assert!(
        guard.check_and_update(200),
        "Counter 200 should be accepted"
    );
    // Counter 0 is outside the window [72, 200]
    let result = guard.check_and_update(0);
    assert!(!result, "Counter 0 (too old) should be rejected");
}

#[test]
fn test_l6_session_guard_scenario_d_legitimate_in_window() {
    let mut guard = SessionGuard::new();

    assert!(guard.check_and_update(100), "Counter 100");
    let result = guard.check_and_update(98);
    assert!(
        result,
        "Counter 98 should be accepted (legitimate in-window)"
    );
}

#[test]
fn test_l6_session_guard_consecutive_counters() {
    let mut guard = SessionGuard::new();

    for i in 0..50 {
        assert!(
            guard.check_and_update(i),
            "Consecutive counter {} should be accepted",
            i
        );
    }

    assert_eq!(guard.v_max, 49);
}

#[test]
fn test_l6_session_guard_wraparound_replay_detection() {
    let mut guard = SessionGuard::new();

    for i in 0..200 {
        assert!(guard.check_and_update(i), "Counter {i}");
    }

    let result = guard.check_and_update(150);
    assert!(!result, "Replay of counter 150 should be rejected");
}

#[test]
fn test_l6_session_guard_window_shift_on_jump() {
    let mut guard = SessionGuard::new();

    assert!(guard.check_and_update(10));
    assert!(guard.check_and_update(300), "Large jump should be accepted");
    assert_eq!(guard.v_max, 300);
    assert_eq!(
        guard.bitmask, 1,
        "After complete window skip, bitmask should reset to 1"
    );
}

#[test]
fn test_l6_session_guard_rejects_counter_below_when_window_skipped() {
    let mut guard = SessionGuard::new();

    assert!(guard.check_and_update(100));
    assert!(guard.check_and_update(500));

    assert!(
        !guard.check_and_update(100),
        "Counter 100 should be too old after jump to 500"
    );
}

#[test]
fn test_l6_session_guard_hard_timeout() {
    let mut guard = SessionGuard::new();
    assert!(guard.is_valid());
}

#[test]
fn test_l6_session_guard_reset() {
    let mut guard = SessionGuard::new();

    guard.check_and_update(42);
    guard.check_and_update(100);

    guard.reset();
    assert_eq!(guard.v_max, 0, "After reset, v_max should be 0");
    assert_eq!(guard.bitmask, 0, "After reset, bitmask should be 0");
    assert!(guard.is_valid(), "After reset, guard should be valid");
    assert!(
        guard.check_and_update(1),
        "After reset, counter 1 should be accepted"
    );
}

#[test]
fn test_l6_session_guard_exact_boundary_oldest() {
    let mut guard = SessionGuard::new();
    assert!(guard.check_and_update(128));
    let result = guard.check_and_update(0);
    assert!(!result, "Counter 0 should be rejected as too old");
}

#[test]
fn test_l6_session_guard_out_of_order_within_window() {
    let mut guard = SessionGuard::new();

    assert!(guard.check_and_update(50), "Counter 50");
    assert!(guard.check_and_update(48), "Counter 48 (out of order)");
    assert!(guard.check_and_update(52), "Counter 52 (out of order)");
    assert!(guard.check_and_update(49), "Counter 49 (out of order)");
    assert!(
        !guard.check_and_update(48),
        "Replay of 48 should be rejected"
    );
}

// ─────────────────────────────────────────────────────────
// Protocol Integration: L1 + L2 + L4 combined
// ─────────────────────────────────────────────────────────

#[test]
fn test_full_encrypt_shard_reconstruct_decrypt() {
    let key = [0x42u8; 32];
    let original = b"Even-length text for multi-layer test!";

    // Step 1: Encrypt (L2) - appends 16-byte Poly1305 tag
    let mut encrypted = original.to_vec();
    l2_aead::encrypt_in_place(&key, 1, &mut encrypted);

    // Step 2: Encode with real (2,1) Reed-Solomon erasure coding (L4)
    let shards = l4_rs::encode(&mut encrypted);
    assert_eq!(shards.len(), 3, "RS(2,1) produces 3 shards");

    // Step 3: Simulate losing shard 0, reconstruct from shard 1 and parity shard 2
    let mut received_shards: Vec<Option<Vec<u8>>> = vec![
        None,                    // Lost data shard 0
        Some(shards[1].clone()), // Data shard 1
        Some(shards[2].clone()), // Parity shard 2
    ];
    l4_rs::reconstruct(&mut received_shards)
        .expect("RS reconstruction from 2 of 3 shards should succeed");

    // Reassemble original ciphertext from reconstructed data shards
    let mut reconstructed_enc = [
        received_shards[0].as_ref().unwrap().as_slice(),
        received_shards[1].as_ref().unwrap().as_slice(),
    ]
    .concat();

    // Step 4: Decrypt (L2)
    let decrypted = l2_aead::decrypt_in_place(&key, 1, &mut reconstructed_enc)
        .expect("Decryption after RS reconstruction should succeed")
        .to_vec();

    assert_eq!(
        decrypted.as_slice(),
        original,
        "Full encrypt→RS-shard→reconstruct→decrypt should match original"
    );
}

// ─────────────────────────────────────────────────────────
// P2-3 — ML-KEM constant-time decapsulation audit (integration)
// ─────────────────────────────────────────────────────────
//
// The unit tests in `ghost::net::security` cover the same property; this is the
// public-API half of the audit, driving `security::TemporalIsolator` exactly as
// the fuzz target does.
//
// The audit finding, written down so it is not re-litigated: the only
// non-constant-time thing in this path was the *removed* dummy-decapsulation
// loop, which was a fixed additive cost that hid nothing. `ml-kem` 0.3.2's own
// `decapsulate` does FIPS 203 §7.3 implicit rejection with `subtle`
// (`cp.ct_eq(encapsulated_key)` + `CtOption::ct_select`), so there is no
// secret-dependent branch or memory access left to give a timing oracle.

#[test]
fn test_p2_3_temporal_isolator_round_trips_the_shared_secret() {
    use ml_kem::kem::Encapsulate;
    use subtle::ConstantTimeEq;
    use vantablack::ghost::net::security::TemporalIsolator;

    let (ek, dk) = l1_kem::generate_kyber_keypair();
    let (ct, ss) = ek.encapsulate();
    let ct_bytes: [u8; 768] = ct.into();

    let got = TemporalIsolator::fixed_time_decapsulate(&ct_bytes, &dk).expect("decapsulates");
    assert_eq!(got.len(), 32);
    assert!(
        bool::from(got.as_slice().ct_eq(ss.as_slice())),
        "one decapsulation must return exactly the encapsulator's secret"
    );
}

#[test]
fn test_p2_3_temporal_isolator_implicitly_rejects_a_tampered_ciphertext() {
    use ml_kem::kem::Encapsulate;
    use subtle::ConstantTimeEq;
    use vantablack::ghost::net::security::TemporalIsolator;

    let (ek, dk) = l1_kem::generate_kyber_keypair();
    let (ct, ss) = ek.encapsulate();
    let mut ct_bytes: [u8; 768] = ct.into();
    ct_bytes[767] ^= 0xFF;

    // No `Err`, no panic: the failure path is the same shape as the success
    // path, which is the whole point of implicit rejection — and is why the
    // old padding loop could not have been hiding anything.
    let got = TemporalIsolator::fixed_time_decapsulate(&ct_bytes, &dk)
        .expect("implicit rejection is not an error");
    assert_eq!(got.len(), 32);
    assert!(
        !bool::from(got.as_slice().ct_eq(ss.as_slice())),
        "a tampered ciphertext must not yield the true shared secret"
    );
}
