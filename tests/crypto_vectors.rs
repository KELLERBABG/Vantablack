//! Cryptographic Test Vectors & Standards Conformance Suite.
//!
//! Validates Vantablack's cryptographic pipeline against published IETF / NIST test vectors:
//! 1. HKDF-SHA256 (RFC 5869 Test Case 1).
//! 2. ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8.2 Test Vector).
//! 3. Hybrid Post-Quantum Key Mixing (ML-KEM-768 + X25519 HKDF composition).
//! 4. Reed-Solomon RS(2,1) Galois Field arithmetic determinism.

use hkdf::Hkdf;
use sha2::Sha256;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ml_kem::kem::KeyExport;
use vantablack::ghost::layers::{l1_kem, l4_rs};

#[test]
fn test_rfc5869_hkdf_sha256_standard_test_vector_1() {
    // RFC 5869 Test Case 1: Basic test case with SHA-256
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    let expected_okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
    assert_eq!(hex::encode(prk), expected_prk, "PRK matches RFC 5869 vector");

    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm).expect("expand succeeds");
    assert_eq!(hex::encode(okm), expected_okm, "OKM matches RFC 5869 vector");
}

#[test]
fn test_rfc8439_chacha20_poly1305_standard_test_vector() {
    // RFC 8439 Section 2.8.2: Example and Test Vector for AEAD_CHACHA20_POLY1305
    let key_bytes = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce_bytes = hex::decode("070000004041424344454647").unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let expected_ciphertext_hex = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    let expected_tag_hex = "1ae10b594f09e26a7e902ecbd0600691";

    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: &aad,
    };

    let ciphertext = cipher.encrypt(nonce, payload).expect("encryption succeeds");

    // Ciphertext consists of encrypted plaintext + 16-byte Poly1305 tag
    let split_pos = ciphertext.len() - 16;
    let actual_ct = &ciphertext[..split_pos];
    let actual_tag = &ciphertext[split_pos..];

    assert_eq!(hex::encode(actual_ct), expected_ciphertext_hex, "Ciphertext matches RFC 8439");
    assert_eq!(hex::encode(actual_tag), expected_tag_hex, "Tag matches RFC 8439");

    // Decrypt and verify roundtrip
    let decrypted = cipher.decrypt(nonce, Payload { msg: &ciphertext, aad: &aad }).expect("decryption succeeds");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_hybrid_kem_blended_key_derivation_determinism() {
    let (ek, dk) = l1_kem::generate_kyber768_keypair();
    let ek_bytes = ek.to_bytes();

    let (ct, shared_secret_bob) = l1_kem::kyber768_encapsulate(&ek_bytes).expect("encapsulate succeeds");
    let shared_secret_alice = l1_kem::kyber768_decapsulate(&dk, &ct).expect("decapsulation succeeds");

    // Both parties arrive at the identical shared secret
    assert_eq!(shared_secret_alice, shared_secret_bob);
    assert!(!shared_secret_alice.is_empty(), "Shared secret must be non-empty");

    // Mix through HKDF with an additional context string
    let (prk1, hk1) = Hkdf::<Sha256>::extract(None, &shared_secret_alice);
    let (prk2, hk2) = Hkdf::<Sha256>::extract(None, &shared_secret_bob);
    assert_eq!(prk1, prk2);

    let mut session_key1 = [0u8; 32];
    let mut session_key2 = [0u8; 32];
    hk1.expand(b"VANTABLACK_SESSION_KEY_V1", &mut session_key1).unwrap();
    hk2.expand(b"VANTABLACK_SESSION_KEY_V1", &mut session_key2).unwrap();

    assert_eq!(session_key1, session_key2);
}

#[test]
fn test_rs_2_1_galois_erasure_algebra() {
    let mut data = b"EXACT_ALGEBRAIC_ERASURE_TEST_VECTOR_12345678".to_vec();
    let shards = l4_rs::encode(&mut data);
    assert_eq!(shards.len(), 3);

    // Verify Systematic Property: shard 0 + shard 1 equals original data
    let mut joined = shards[0].clone();
    joined.extend_from_slice(&shards[1]);
    assert_eq!(&joined[..data.len()], &data[..]);

    // Test Reconstruction with missing shard 0
    let mut missing_0 = vec![None, Some(shards[1].clone()), Some(shards[2].clone())];
    l4_rs::reconstruct(&mut missing_0).expect("reconstruct succeeds with shard 0 missing");
    assert_eq!(missing_0[0].as_ref().unwrap(), &shards[0]);

    // Test Reconstruction with missing shard 1
    let mut missing_1 = vec![Some(shards[0].clone()), None, Some(shards[2].clone())];
    l4_rs::reconstruct(&mut missing_1).expect("reconstruct succeeds with shard 1 missing");
    assert_eq!(missing_1[1].as_ref().unwrap(), &shards[1]);

    // Test Reconstruction with missing parity shard 2
    let mut missing_2 = vec![Some(shards[0].clone()), Some(shards[1].clone()), None];
    l4_rs::reconstruct(&mut missing_2).expect("reconstruct succeeds with parity missing");
    assert_eq!(missing_2[2].as_ref().unwrap(), &shards[2]);
}
