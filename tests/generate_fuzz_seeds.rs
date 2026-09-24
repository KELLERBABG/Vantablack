//! Seed Corpus Generator for Vantablack Fuzz Targets (Roadmap Item 5)

use std::fs;
use std::path::Path;

use ml_kem::kem::Encapsulate;
use vantablack::ghost::layers::l0_identity::GhostIdentity;
use vantablack::ghost::layers::l1_kem::{
    build_handshake_pdu, build_response_pdu, generate_kyber_keypair,
};
use vantablack::ghost::net::{
    build_gtf_v2_frame, frame_shard, GtfV2Header, DUMMY_MAGIC, FLAG_DUMMY, JITTER_MAX,
};

#[test]
fn generate_all_fuzz_seed_corpora() {
    let base_dir = Path::new("fuzz/corpus");
    fs::create_dir_all(base_dir).unwrap();

    // ── 1. fuzz_handle_pkt ──
    let dir = base_dir.join("fuzz_handle_pkt");
    fs::create_dir_all(&dir).unwrap();

    let session_hash = [0x12, 0x34, 0x56, 0x78];
    let counter = 1u64;
    let auth_tag = [0xAAu8; 16];
    let header = GtfV2Header {
        session_hash,
        counter,
        epoch: 1,
        nonce: [0x55u8; 12],
        shard_index: 0,
        flags: 0,
        bulk: false,
        tail: [0x77u8; JITTER_MAX],
    };
    let payload = b"authenticated_wire_payload_sample_seed";
    let gtf_v2_seed = build_gtf_v2_frame(&header, &frame_shard(payload), &auth_tag);
    fs::write(dir.join("seed1_gtf_v2.bin"), &gtf_v2_seed).unwrap();

    let dummy_header = GtfV2Header {
        flags: FLAG_DUMMY,
        ..header
    };
    let gtf_dummy_seed = build_gtf_v2_frame(&dummy_header, &frame_shard(DUMMY_MAGIC), &auth_tag);
    fs::write(dir.join("seed2_gtf_dummy.bin"), &gtf_dummy_seed).unwrap();

    // ── 2. fuzz_parse_handshake_pdu ──
    let dir = base_dir.join("fuzz_parse_handshake_pdu");
    fs::create_dir_all(&dir).unwrap();

    let initiator_id = GhostIdentity::generate_fresh();
    let responder_id = GhostIdentity::generate_fresh();

    let (_x_secret, x_public) = {
        let s = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let p = x25519_dalek::PublicKey::from(&s);
        (s, p)
    };
    let (kyber_pk, _kyber_sk) = generate_kyber_keypair();

    let hs_pdu = build_handshake_pdu(
        &initiator_id.public_key_bytes(),
        |data| initiator_id.sign(data).to_bytes(),
        &x_public,
        &kyber_pk,
    );
    fs::write(dir.join("seed1_handshake_pdu.bin"), &hs_pdu).unwrap();

    let (resp_x_pub, _resp_x_priv) = {
        let s = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let p = x25519_dalek::PublicKey::from(&s);
        (p, s)
    };
    let (ct, _ss) = kyber_pk.encapsulate();
    let ct_arr: &[u8; 768] = ct.as_slice().try_into().expect("768 bytes");
    let resp_pdu = build_response_pdu(
        &responder_id.public_key_bytes(),
        |data| responder_id.sign(data).to_bytes(),
        resp_x_pub.as_bytes(),
        ct_arr,
    );
    fs::write(dir.join("seed2_response_pdu.bin"), &resp_pdu).unwrap();

    // ── 3. fuzz_kyber_ciphertext ──
    let dir = base_dir.join("fuzz_kyber_ciphertext");
    fs::create_dir_all(&dir).unwrap();

    let ct_bytes = ct.as_slice();
    fs::write(dir.join("seed1_valid_kem512_ct.bin"), ct_bytes).unwrap();

    let mut ct_padded = ct_bytes.to_vec();
    ct_padded.extend_from_slice(&[0xFF; 64]);
    fs::write(dir.join("seed2_kem512_ct_padded.bin"), &ct_padded).unwrap();

    // ── 4. fuzz_build_gtf_frame ──
    let dir = base_dir.join("fuzz_build_gtf_frame");
    fs::create_dir_all(&dir).unwrap();

    let p1 = b"small_payload_gtf_seed";
    let p2 = vec![0x42u8; 486]; // Max privacy payload
    let p3 = vec![0x99u8; 1446]; // Max bulk payload
    fs::write(dir.join("seed1_small.bin"), p1).unwrap();
    fs::write(dir.join("seed2_max_privacy.bin"), &p2).unwrap();
    fs::write(dir.join("seed3_max_bulk.bin"), &p3).unwrap();

    // ── 5. fuzz_parse_relay_header ──
    let dir = base_dir.join("fuzz_parse_relay_header");
    fs::create_dir_all(&dir).unwrap();

    let mut relay_packet = Vec::new();
    relay_packet.extend_from_slice(b"RELAY"); // Magic
    relay_packet.push(0x01); // Version
    relay_packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]); // Next hop fingerprint
    relay_packet.extend_from_slice(&100u16.to_be_bytes()); // Payload len
    relay_packet.extend_from_slice(&vec![0xAA; 100]); // Payload
    fs::write(dir.join("seed1_relay_packet.bin"), &relay_packet).unwrap();

    // ── 6. fuzz_unframe ──
    let dir = base_dir.join("fuzz_unframe");
    fs::create_dir_all(&dir).unwrap();

    let mut framed_msg = Vec::new();
    let msg = b"sample_framed_unframe_seed_data";
    framed_msg.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    framed_msg.extend_from_slice(msg);
    fs::write(dir.join("seed1_framed.bin"), &framed_msg).unwrap();

    let zero_len_framed = vec![0x00, 0x00];
    fs::write(dir.join("seed2_zero_len.bin"), &zero_len_framed).unwrap();

    // ── 7. fuzz_parse_quic_binding ──
    let dir = base_dir.join("fuzz_parse_quic_binding");
    fs::create_dir_all(&dir).unwrap();

    let binding = b"fuzz-channel-binding";
    let sig = initiator_id.sign(binding);
    let mut binding_payload = Vec::new();
    binding_payload.extend_from_slice(&initiator_id.public_key_bytes());
    binding_payload.extend_from_slice(&sig.to_bytes());
    fs::write(dir.join("seed1_quic_binding.bin"), &binding_payload).unwrap();

    println!("All 7 fuzz target seed corpora generated successfully in fuzz/corpus/");
}
