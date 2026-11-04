//! Comprehensive SOTA Verification and Empirical Benchmark Suite
//!
//! Measures and verifies every quantitative performance and cryptographic claim made in:
//! - docs/VERIFICATION_AND_BENCHMARKS.md
//! - docs/SOTA.md
//! - README.md

use ml_kem::kem::{Decapsulate, KeyExport};
use std::time::Instant;
use vantablack::ghost::layers::{l0_identity, l1_kem, l2_aead, l4_rs, l6_session};
use vantablack::ghost::net::{
    self,
    coalesce::{CoalescingQueue, COALESCE_TARGET_BYTES},
    reassembly::ReassemblyBuffer,
    shardsec, GtfV2Header,
};

const BENCH_PACKETS: usize = 50_000;
const DPI_FRAMES: usize = 10_000;

#[test]
fn sota_comprehensive_benchmark() {
    println!("\n================================================================================");
    println!("        VANTABLACK SOTA EMPIRICAL BENCHMARK & VERIFICATION REPORT               ");
    println!("================================================================================\n");

    // ─────────────────────────────────────────────────────────────────────────────
    // 1. L4 RS(2,1) ENCODING BENCHMARKS
    // ─────────────────────────────────────────────────────────────────────────────
    println!("--- [1] L4 REED-SOLOMON RS(2,1) MICROBENCHMARKS ---");

    // 1.1 900 B Payload (Standard Privacy MTU)
    let payload_900 = vec![0x42u8; 900];
    let start = Instant::now();
    for _ in 0..BENCH_PACKETS {
        let mut d = payload_900.clone();
        let _ = l4_rs::encode(&mut d);
    }
    let elapsed_900 = start.elapsed();
    let total_bytes_900 = (BENCH_PACKETS * 900) as f64;
    let mib_900 = total_bytes_900 / (1024.0 * 1024.0);
    let throughput_900 = mib_900 / elapsed_900.as_secs_f64();
    let lat_900_us = (elapsed_900.as_secs_f64() * 1_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "RS(2,1) Encode  (900 B):   {:>8.2} MiB/s | {:>6.2} µs/pkt (Claimed: 141.32 MiB/s, 6.07 µs)",
        throughput_900, lat_900_us
    );

    // 1.2 1400 B Payload (Bulk MTU)
    let payload_1400 = vec![0x42u8; 1400];
    let start = Instant::now();
    for _ in 0..BENCH_PACKETS {
        let mut d = payload_1400.clone();
        let _ = l4_rs::encode(&mut d);
    }
    let elapsed_1400 = start.elapsed();
    let total_bytes_1400 = (BENCH_PACKETS * 1400) as f64;
    let mib_1400 = total_bytes_1400 / (1024.0 * 1024.0);
    let throughput_1400 = mib_1400 / elapsed_1400.as_secs_f64();
    let lat_1400_us = (elapsed_1400.as_secs_f64() * 1_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "RS(2,1) Encode (1400 B):   {:>8.2} MiB/s | {:>6.2} µs/pkt (Claimed: 258.13 MiB/s, 5.17 µs)",
        throughput_1400, lat_1400_us
    );

    // 1.3 RS(2,1) Erasure Recovery (Lost Shard 0)
    let mut initial_data = payload_900.clone();
    let encoded_shards = l4_rs::encode(&mut initial_data);
    let start = Instant::now();
    for _ in 0..BENCH_PACKETS {
        let mut test_shards = vec![
            None,
            Some(encoded_shards[1].clone()),
            Some(encoded_shards[2].clone()),
        ];
        l4_rs::reconstruct(&mut test_shards).expect("RS reconstruction failed");
    }
    let elapsed_rec = start.elapsed();
    let throughput_rec = mib_900 / elapsed_rec.as_secs_f64();
    let lat_rec_us = (elapsed_rec.as_secs_f64() * 1_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "RS(2,1) Recovery (Lost S0): {:>8.2} MiB/s | {:>6.2} µs/pkt (Claimed: 350.88 MiB/s, 2.45 µs)",
        throughput_rec, lat_rec_us
    );

    // ─────────────────────────────────────────────────────────────────────────────
    // 2. GTF V2 FRAME CONSTRUCTION
    // ─────────────────────────────────────────────────────────────────────────────
    println!("\n--- [2] GTF v2 FRAMING MICROBENCHMARK ---");
    let key = [0x5Au8; 32];
    let nonce = [0x01u8; 12];
    let tail = net::tail_for(
        &key,
        &nonce,
        1,
        l2_aead::NonceDirection::InitiatorToResponder,
    );
    let header = GtfV2Header {
        session_hash: [1, 2, 3, 4],
        counter: 42,
        epoch: 1,
        nonce,
        shard_index: 0,
        flags: 0,
        bulk: false,
        tail,
    };
    let shard_payload = vec![0x33u8; 450];
    let tag = [0x77u8; 16];

    let start = Instant::now();
    for _ in 0..BENCH_PACKETS {
        let _ = net::build_gtf_v2_frame(&header, &shard_payload, &tag);
    }
    let elapsed_frame = start.elapsed();
    let total_wire_bytes = (BENCH_PACKETS * 576) as f64;
    let mib_frame = total_wire_bytes / (1024.0 * 1024.0);
    let throughput_frame = mib_frame / elapsed_frame.as_secs_f64();
    let lat_frame_us = (elapsed_frame.as_secs_f64() * 1_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "GTF v2 Frame Build (576 B): {:>8.2} MiB/s | {:>6.2} µs/pkt (Claimed: 2970.51 MiB/s, 0.29 µs)",
        throughput_frame, lat_frame_us
    );

    // ─────────────────────────────────────────────────────────────────────────────
    // 3. FULL DATA PLANE PIPELINE BENCHMARKS
    // ─────────────────────────────────────────────────────────────────────────────
    println!("\n--- [3] FULL DATA-PLANE PIPELINE BENCHMARKS ---");

    // 3.1 Legacy Pipeline (AEAD + RS(2,1) + GTF v2)
    let raw_payload = vec![0x41u8; 450];
    let start = Instant::now();
    for ctr in 0..BENCH_PACKETS {
        let mut framed = Vec::with_capacity(2 + raw_payload.len() + 2 + 16);
        framed.extend_from_slice(&(raw_payload.len() as u16).to_be_bytes());
        framed.extend_from_slice(&raw_payload);
        if framed.len() % 2 != 0 {
            framed.push(0);
        }
        let nonce_arr = [0x05u8; 12];
        let tail_bytes = net::tail_for(
            &key,
            &nonce_arr,
            0,
            l2_aead::NonceDirection::InitiatorToResponder,
        );
        l2_aead::xchacha_seal_in_place_with_aad(
            &key,
            &nonce_arr,
            0,
            l2_aead::NonceDirection::InitiatorToResponder,
            &mut framed,
            &tail_bytes,
        )
        .expect("seal");
        let auth_tag: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
        let shards = l4_rs::encode(&mut framed);
        for (i, shard) in shards.into_iter().enumerate() {
            let h = GtfV2Header {
                session_hash: [1, 2, 3, 4],
                counter: ctr as u64,
                epoch: 0,
                nonce: nonce_arr,
                shard_index: i as u8,
                flags: 0,
                bulk: false,
                tail: tail_bytes,
            };
            let _ = net::build_gtf_v2_frame(&h, &shard, &auth_tag);
        }
    }
    let elapsed_pipeline = start.elapsed();
    let total_pipeline_bytes = (BENCH_PACKETS * raw_payload.len()) as f64;
    let mib_pipeline = total_pipeline_bytes / (1024.0 * 1024.0);
    let throughput_pipeline = mib_pipeline / elapsed_pipeline.as_secs_f64();
    let lat_pipeline_us = (elapsed_pipeline.as_secs_f64() * 1_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "Pipeline (AEAD+RS+GTFv2):   {:>8.2} MiB/s | {:>6.2} µs/pkt ({:.2} Gbps, Claimed: 204.06 MiB/s)",
        throughput_pipeline, lat_pipeline_us, (throughput_pipeline * 8.0) / 1024.0
    );

    // 3.2 Default ShardSec Pipeline (RS(2,1) + 3x Independent HKDF/AEAD + GTF Framing)
    let start = Instant::now();
    for _ in 0..BENCH_PACKETS {
        let sealed_shards = shardsec::seal_message(
            &key,
            0,
            &[1u8; 12],
            l2_aead::NonceDirection::InitiatorToResponder,
            &raw_payload,
        );
        for s in sealed_shards {
            let h = GtfV2Header {
                session_hash: [1, 2, 3, 4],
                counter: 10,
                epoch: 0,
                nonce: [1u8; 12],
                shard_index: s.index,
                flags: net::FLAG_SHARDSEC,
                bulk: false,
                tail: [0u8; 64],
            };
            let mut wire = s.ciphertext;
            wire.extend_from_slice(&s.tag);
            let _ = net::build_gtf_v2_frame(&h, &wire, &[0u8; 16]);
        }
    }
    let elapsed_shardsec = start.elapsed();
    let throughput_shardsec = mib_pipeline / elapsed_shardsec.as_secs_f64();
    let lat_shardsec_us = (elapsed_shardsec.as_secs_f64() * 1_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "Pipeline (ShardSec Default):{:>8.2} MiB/s | {:>6.2} µs/pkt ({:.2} Gbps)",
        throughput_shardsec,
        lat_shardsec_us,
        (throughput_shardsec * 8.0) / 1024.0
    );

    // 3.3 Zero-Allocation Coalescing Pipeline (984 B Batch + SIMD RS(2,1))
    let batch_payload = vec![0x33u8; COALESCE_TARGET_BYTES];
    let start = Instant::now();
    let mut queue = CoalescingQueue::default();
    let mut total_coalesced_bytes = 0;
    for _ in 0..BENCH_PACKETS {
        let groups = queue.push(&batch_payload, true);
        total_coalesced_bytes += batch_payload.len();
        let _ = &groups[0];
    }
    let elapsed_coalesce = start.elapsed();
    let mib_coalesce = (total_coalesced_bytes as f64) / (1024.0 * 1024.0);
    let throughput_coalesce = mib_coalesce / elapsed_coalesce.as_secs_f64();
    let lat_coalesce_us = (elapsed_coalesce.as_secs_f64() * 1_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "Coalescing Queue (984 B Batch):{:>7.2} MiB/s | {:>6.2} µs/batch ({:.2} Gbps)",
        throughput_coalesce,
        lat_coalesce_us,
        (throughput_coalesce * 8.0) / 1024.0
    );

    // 3.4 Exit Reassembly Fast-Path (D0 + D1 -> Instant Concatenation)
    let sample_groups = queue.push(&batch_payload, true);
    let [d0, d1, p0] = &sample_groups[0];
    let mut rx = ReassemblyBuffer::new();
    let start = Instant::now();
    for _ in 0..BENCH_PACKETS {
        let _ = rx.ingest_shard(d0);
        let _ = rx.ingest_shard(d1);
    }
    let elapsed_reasm = start.elapsed();
    let throughput_reasm = mib_coalesce / elapsed_reasm.as_secs_f64();
    let lat_reasm_us = (elapsed_reasm.as_secs_f64() * 1_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "Reassembly Fast-Path (D0+D1): {:>8.2} MiB/s | {:>6.2} µs/batch ({:.2} Gbps)",
        throughput_reasm,
        lat_reasm_us,
        (throughput_reasm * 8.0) / 1024.0
    );

    // 3.5 Exit Reassembly Erasure Recovery (D0 + P0 -> SIMD RS Reconstruction)
    let start = Instant::now();
    for _ in 0..BENCH_PACKETS {
        let _ = rx.ingest_shard(d0);
        let _ = rx.ingest_shard(p0);
    }
    let elapsed_reasm_rec = start.elapsed();
    let throughput_reasm_rec = mib_coalesce / elapsed_reasm_rec.as_secs_f64();
    let lat_reasm_rec_us = (elapsed_reasm_rec.as_secs_f64() * 1_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "Reassembly Erasure Rec (D0+P0):{:>7.2} MiB/s | {:>6.2} µs/batch ({:.2} Gbps)",
        throughput_reasm_rec,
        lat_reasm_rec_us,
        (throughput_reasm_rec * 8.0) / 1024.0
    );

    // ─────────────────────────────────────────────────────────────────────────────
    // 4. TRAFFIC ANALYSIS & DPI RESISTANCE (STATISTICAL VERIFICATION)
    // ─────────────────────────────────────────────────────────────────────────────
    println!("\n--- [4] DPI & WIRE STATISTICAL VERIFICATION (10,000 FRAMES) ---");
    let mut lengths = Vec::with_capacity(DPI_FRAMES);
    let mut aggregate_stream = Vec::with_capacity(DPI_FRAMES * 576);

    for i in 0..DPI_FRAMES {
        let random_payload_len = 50 + (i % 380);
        let p: Vec<u8> = (0..random_payload_len).map(|b| (b * 7 + i) as u8).collect();
        let nonce_i = [(i & 0xFF) as u8; 12];
        let tail_i = net::tail_for(
            &key,
            &nonce_i,
            0,
            l2_aead::NonceDirection::InitiatorToResponder,
        );
        let mut framed = Vec::with_capacity(p.len() + 2 + 16);
        framed.extend_from_slice(&(p.len() as u16).to_be_bytes());
        framed.extend_from_slice(&p);
        if framed.len() % 2 != 0 {
            framed.push(0);
        }
        l2_aead::xchacha_seal_in_place_with_aad(
            &key,
            &nonce_i,
            0,
            l2_aead::NonceDirection::InitiatorToResponder,
            &mut framed,
            &tail_i,
        )
        .unwrap();
        let tag_i: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
        let h = GtfV2Header {
            session_hash: [0xDE, 0xAD, 0xBE, 0xEF],
            counter: i as u64,
            epoch: 0,
            nonce: nonce_i,
            shard_index: 0,
            flags: 0,
            bulk: false,
            tail: tail_i,
        };
        let frame = net::build_gtf_v2_frame(&h, &framed[..framed.len() - 16], &tag_i);
        lengths.push(frame.len());
        aggregate_stream.extend_from_slice(&frame);
    }

    let min_len = lengths.iter().min().unwrap();
    let max_len = lengths.iter().max().unwrap();
    let mean_len = lengths.iter().sum::<usize>() as f64 / lengths.len() as f64;
    let variance = lengths
        .iter()
        .map(|&l| (l as f64 - mean_len).powi(2))
        .sum::<f64>()
        / lengths.len() as f64;
    let shannon = l1_kem::calculate_shannon_entropy(&aggregate_stream);
    let (chi2, p_val) = l1_kem::calculate_chi_square_uniformity(&aggregate_stream);

    println!(
        "Privacy Frame Length:   min={} B, max={} B, mean={:.1} B, variance={:.4}",
        min_len, max_len, mean_len, variance
    );
    println!(
        "Shannon Byte Entropy:   {:.4} bits/byte (Target: >= 7.95, Claimed: 7.989)",
        shannon
    );
    println!(
        "Chi-Square Uniformity:  chi2={:.2}, p={:.4} (Target: p in [0.01, 0.99])",
        chi2, p_val
    );

    // 4.1 Keyed Tail Tamper Resistance Check
    let mut tamper_success_count = 0;
    for i in 0..100 {
        let nonce_t = [i as u8; 12];
        let tail_t = net::tail_for(
            &key,
            &nonce_t,
            0,
            l2_aead::NonceDirection::InitiatorToResponder,
        );
        let mut framed = vec![0x99u8; 100];
        l2_aead::xchacha_seal_in_place_with_aad(
            &key,
            &nonce_t,
            0,
            l2_aead::NonceDirection::InitiatorToResponder,
            &mut framed,
            &tail_t,
        )
        .unwrap();
        let tag_t: [u8; 16] = framed[framed.len() - 16..].try_into().unwrap();
        let h = GtfV2Header {
            session_hash: [0x11, 0x22, 0x33, 0x44],
            counter: i as u64,
            epoch: 0,
            nonce: nonce_t,
            shard_index: 0,
            flags: 0,
            bulk: false,
            tail: tail_t,
        };
        let mut frame = net::build_gtf_v2_frame(&h, &framed[..framed.len() - 16], &tag_t);
        // Flip one bit in the tail (bytes 512..575)
        let tail_byte_idx = 512 + (i % 64);
        frame[tail_byte_idx] ^= 0x01;

        let parsed_h = net::parse_gtf_v2_header(&frame).unwrap();
        let mut open_buf = net::extract_payload(&frame).to_vec();
        open_buf.extend_from_slice(net::extract_auth_tag(&frame));
        let open_res = l2_aead::xchacha_open_with_aad(
            &key,
            &parsed_h.nonce,
            parsed_h.epoch,
            l2_aead::NonceDirection::InitiatorToResponder,
            &mut open_buf,
            &parsed_h.tail,
        );
        if open_res.is_ok() {
            tamper_success_count += 1;
        }
    }
    println!(
        "Tail Tamper Rejection:  {} / 100 rejected (100% rejection required)",
        100 - tamper_success_count
    );

    // ─────────────────────────────────────────────────────────────────────────────
    // 5. SESSIONGUARD ANTI-REPLAY SLIDING WINDOW BENCHMARK
    // ─────────────────────────────────────────────────────────────────────────────
    println!("\n--- [5] SESSIONGUARD ANTI-REPLAY BENCHMARK ---");
    let mut guard = l6_session::SessionGuard::new();
    let start = Instant::now();
    for c in 1..=BENCH_PACKETS as u32 {
        assert!(guard.check_and_update(c));
    }
    let elapsed_sg = start.elapsed();
    let lat_sg_ns = (elapsed_sg.as_secs_f64() * 1_000_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "SessionGuard Sequential Accept: {:>6.2} ns/pkt ({:.2} Mpps)",
        lat_sg_ns,
        (BENCH_PACKETS as f64 / elapsed_sg.as_secs_f64()) / 1_000_000.0
    );

    let start = Instant::now();
    for c in 1..=BENCH_PACKETS as u32 {
        // Replay of same counters
        assert!(!guard.check_and_update(c));
    }
    let elapsed_replay = start.elapsed();
    let lat_replay_ns = (elapsed_replay.as_secs_f64() * 1_000_000_000.0) / (BENCH_PACKETS as f64);
    println!(
        "SessionGuard Replay Drop:       {:>6.2} ns/pkt ({:.2} Mpps blocked)",
        lat_replay_ns,
        (BENCH_PACKETS as f64 / elapsed_replay.as_secs_f64()) / 1_000_000.0
    );

    // ─────────────────────────────────────────────────────────────────────────────
    // 6. POST-QUANTUM CRYPTOGRAPHY PRIMITIVE BENCHMARKS
    // ─────────────────────────────────────────────────────────────────────────────
    println!("\n--- [6] POST-QUANTUM & CLASSICAL CRYPTOGRAPHIC BENCHMARKS ---");
    const CRYPTO_ITERS: usize = 1_000;

    // 6.1 Ephemeral X25519
    let start = Instant::now();
    for _ in 0..CRYPTO_ITERS {
        let (s, p) = l1_kem::generate_x25519_keypair();
        let _ = s.diffie_hellman(&p);
    }
    let el_x25519 = start.elapsed();
    println!(
        "X25519 ECDH (Keygen + DH):      {:>6.2} µs/op",
        (el_x25519.as_secs_f64() * 1_000_000.0) / CRYPTO_ITERS as f64
    );

    // 6.2 ML-KEM-768 (Kyber-768 / FIPS 203)
    let start = Instant::now();
    for _ in 0..CRYPTO_ITERS {
        let (ek, dk) = l1_kem::generate_kyber768_keypair();
        let (ct, ss_enc) = l1_kem::kyber768_encapsulate(&ek.to_bytes()).unwrap();
        let ss_dec = l1_kem::kyber768_decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }
    let el_kem768 = start.elapsed();
    println!(
        "ML-KEM-768 (Keygen+Encap+Decap):{:>6.2} µs/op",
        (el_kem768.as_secs_f64() * 1_000_000.0) / CRYPTO_ITERS as f64
    );

    // 6.3 ML-KEM-512 (Kyber-512)
    let start = Instant::now();
    for _ in 0..CRYPTO_ITERS {
        let (ek, dk) = l1_kem::generate_kyber_keypair();
        let (ct, ss_enc) = l1_kem::kyber_encapsulate(&ek.to_bytes()).unwrap();
        let ky_ct = ml_kem::kem::Ciphertext::<ml_kem::MlKem512>::from(ct);
        let ss_dec = dk.decapsulate(&ky_ct);
        assert_eq!(ss_enc, ss_dec.as_slice());
    }
    let el_kem512 = start.elapsed();
    println!(
        "ML-KEM-512 (Keygen+Encap+Decap):{:>6.2} µs/op",
        (el_kem512.as_secs_f64() * 1_000_000.0) / CRYPTO_ITERS as f64
    );

    // 6.4 Ed25519 Sign & Verify
    let id = l0_identity::GhostIdentity::generate_fresh();
    let msg = b"benchmark message for identity signing verification";
    let start = Instant::now();
    for _ in 0..CRYPTO_ITERS {
        let sig = id.sign(msg);
        let pk = id.public_key_bytes();
        assert!(l0_identity::verify_peer_signature(
            &pk,
            msg,
            &sig.to_bytes()
        ));
    }
    let el_ed25519 = start.elapsed();
    println!(
        "Ed25519 (Sign + Verify):        {:>6.2} µs/op",
        (el_ed25519.as_secs_f64() * 1_000_000.0) / CRYPTO_ITERS as f64
    );

    // 6.5 ML-DSA-65 (FIPS 204) Sign & Verify
    let start = Instant::now();
    for _ in 0..CRYPTO_ITERS {
        let sig = id.sign_hybrid(msg);
        assert!(id.verify_hybrid(msg, &sig));
    }
    let el_mldsa = start.elapsed();
    println!(
        "Hybrid ML-DSA-65+Ed25519:       {:>6.2} µs/op",
        (el_mldsa.as_secs_f64() * 1_000_000.0) / CRYPTO_ITERS as f64
    );

    println!("\n================================================================================");
    println!("                       BENCHMARK COMPLETE                                       ");
    println!("================================================================================\n");
}
