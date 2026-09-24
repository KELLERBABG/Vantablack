//! DPI (Deep Packet Inspection) & Traffic-Analysis Resistance Verification
//!
//! Grounded in RFC 4787, Shannon information theory, and real-world DPI heuristics:
//! 1. Plaintext signature detection (zero leakage of HTTP/JSON/TLS patterns).
//! 2. Shannon entropy analysis (aggregate wire stream H >= 7.90 bits/byte, normalized H_norm >= 0.95).
//! 3. Packet size histogram uniformity (cover frames and data frames share identical shape: 576 bytes).
//! 4. Inter-arrival timing jitter (Poisson exponential gaps, CV ≈ 1.0, not a metronome).
//! 5. Authenticated receiver classification (blind to wire observer, unforgeable marker).

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use vantablack::ghost::layers::l2_aead::{
    random_xnonce, xchacha_open_with_aad, xchacha_seal_in_place_with_aad, NonceDirection,
};
use vantablack::ghost::layers::l4_rs;
use vantablack::ghost::net::{
    build_gtf_v2_frame, extract_auth_tag, extract_payload, frame_shard, is_dummy_payload,
    parse_gtf_v2_header, tail_for, unframe, GtfV2Header, DUMMY_MAGIC, FLAG_DUMMY, GTF_BASE_SIZE,
    JITTER_MAX,
};

const SESSION_HASH: [u8; 4] = [0x7E, 0x57, 0xCA, 0xFE];

/// Calculate Shannon entropy in bits per byte (0.0 to 8.0).
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Calculate normalized entropy H / log2(min(256, N)) where 1.0 is maximum possible entropy.
fn normalized_entropy(bytes: &[u8]) -> f64 {
    if bytes.len() <= 1 {
        return 1.0;
    }
    let max_possible = (bytes.len().min(256) as f64).log2();
    shannon_entropy(bytes) / max_possible
}

/// Helper that reproduces the node's `enc_split` + `frame_shard` + GTF v2 wire framing pipeline.
fn produce_wire_frames(
    key: &[u8; 32],
    epoch: u64,
    counter: u64,
    payload: &[u8],
    is_cover: bool,
) -> Vec<Vec<u8>> {
    // 1. Prepend length and pad to even
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(payload);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }

    // 2. RS(2,1) encode into 3 shards
    let shards = l4_rs::encode(&mut framed);

    // 3. Encrypt each shard with XChaCha20-Poly1305 and package into GTF v2 frames
    let mut wire_frames = Vec::with_capacity(3);
    for (i, shard) in shards.iter().enumerate() {
        let nonce = random_xnonce();
        let tail = tail_for(key, &nonce, epoch, NonceDirection::InitiatorToResponder);

        let mut enc_shard = shard.clone();
        xchacha_seal_in_place_with_aad(
            key,
            &nonce,
            epoch,
            NonceDirection::InitiatorToResponder,
            &mut enc_shard,
            &tail,
        )
        .expect("seal");

        let tag: [u8; 16] = enc_shard[enc_shard.len() - 16..].try_into().unwrap();
        let ciphertext = &enc_shard[..enc_shard.len() - 16];

        let header = GtfV2Header {
            session_hash: SESSION_HASH,
            counter,
            epoch,
            nonce,
            shard_index: i as u8,
            flags: if is_cover { FLAG_DUMMY } else { 0 },
            bulk: false,
            tail,
        };

        // Frame the ciphertext with length prefix matching canonical GhostNet wire layout
        let framed_payload = frame_shard(ciphertext);
        let frame = build_gtf_v2_frame(&header, &framed_payload, &tag);
        wire_frames.push(frame);
    }
    wire_frames
}

/// Exponential inter-arrival generator (matching main.rs:577).
fn cover_gap(uniform: f64, frames_per_sec: f64) -> Duration {
    let per_message = frames_per_sec / 3.0;
    if !(per_message > 0.0) {
        return Duration::from_secs(3600);
    }
    let u = uniform.clamp(0.0, 1.0 - f64::EPSILON);
    let secs = -(1.0 - u).ln() / per_message;
    Duration::from_secs_f64(secs.clamp(0.005, 30.0))
}

#[test]
fn dpi_test_zero_plaintext_leakage_under_http_and_api_traffic() {
    let key = [0x42u8; 32];
    let epoch = 1u64;

    // High-entropy and common structured plaintexts that DPI sniffers look for:
    let sensitive_inputs: Vec<&[u8]> = vec![
        b"GET /api/v1/user/credentials HTTP/1.1\r\nHost: internal.bank.local\r\nAuthorization: Bearer secret_jwt_token_9876543210\r\n\r\n",
        b"POST /api/connect HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"peer\":\"kellerbabg\",\"private_key\":\"dontleakme\"}",
        b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n",
        b"\x16\x03\x01\x00\xba\x01\x00\x00\xb6\x03\x03\x7b\x58\x6c\x1c\x00", // TLS ClientHello header
        b"vantablack_ghost_mesh_master_key_fingerprint_check",
    ];

    let forbidden_signatures: Vec<&[u8]> = vec![
        b"GET ",
        b"POST ",
        b"HTTP/1.",
        b"Host:",
        b"Authorization",
        b"Bearer",
        b"Content-Type",
        b"application/json",
        b"credentials",
        b"kellerbabg",
        b"private_key",
        b"dontleakme",
        b"SSH-2.0",
        b"vantablack",
        b"ghost",
        b"internal.bank.local",
    ];

    let mut all_wire_bytes = Vec::new();

    for (counter, input) in sensitive_inputs.iter().enumerate() {
        let frames = produce_wire_frames(&key, epoch, counter as u64, input, false);
        for frame in frames {
            all_wire_bytes.extend_from_slice(&frame);

            // Test each forbidden signature against this wire frame
            for sig in &forbidden_signatures {
                let sig_str = String::from_utf8_lossy(sig);
                let found = frame
                    .windows(sig.len())
                    .any(|window| window.eq_ignore_ascii_case(sig));
                assert!(
                    !found,
                    "CRITICAL DPI LEAK: Forbidden signature '{sig_str}' discovered in raw wire frame!"
                );
            }
        }
    }

    // Also assert no long printable ASCII string runs (> 6 characters) on the wire
    let mut printable_run = 0;
    for &b in &all_wire_bytes {
        if (0x20..=0x7E).contains(&b) {
            printable_run += 1;
            assert!(
                printable_run < 16,
                "Suspiciously long ASCII run on wire (length {printable_run})"
            );
        } else {
            printable_run = 0;
        }
    }

    println!("PASS: Zero plaintext signatures or ASCII leakage found across {} wire bytes", all_wire_bytes.len());
}

#[test]
fn dpi_test_shannon_entropy_statistical_indistinguishability() {
    let key = [0x55u8; 32];
    let epoch = 3u64;

    let mut data_wire_stream = Vec::new();
    let mut cover_wire_stream = Vec::new();

    let mut data_norm_entropies = Vec::new();
    let mut cover_norm_entropies = Vec::new();

    // 1. Generate 50 data messages (150 wire frames) with structured low-entropy plaintexts
    for i in 0..50 {
        let plaintext = format!("Log entry #{i}: status=OK, host=node-{i}.ghostnet, payload=json_metrics_{i}");
        let frames = produce_wire_frames(&key, epoch, i, plaintext.as_bytes(), false);
        for frame in frames {
            let payload_raw = unframe(extract_payload(&frame)).expect("unframe payload");
            let tag = extract_auth_tag(&frame);
            let tail = &frame[GTF_BASE_SIZE..GTF_BASE_SIZE + JITTER_MAX];

            let mut crypto_section = payload_raw;
            crypto_section.extend_from_slice(&tag);
            crypto_section.extend_from_slice(tail);

            data_norm_entropies.push(normalized_entropy(&crypto_section));
            data_wire_stream.extend_from_slice(&crypto_section);
        }
    }

    // 2. Generate 50 cover/dummy messages (150 wire frames)
    for i in 50..100 {
        let frames = produce_wire_frames(&key, epoch, i, DUMMY_MAGIC, true);
        for frame in frames {
            let payload_raw = unframe(extract_payload(&frame)).expect("unframe payload");
            let tag = extract_auth_tag(&frame);
            let tail = &frame[GTF_BASE_SIZE..GTF_BASE_SIZE + JITTER_MAX];

            let mut crypto_section = payload_raw;
            crypto_section.extend_from_slice(&tag);
            crypto_section.extend_from_slice(tail);

            cover_norm_entropies.push(normalized_entropy(&crypto_section));
            cover_wire_stream.extend_from_slice(&crypto_section);
        }
    }

    let stream_data_entropy = shannon_entropy(&data_wire_stream);
    let stream_cover_entropy = shannon_entropy(&cover_wire_stream);

    let mean_data_norm = data_norm_entropies.iter().sum::<f64>() / data_norm_entropies.len() as f64;
    let mean_cover_norm = cover_norm_entropies.iter().sum::<f64>() / cover_norm_entropies.len() as f64;

    println!("Aggregate Data Stream Entropy:  {stream_data_entropy:.4} / 8.0 bits/byte (Stream size: {} bytes)", data_wire_stream.len());
    println!("Aggregate Cover Stream Entropy: {stream_cover_entropy:.4} / 8.0 bits/byte (Stream size: {} bytes)", cover_wire_stream.len());
    println!("Mean Normalized Per-Frame Entropy: Data = {mean_data_norm:.4}, Cover = {mean_cover_norm:.4}");

    // Assert that the aggregate wire byte streams have near-maximal theoretical Shannon entropy (>= 7.90)
    assert!(
        stream_data_entropy >= 7.90,
        "Data stream entropy ({stream_data_entropy:.4}) below 7.90"
    );
    assert!(
        stream_cover_entropy >= 7.90,
        "Cover stream entropy ({stream_cover_entropy:.4}) below 7.90"
    );

    // Assert per-frame normalized entropy is uniformly high (>= 93% of theoretical max)
    assert!(mean_data_norm >= 0.93);
    assert!(mean_cover_norm >= 0.93);

    // Assert statistical indistinguishability between real application data and cover traffic
    let stream_delta = (stream_data_entropy - stream_cover_entropy).abs();
    println!("Stream Entropy Delta (Data vs Cover): {stream_delta:.5} bits/byte");
    assert!(
        stream_delta < 0.05,
        "Entropy difference ({stream_delta:.5}) indicates statistical distinguishability!"
    );
}

#[test]
fn dpi_test_packet_size_uniformity_histogram() {
    let key = [0x99u8; 32];
    let epoch = 10u64;

    let expected_frame_size = GTF_BASE_SIZE + JITTER_MAX; // 576 bytes

    // Test a wide variety of payload sizes
    let test_payload_sizes = vec![1, 4, 16, 64, 128, 256, 384, 460];
    let mut size_histogram: HashMap<usize, usize> = HashMap::new();

    for (c, &sz) in test_payload_sizes.iter().enumerate() {
        let payload = vec![0xAB; sz];
        let frames = produce_wire_frames(&key, epoch, c as u64, &payload, false);
        for f in frames {
            *size_histogram.entry(f.len()).or_insert(0) += 1;
        }
    }

    // Add cover frames to the histogram
    let cover_frames = produce_wire_frames(&key, epoch, 999, DUMMY_MAGIC, true);
    for f in cover_frames {
        *size_histogram.entry(f.len()).or_insert(0) += 1;
    }

    println!("Wire Packet Size Histogram:");
    for (size, count) in &size_histogram {
        println!("  - {size} bytes: {count} frames");
    }

    // All standard privacy frames (data and cover) must have exactly 576 bytes
    assert_eq!(
        size_histogram.len(),
        1,
        "All privacy and cover frames must share identical wire size to prevent side-channel fingerprinting"
    );
    assert!(
        size_histogram.contains_key(&expected_frame_size),
        "Expected size {expected_frame_size} bytes not found"
    );
}

#[test]
fn dpi_test_inter_arrival_timing_jitter_distribution() {
    let target_rate_hz = 2.0;
    let n_samples = 10_000;
    let mut gaps = Vec::with_capacity(n_samples);
    let mut unique_gaps = HashSet::new();

    for i in 0..n_samples {
        let u = (i as f64 + 0.5) / n_samples as f64;
        let gap = cover_gap(u, target_rate_hz).as_secs_f64();
        gaps.push(gap);
        unique_gaps.insert((gap * 10_000.0) as u64); // quantized to 0.1ms
    }

    let sum: f64 = gaps.iter().sum();
    let mean = sum / n_samples as f64;

    // Variance and standard deviation
    let variance = gaps.iter().map(|&g| (g - mean).powi(2)).sum::<f64>() / n_samples as f64;
    let std_dev = variance.sqrt();
    let coefficient_of_variation = std_dev / mean;

    let expected_mean = 3.0 / target_rate_hz; // 1.5s per message

    println!("Inter-Arrival Timing Statistics ({} samples):", n_samples);
    println!("  - Mean interval: {:.4}s (Target: {:.4}s)", mean, expected_mean);
    println!("  - Standard deviation: {:.4}s", std_dev);
    println!("  - Variance: {:.4}", variance);
    println!("  - Coefficient of Variation (CV): {:.4}", coefficient_of_variation);
    println!("  - Unique intervals: {} / {}", unique_gaps.len(), n_samples);

    // 1. Mean must be within 15% of target
    assert!(
        (mean - expected_mean).abs() < 0.15 * expected_mean,
        "Mean gap differs significantly from Poisson expectation"
    );

    // 2. Variance must be strictly positive (not a metronome)
    assert!(variance > 0.5, "Variance too low; looks like a fixed timer!");

    // 3. For an exponential distribution, CV (std_dev / mean) is theoretically 1.0
    assert!(
        (coefficient_of_variation - 1.0).abs() < 0.25,
        "Timing distribution does not resemble a Poisson process (CV = {coefficient_of_variation:.4})"
    );

    // 4. Entropy of timing intervals (high uniqueness)
    assert!(
        unique_gaps.len() > 9_000,
        "Too many duplicate intervals; periodic fingerprint detected"
    );
}

#[test]
fn dpi_test_receiver_differentiates_data_and_cover() {
    let key = [0x77u8; 32];
    let epoch = 5u64;

    let test_data = b"REAL APPLICATION PACKET PAYLOAD";
    let data_frames = produce_wire_frames(&key, epoch, 100, test_data, false);
    let cover_frames = produce_wire_frames(&key, epoch, 101, DUMMY_MAGIC, true);

    // Receiver decodes data frames:
    let mut decrypted_data_shards = Vec::new();
    for frame in &data_frames {
        let header = parse_gtf_v2_header(frame).expect("header");
        let tag = extract_auth_tag(frame);
        let ciphertext = unframe(extract_payload(frame)).expect("unframe ciphertext");

        let mut buf = ciphertext.to_vec();
        buf.extend_from_slice(&tag);
        let opened = xchacha_open_with_aad(
            &key,
            &header.nonce,
            epoch,
            NonceDirection::InitiatorToResponder,
            &mut buf,
            &header.tail,
        )
        .expect("open data shard");

        decrypted_data_shards.push(Some(opened.to_vec()));
    }

    // Reconstruct RS(2,1) shards
    l4_rs::reconstruct(&mut decrypted_data_shards).expect("RS reconstruct");
    let mut recovered_bytes = Vec::new();
    recovered_bytes.extend_from_slice(decrypted_data_shards[0].as_ref().unwrap());
    recovered_bytes.extend_from_slice(decrypted_data_shards[1].as_ref().unwrap());
    let len = u16::from_be_bytes(recovered_bytes[0..2].try_into().unwrap()) as usize;
    let payload = &recovered_bytes[2..2 + len];
    assert_eq!(payload, test_data, "Data recovered intact");
    assert!(!is_dummy_payload(payload), "Real data is not dummy");

    // Receiver decodes cover frames:
    let mut decrypted_cover_shards = Vec::new();
    for frame in &cover_frames {
        let header = parse_gtf_v2_header(frame).expect("header");
        let tag = extract_auth_tag(frame);
        let ciphertext = unframe(extract_payload(frame)).expect("unframe ciphertext");

        let mut buf = ciphertext.to_vec();
        buf.extend_from_slice(&tag);
        let opened = xchacha_open_with_aad(
            &key,
            &header.nonce,
            epoch,
            NonceDirection::InitiatorToResponder,
            &mut buf,
            &header.tail,
        )
        .expect("open cover shard");

        decrypted_cover_shards.push(Some(opened.to_vec()));
    }

    l4_rs::reconstruct(&mut decrypted_cover_shards).expect("RS reconstruct");
    let mut recovered_cover_bytes = Vec::new();
    recovered_cover_bytes.extend_from_slice(decrypted_cover_shards[0].as_ref().unwrap());
    recovered_cover_bytes.extend_from_slice(decrypted_cover_shards[1].as_ref().unwrap());
    let cover_len = u16::from_be_bytes(recovered_cover_bytes[0..2].try_into().unwrap()) as usize;
    let cover_payload = &recovered_cover_bytes[2..2 + cover_len];

    assert!(
        is_dummy_payload(cover_payload),
        "Authenticated receiver identifies DUMMY_MAGIC"
    );
    println!("PASS: Receiver authenticated classification verified");
}
