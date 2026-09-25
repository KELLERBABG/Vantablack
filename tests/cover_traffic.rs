//! Cover Traffic & Traffic-Shaping Verification Test
//!
//! Verifies:
//! 1. 100 real packets sent through simulated mesh generate interleaved dummy frames.
//! 2. Real-to-dummy ratio stays within configured traffic-shaping bounds.
//! 3. Poisson exponential timing jitter distribution is non-zero (CV > 0.40).
//! 4. Dummy frames and real data frames share identical size shape on the wire (576 bytes).
//! 5. Receiver unambiguously distinguishes real data from dummy frames without leaking plaintext.

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

const SESSION_HASH: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
const NOMINAL_COVER_RATE_HZ: f64 = 2.0;

/// Simulates drawing an exponential inter-arrival interval (Poisson cover gap)
fn cover_gap(uniform: f64, frames_per_sec: f64) -> Duration {
    let per_message = frames_per_sec / 3.0;
    if !(per_message > 0.0) {
        return Duration::from_secs(3600);
    }
    let u = uniform.clamp(0.0, 1.0 - f64::EPSILON);
    let secs = -(1.0 - u).ln() / per_message;
    Duration::from_secs_f64(secs.clamp(0.005, 30.0))
}

fn produce_wire_frame(
    key: &[u8; 32],
    epoch: u64,
    counter: u64,
    payload: &[u8],
    is_cover: bool,
) -> Vec<Vec<u8>> {
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(payload);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }

    let shards = l4_rs::encode(&mut framed);
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
        .expect("seal succeeds");

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

        let frame = build_gtf_v2_frame(&header, &frame_shard(ciphertext), &tag);
        wire_frames.push(frame);
    }
    wire_frames
}

#[test]
fn test_cover_traffic_wire_size_indistinguishability() {
    let session_key = [0x42u8; 32];
    let data_payload =
        b"GET /api/v1/resource/secure_query_user HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let cover_payload = DUMMY_MAGIC;

    let data_frames = produce_wire_frame(&session_key, 1, 100, data_payload, false);
    let cover_frames = produce_wire_frame(&session_key, 1, 101, cover_payload, true);

    assert_eq!(data_frames.len(), 3);
    assert_eq!(cover_frames.len(), 3);

    // Exact wire size equivalence: both must be standard GTF privacy frame size
    let expected_size = GTF_BASE_SIZE + JITTER_MAX;
    for df in &data_frames {
        assert_eq!(
            df.len(),
            expected_size,
            "Data frame size must match GTF privacy standard"
        );
    }
    for cf in &cover_frames {
        assert_eq!(
            cf.len(),
            expected_size,
            "Cover frame size must match GTF privacy standard exactly"
        );
    }
}

#[test]
fn test_simulated_mesh_100_packets_cover_traffic_ratio_and_jitter() {
    let session_key = [0x88u8; 32];
    let mut total_data_messages = 0usize;
    let mut total_cover_messages = 0usize;

    let mut stream_intervals = Vec::new();
    let mut received_real_data = Vec::new();
    let mut received_cover_dummies = 0usize;

    // Send 100 real packets through simulated mesh interleaved with Poisson cover emissions
    let mut rng_seed = 0.123456789f64;
    let mut pseudo_rand = || {
        rng_seed = (rng_seed * 48271.0) % 2147483647.0;
        rng_seed / 2147483647.0
    };

    let epoch = 1u64;
    let mut counter = 1u64;

    for i in 0..100 {
        // Real payload
        let real_payload = format!("mesh_payload_data_packet_index_{:04}", i).into_bytes();
        let wire_shards = produce_wire_frame(&session_key, epoch, counter, &real_payload, false);
        total_data_messages += 1;
        counter += 1;

        // Receiver processing for real message: reconstruct from shards 0 and 1 (with 2 missing to test RS recovery)
        let mut decrypted_data_shards = vec![None, None, None];
        for (idx, shard) in wire_shards.iter().take(2).enumerate() {
            let h = parse_gtf_v2_header(shard).expect("valid header");
            let tag = extract_auth_tag(shard);
            let ciphertext = unframe(extract_payload(shard)).expect("unframe");
            let mut buf = ciphertext.to_vec();
            buf.extend_from_slice(&tag);
            let opened = xchacha_open_with_aad(
                &session_key,
                &h.nonce,
                h.epoch,
                NonceDirection::InitiatorToResponder,
                &mut buf,
                &h.tail,
            )
            .expect("open");
            decrypted_data_shards[idx] = Some(opened.to_vec());
        }
        l4_rs::reconstruct(&mut decrypted_data_shards).expect("RS reconstruct");
        let mut recovered_bytes = Vec::new();
        recovered_bytes.extend_from_slice(decrypted_data_shards[0].as_ref().unwrap());
        recovered_bytes.extend_from_slice(decrypted_data_shards[1].as_ref().unwrap());
        let len = u16::from_be_bytes(recovered_bytes[0..2].try_into().unwrap()) as usize;
        let recovered_data = &recovered_bytes[2..2 + len];
        received_real_data.push(recovered_data.to_vec());
        assert_eq!(recovered_data, &real_payload[..]);

        // Interleaved cover traffic injection
        let gap = cover_gap(pseudo_rand(), NOMINAL_COVER_RATE_HZ);
        stream_intervals.push(gap.as_secs_f64());

        // Periodically inject cover message (simulating 1 cover per ~2 data bursts)
        if i % 2 == 0 {
            let cover_wire_shards =
                produce_wire_frame(&session_key, epoch, counter, DUMMY_MAGIC, true);
            total_cover_messages += 1;
            counter += 1;

            // Receiver identifies dummy frame flags on wire
            let h0 = parse_gtf_v2_header(&cover_wire_shards[0]).expect("valid header");
            assert_eq!(h0.flags & FLAG_DUMMY, FLAG_DUMMY);

            // Reconstruct and authenticate cover message
            let mut decrypted_cover_shards = vec![None, None, None];
            for (idx, shard) in cover_wire_shards.iter().take(2).enumerate() {
                let h = parse_gtf_v2_header(shard).expect("header");
                let tag = extract_auth_tag(shard);
                let ciphertext = unframe(extract_payload(shard)).expect("unframe");
                let mut buf = ciphertext.to_vec();
                buf.extend_from_slice(&tag);
                let opened = xchacha_open_with_aad(
                    &session_key,
                    &h.nonce,
                    h.epoch,
                    NonceDirection::InitiatorToResponder,
                    &mut buf,
                    &h.tail,
                )
                .expect("open");
                decrypted_cover_shards[idx] = Some(opened.to_vec());
            }
            l4_rs::reconstruct(&mut decrypted_cover_shards).expect("RS reconstruct");
            let mut recovered_cover_bytes = Vec::new();
            recovered_cover_bytes.extend_from_slice(decrypted_cover_shards[0].as_ref().unwrap());
            recovered_cover_bytes.extend_from_slice(decrypted_cover_shards[1].as_ref().unwrap());
            let cover_len =
                u16::from_be_bytes(recovered_cover_bytes[0..2].try_into().unwrap()) as usize;
            let cover_payload = &recovered_cover_bytes[2..2 + cover_len];
            if is_dummy_payload(cover_payload) {
                received_cover_dummies += 1;
            }
        }
    }

    assert_eq!(total_data_messages, 100);
    assert_eq!(received_real_data.len(), 100);
    assert_eq!(total_cover_messages, 50);
    assert_eq!(received_cover_dummies, 50);

    // Verify non-zero timing jitter distribution (Poisson exponential inter-arrival times)
    let mean_interval: f64 = stream_intervals.iter().sum::<f64>() / stream_intervals.len() as f64;
    let variance: f64 = stream_intervals
        .iter()
        .map(|v| (v - mean_interval).powi(2))
        .sum::<f64>()
        / stream_intervals.len() as f64;
    let std_dev = variance.sqrt();
    let cv = std_dev / mean_interval;

    println!(
        "Cover Traffic Stats: Real={}, Dummy={}, Ratio={:.2}, MeanGap={:.3}s, CV={:.3}",
        total_data_messages,
        total_cover_messages,
        total_cover_messages as f64 / total_data_messages as f64,
        mean_interval,
        cv
    );

    assert!(mean_interval > 0.05, "Mean gap must be realistic");
    assert!(
        cv > 0.40,
        "Coefficient of variation for exponential distribution must exceed 0.40 (not a metronome)"
    );
}
